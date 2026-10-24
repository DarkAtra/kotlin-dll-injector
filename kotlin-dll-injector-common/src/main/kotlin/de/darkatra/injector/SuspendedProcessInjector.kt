package de.darkatra.injector

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.platform.win32.WinBase.SYSTEM_INFO
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.platform.win32.WinNT.MEMORY_BASIC_INFORMATION
import com.sun.jna.platform.win32.WinNT.MEM_COMMIT
import com.sun.jna.platform.win32.WinNT.MEM_FREE
import com.sun.jna.platform.win32.WinNT.MEM_RELEASE
import com.sun.jna.platform.win32.WinNT.MEM_RESERVE
import com.sun.jna.platform.win32.WinNT.PAGE_READWRITE
import com.sun.jna.ptr.IntByReference
import de.darkatra.injector.jna.Kernel32
import de.darkatra.injector.jna.Ntdll
import de.darkatra.injector.logging.Logger
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object SuspendedProcessInjector {

    private const val PE_SIGNATURE = 0x00004550
    private const val MAX_IMPORT_DESCRIPTORS = 4096
    private const val MAX_THUNKS_PER_DESCRIPTOR = 65536
    private const val FIRST_THUNK_OFFSET = 16

    fun inject(processId: Long, dllPath: String, logger: Logger) {

        // get the handle to the process
        val processHandle = ProcessUtils.openHandleToProcess(processId)
            ?: throw InjectionException("Could not OpenProcess with pid '${processId}', error code: ${com.sun.jna.platform.win32.Kernel32.INSTANCE.GetLastError()}")

        val image = readRemoteImage(processHandle)
        val originalDescriptors = readImportDescriptors(processHandle, image)
        val allocationSize = ImportTableBuilder.requiredSize(image.architecture, dllPath, originalDescriptors.size)
        val allocation = allocateRvaAddressableMemory(processHandle, image, allocationSize)
            ?: throw InjectionException("Could not allocate RVA-addressable memory in the suspended process, error code: ${Kernel32.INSTANCE.GetLastError()}")
        val allocationAddress = Pointer.nativeValue(allocation)
        var headerWriteAttempted = false

        try {
            val importTable = ImportTableBuilder.build(
                imageBaseAddress = image.baseAddress,
                allocationAddress = allocationAddress,
                architecture = image.architecture,
                dllPath = dllPath,
                originalDescriptors = originalDescriptors
            )

            writeProcessMemory(processHandle, allocation, importTable.bytes)
            logger.trace("* Wrote the replacement import table to 0x${allocationAddress.toString(16)}.")

            val headerAddress = image.peSignatureAddress + image.importDirectoryOffset
            val headerSize = image.iatDirectoryOffset - image.importDirectoryOffset + 8
            val originalHeaderBytes = readProcessMemory(processHandle, headerAddress, headerSize)
            val updatedHeaderBytes = originalHeaderBytes.copyOf()
            val headerBuffer = ByteBuffer.wrap(updatedHeaderBytes).order(ByteOrder.LITTLE_ENDIAN)
            headerBuffer.putInt(0, importTable.importDirectoryRva)
            headerBuffer.putInt(4, importTable.importDirectorySize)
            val boundImportOffset = image.boundImportDirectoryOffset - image.importDirectoryOffset
            headerBuffer.putInt(boundImportOffset, 0)
            headerBuffer.putInt(boundImportOffset + 4, 0)

            // Without an IAT directory the loader skips the whole import table as soon as it contains a descriptor
            // whose IAT lives outside of the image, so the directory needs to cover the original IATs.
            val iatDirectoryOffset = image.iatDirectoryOffset - image.importDirectoryOffset
            if (headerBuffer.getInt(iatDirectoryOffset) == 0 && headerBuffer.getInt(iatDirectoryOffset + 4) == 0) {
                val originalIat = findOriginalIat(processHandle, image, originalDescriptors)
                if (originalIat != null) {
                    headerBuffer.putInt(iatDirectoryOffset, originalIat.rva)
                    headerBuffer.putInt(iatDirectoryOffset + 4, originalIat.size)
                    logger.trace("* The image has no IAT directory, set it to the original import address tables (RVA 0x${originalIat.rva.toString(16)}, size 0x${originalIat.size.toString(16)}).")
                }
            }

            val oldProtection = IntByReference()
            val headerPointer = Pointer.createConstant(headerAddress)
            if (!Kernel32.INSTANCE.VirtualProtectEx(
                    processHandle,
                    headerPointer,
                    BaseTSD.SIZE_T(headerSize.toLong()),
                    PAGE_READWRITE,
                    oldProtection
                )
            ) {
                throw InjectionException("Could not make the PE headers writable, error code: ${Kernel32.INSTANCE.GetLastError()}")
            }

            var headerFailure: Throwable? = null
            try {
                headerWriteAttempted = true
                writeProcessMemory(processHandle, headerPointer, updatedHeaderBytes)
            } catch (e: Throwable) {
                headerFailure = e
                throw e
            } finally {
                val ignoredProtection = IntByReference()
                if (!Kernel32.INSTANCE.VirtualProtectEx(
                        processHandle,
                        headerPointer,
                        BaseTSD.SIZE_T(headerSize.toLong()),
                        oldProtection.value,
                        ignoredProtection
                    )
                ) {
                    val protectionFailure = InjectionException("Could not restore the PE header protection, error code: ${Kernel32.INSTANCE.GetLastError()}")
                    if (headerFailure == null) {
                        throw protectionFailure
                    }
                    headerFailure.addSuppressed(protectionFailure)
                }
            }

            logger.trace("* Pointed the image import directory at the replacement table and cleared the bound-import directory.")
        } catch (e: Throwable) {
            if (!headerWriteAttempted) {
                Kernel32.INSTANCE.VirtualFreeEx(processHandle, allocation, BaseTSD.SIZE_T(0), MEM_RELEASE)
            }
            throw e
        }
    }

    private fun readRemoteImage(processHandle: HANDLE): RemoteImage {

        val peb = findPeb(processHandle)
        val imageBaseOffset = if (peb.is32Bit) 8L else 16L
        val imageBaseAddress = readPointer(processHandle, peb.address + imageBaseOffset, peb.is32Bit)
        if (imageBaseAddress == 0L) {
            throw InjectionException("The suspended process has no image base address in its PEB.")
        }

        val peSignatureOffset = readInt(processHandle, imageBaseAddress + OFFSET_TO_PE_SIGNATURE_POINTER)
        if (peSignatureOffset !in 1..0x100000) {
            throw InjectionException("The suspended process has an invalid PE signature offset: $peSignatureOffset")
        }

        val peSignatureAddress = imageBaseAddress + peSignatureOffset
        if (readInt(processHandle, peSignatureAddress) != PE_SIGNATURE) {
            throw InjectionException("The suspended process image does not have a valid PE signature.")
        }

        val architecture = when (readShort(processHandle, peSignatureAddress + OPTIONAL_HEADER_MAGIC_FROM_SIGNATURE)) {
            OPTIONAL_HEADER_MAGIC_32 -> ProcessArchitecture.X_86
            OPTIONAL_HEADER_MAGIC_64 -> ProcessArchitecture.X_64
            else -> throw InjectionException("The suspended process has an unsupported PE optional-header magic.")
        }
        if (peb.is32Bit != (architecture == ProcessArchitecture.X_86)) {
            throw InjectionException("The process PEB and PE header disagree about the target architecture.")
        }

        val sizeOfImage = readUnsignedInt(processHandle, peSignatureAddress + SIZE_OF_IMAGE_FROM_SIGNATURE)
        if (sizeOfImage == 0L) {
            throw InjectionException("The suspended process image has an invalid image size.")
        }

        return when (architecture) {
            ProcessArchitecture.X_86 -> RemoteImage(
                baseAddress = imageBaseAddress,
                size = sizeOfImage,
                peSignatureAddress = peSignatureAddress,
                architecture = architecture,
                importDirectoryOffset = IMPORT_TABLE_FROM_SIGNATURE_32,
                boundImportDirectoryOffset = BOUND_IMPORT_TABLE_FROM_SIGNATURE_32,
                iatDirectoryOffset = IAT_TABLE_FROM_SIGNATURE_32
            )

            ProcessArchitecture.X_64 -> RemoteImage(
                baseAddress = imageBaseAddress,
                size = sizeOfImage,
                peSignatureAddress = peSignatureAddress,
                architecture = architecture,
                importDirectoryOffset = IMPORT_TABLE_FROM_SIGNATURE_64,
                boundImportDirectoryOffset = BOUND_IMPORT_TABLE_FROM_SIGNATURE_64,
                iatDirectoryOffset = IAT_TABLE_FROM_SIGNATURE_64
            )
        }
    }

    private fun findPeb(processHandle: HANDLE): Peb {

        if (Native.POINTER_SIZE == Long.SIZE_BYTES) {
            Memory(Long.SIZE_BYTES.toLong()).use { wow64Peb ->
                val status = Ntdll.INSTANCE.NtQueryInformationProcess(
                    processHandle,
                    Ntdll.PROCESS_WOW64_INFORMATION,
                    wow64Peb,
                    Long.SIZE_BYTES,
                    null
                )
                if (status >= 0) {
                    val address = wow64Peb.getLong(0)
                    if (address != 0L) {
                        return Peb(address, true)
                    }
                }
            }
        }

        val informationSize = Native.POINTER_SIZE * 6
        return Memory(informationSize.toLong()).use { processInformation ->
            val status = Ntdll.INSTANCE.NtQueryInformationProcess(
                processHandle,
                Ntdll.PROCESS_BASIC_INFORMATION,
                processInformation,
                informationSize,
                null
            )
            if (status < 0) {
                throw InjectionException("NtQueryInformationProcess failed with NTSTATUS 0x${status.toUInt().toString(16)}.")
            }

            val address = if (Native.POINTER_SIZE == Long.SIZE_BYTES) {
                processInformation.getLong(Native.POINTER_SIZE.toLong())
            } else {
                processInformation.getInt(Native.POINTER_SIZE.toLong()).toLong() and UInt.MAX_VALUE.toLong()
            }
            Peb(address, Native.POINTER_SIZE == Int.SIZE_BYTES)
        }
    }

    private fun readImportDescriptors(processHandle: HANDLE, image: RemoteImage): List<ByteArray> {

        val importDirectoryRva = readUnsignedInt(
            processHandle,
            image.peSignatureAddress + image.importDirectoryOffset
        )
        if (importDirectoryRva == 0L) {
            return emptyList()
        }
        if (importDirectoryRva >= image.size) {
            throw InjectionException("The image import directory points outside the mapped image.")
        }

        val descriptors = mutableListOf<ByteArray>()
        repeat(MAX_IMPORT_DESCRIPTORS) { index ->
            val descriptorAddress = image.baseAddress + importDirectoryRva + (index * ImportTableBuilder.IMPORT_DESCRIPTOR_SIZE)
            val descriptor = readProcessMemory(processHandle, descriptorAddress, ImportTableBuilder.IMPORT_DESCRIPTOR_SIZE)
            if (descriptor.all { it == 0.toByte() }) {
                return descriptors
            }
            descriptors.add(descriptor)
        }

        throw InjectionException("The image import directory has no terminator within $MAX_IMPORT_DESCRIPTORS descriptors.")
    }

    private fun findOriginalIat(processHandle: HANDLE, image: RemoteImage, originalDescriptors: List<ByteArray>): IatRange? {

        val thunkSize = when (image.architecture) {
            ProcessArchitecture.X_86 -> Int.SIZE_BYTES
            ProcessArchitecture.X_64 -> Long.SIZE_BYTES
        }

        var start = Long.MAX_VALUE
        var end = 0L
        originalDescriptors.forEach { descriptor ->
            val firstThunkRva = ByteBuffer.wrap(descriptor).order(ByteOrder.LITTLE_ENDIAN).getInt(FIRST_THUNK_OFFSET).toLong() and UInt.MAX_VALUE.toLong()
            if (firstThunkRva == 0L) {
                return@forEach
            }

            var thunkCount = 0
            while (true) {
                val thunkEndRva = firstThunkRva + (thunkCount + 1L) * thunkSize
                if (thunkEndRva > image.size || thunkCount >= MAX_THUNKS_PER_DESCRIPTOR) {
                    throw InjectionException("The import address table at RVA 0x${firstThunkRva.toString(16)} has no terminator inside of the image.")
                }
                val thunk = readProcessMemory(processHandle, image.baseAddress + firstThunkRva + thunkCount.toLong() * thunkSize, thunkSize)
                if (thunk.all { it == 0.toByte() }) {
                    break
                }
                thunkCount++
            }

            start = minOf(start, firstThunkRva)
            end = maxOf(end, firstThunkRva + (thunkCount + 1L) * thunkSize)
        }

        return when (end) {
            0L -> null
            else -> IatRange(start.toInt(), (end - start).toInt())
        }
    }

    private fun allocateRvaAddressableMemory(processHandle: HANDLE, image: RemoteImage, size: Int): Pointer? {

        val systemInfo = SYSTEM_INFO()
        Kernel32.INSTANCE.GetSystemInfo(systemInfo)
        val allocationGranularity = systemInfo.dwAllocationGranularity.toLong()
        val highestRvaAddress = image.baseAddress + UInt.MAX_VALUE.toLong()
        val highestTargetAddress = when (image.architecture) {
            ProcessArchitecture.X_86 -> UInt.MAX_VALUE.toLong()
            ProcessArchitecture.X_64 -> highestRvaAddress
        }
        var candidate = align(image.baseAddress + image.size, allocationGranularity)

        while (candidate <= highestTargetAddress - size) {
            val memoryInformation = MEMORY_BASIC_INFORMATION()
            val queryResult = Kernel32.INSTANCE.VirtualQueryEx(
                processHandle,
                Pointer.createConstant(candidate),
                memoryInformation,
                BaseTSD.SIZE_T(memoryInformation.size().toLong())
            )
            if (queryResult.toLong() == 0L) {
                candidate += allocationGranularity
                continue
            }

            val regionBase = Pointer.nativeValue(memoryInformation.baseAddress)
            val regionEnd = regionBase + memoryInformation.regionSize.toLong()
            val allocationAddress = align(maxOf(candidate, regionBase), allocationGranularity)
            if (memoryInformation.state.toInt() == MEM_FREE && allocationAddress <= regionEnd - size) {
                val allocation = Kernel32.INSTANCE.VirtualAllocEx(
                    processHandle,
                    Pointer.createConstant(allocationAddress),
                    BaseTSD.SIZE_T(size.toLong()),
                    MEM_RESERVE or MEM_COMMIT,
                    PAGE_READWRITE
                )
                if (allocation != null) {
                    return allocation
                }
            }

            val nextCandidate = align(regionEnd, allocationGranularity)
            candidate = if (nextCandidate > candidate) nextCandidate else candidate + allocationGranularity
        }

        return null
    }

    private fun readPointer(processHandle: HANDLE, address: Long, is32Bit: Boolean): Long {

        return if (is32Bit) {
            readUnsignedInt(processHandle, address)
        } else {
            readProcessMemory(processHandle, address, Long.SIZE_BYTES).let {
                ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).long
            }
        }
    }

    private fun readUnsignedInt(processHandle: HANDLE, address: Long): Long {

        return readInt(processHandle, address).toLong() and UInt.MAX_VALUE.toLong()
    }

    private fun readInt(processHandle: HANDLE, address: Long): Int {

        return ByteBuffer.wrap(readProcessMemory(processHandle, address, Int.SIZE_BYTES))
            .order(ByteOrder.LITTLE_ENDIAN)
            .int
    }

    private fun readShort(processHandle: HANDLE, address: Long): Short {

        return ByteBuffer.wrap(readProcessMemory(processHandle, address, Short.SIZE_BYTES))
            .order(ByteOrder.LITTLE_ENDIAN)
            .short
    }

    private fun readProcessMemory(processHandle: HANDLE, address: Long, size: Int): ByteArray {

        return Memory(size.toLong()).use { memory ->
            val bytesRead = IntByReference()
            if (!Kernel32.INSTANCE.ReadProcessMemory(
                    processHandle,
                    Pointer.createConstant(address),
                    memory,
                    size,
                    bytesRead
                ) || bytesRead.value != size
            ) {
                throw InjectionException("Could not read $size bytes at 0x${address.toString(16)}, error code: ${Kernel32.INSTANCE.GetLastError()}")
            }
            memory.getByteArray(0, size)
        }
    }

    private fun writeProcessMemory(processHandle: HANDLE, address: Pointer, bytes: ByteArray) {

        Memory(bytes.size.toLong()).use { memory ->
            memory.write(0, bytes, 0, bytes.size)
            val bytesWritten = IntByReference()
            if (!Kernel32.INSTANCE.WriteProcessMemory(processHandle, address, memory, bytes.size, bytesWritten) ||
                bytesWritten.value != bytes.size
            ) {
                throw InjectionException("Could not write ${bytes.size} bytes at 0x${Pointer.nativeValue(address).toString(16)}, error code: ${Kernel32.INSTANCE.GetLastError()}")
            }
        }
    }

    private fun align(value: Long, alignment: Long): Long {

        return (value + alignment - 1) and -alignment
    }

    private data class Peb(
        val address: Long,
        val is32Bit: Boolean
    )

    private data class RemoteImage(
        val baseAddress: Long,
        val size: Long,
        val peSignatureAddress: Long,
        val architecture: ProcessArchitecture,
        val importDirectoryOffset: Int,
        val boundImportDirectoryOffset: Int,
        val iatDirectoryOffset: Int
    )

    private data class IatRange(
        val rva: Int,
        val size: Int
    )
}
