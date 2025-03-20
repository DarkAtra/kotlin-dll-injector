package de.darkatra.injector

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.platform.win32.WinNT.MEM_COMMIT
import com.sun.jna.platform.win32.WinNT.MEM_RESERVE
import com.sun.jna.platform.win32.WinNT.PAGE_EXECUTE_READWRITE
import com.sun.jna.platform.win32.WinNT.PROCESS_CREATE_THREAD
import com.sun.jna.platform.win32.WinNT.PROCESS_QUERY_INFORMATION
import com.sun.jna.platform.win32.WinNT.PROCESS_VM_OPERATION
import com.sun.jna.platform.win32.WinNT.PROCESS_VM_READ
import com.sun.jna.platform.win32.WinNT.PROCESS_VM_WRITE
import de.darkatra.injector.logging.Logger
import de.darkatra.injector.logging.NoopLogger
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import kotlin.io.path.absolutePathString

object Injector {

    fun injectDll(processId: Long, dllPath: Path, logger: Logger = NoopLogger()) {

        val dllPathString = dllPath.absolutePathString()

        logger.info("Attempting to inject '$dllPathString' into process with id '$processId'...")

        // get the handle to the process
        val processHandle = openHandleToProcess(processId)
            ?: throw InjectionException("Could not OpenProcess with pid '${processId}', error code: ${Kernel32.INSTANCE.GetLastError()}")

        logger.trace("* Process handle: $processHandle")

        val loadLibraryPointer = ModuleUtils.getRemoteProcAddress(
            processHandle,
            ProcessUtils.getRemoteModuleHandle(processHandle, "kernel32.dll")!!,
            "LoadLibraryA"
        ) ?: throw InjectionException("Failed to get address for LoadLibraryA.")

        logger.trace("* Address for LoadLibraryA: $loadLibraryPointer")

        // allocate memory for the dll path string
        val dllMemoryPointer = allocateMemoryForString(processHandle, dllPathString)
            ?: throw InjectionException("Failed to allocate memory, error code: ${Kernel32.INSTANCE.GetLastError()}")

        logger.trace("* Allocated ${getMemorySizeOfString(dllPathString)} bytes for the ddl path string at: $loadLibraryPointer")

        // write the dll path string to the allocated memory
        val writeToMemorySuccessful = writeStringToMemory(processHandle, dllMemoryPointer, dllPathString)
        if (!writeToMemorySuccessful) {
            throw InjectionException("Failed to write to memory, error code: ${Kernel32.INSTANCE.GetLastError()}")
        }

        logger.trace("* Successfully written the dll path to memory.")

        // load the dll via remote thread
        val remoteThread = Kernel32.INSTANCE.CreateRemoteThread(
            processHandle,
            null,
            0,
            loadLibraryPointer,
            dllMemoryPointer,
            0,
            null
        ) ?: throw InjectionException("Failed to create remote process, error code: ${Kernel32.INSTANCE.GetLastError()}")

        logger.trace("* Created remote thread to load the dll.")

        Kernel32.INSTANCE.CloseHandle(remoteThread)
        Kernel32.INSTANCE.CloseHandle(processHandle)

        logger.info("Successfully injected '$dllPathString' into process with id '$processId'.")
    }

    private fun openHandleToProcess(processId: Long): HANDLE? {

        return Kernel32.INSTANCE.OpenProcess(
            PROCESS_CREATE_THREAD or
                PROCESS_QUERY_INFORMATION or
                PROCESS_VM_OPERATION or
                PROCESS_VM_READ or
                PROCESS_VM_WRITE,
            false,
            Math.toIntExact(processId)
        )
    }

    private fun allocateMemoryForString(processHandle: HANDLE, string: String): Pointer? {

        return Kernel32.INSTANCE.VirtualAllocEx(
            processHandle,
            null,
            BaseTSD.SIZE_T(getMemorySizeOfString(string)),
            MEM_RESERVE or MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        )
    }

    private fun writeStringToMemory(processHandle: HANDLE, memoryPointer: Pointer, string: String): Boolean {

        val stringLength = getMemorySizeOfString(string)
        return Memory(stringLength).use { memory ->
            memory.setString(0, string, StandardCharsets.UTF_8.name())

            Kernel32.INSTANCE.WriteProcessMemory(
                processHandle,
                memoryPointer,
                memory,
                Math.toIntExact(stringLength),
                null
            )
        }
    }

    private fun getMemorySizeOfString(string: String): Long {
        return Native.toByteArray(string, StandardCharsets.UTF_8).size + 1L
    }
}
