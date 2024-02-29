package de.darkatra.injector

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinNT
import de.darkatra.injector.jna.LPMODULEINFO
import de.darkatra.injector.jna.Psapi

internal object ModuleUtils {

    fun getModuleName(processHandle: WinNT.HANDLE, module: WinDef.HMODULE): String {

        val lpImageFileName = ByteArray(WinDef.MAX_PATH)
        val successful = Psapi.INSTANCE.GetModuleBaseNameA(
            processHandle,
            module,
            lpImageFileName,
            lpImageFileName.size
        ) != 0

        if (!successful) {
            throw InjectionException("Failed to get module name, error code: ${Kernel32.INSTANCE.GetLastError()}")
        }

        return Native.toString(lpImageFileName)
    }

    fun getRemoteProcAddress(processHandle: WinNT.HANDLE, module: WinDef.HMODULE, name: String): Pointer? {

        val moduleBase = getModuleBaseAddress(processHandle, module)
        val moduleBaseAddress = Pointer.nativeValue(moduleBase.pointer)

        val offsetToPESignature = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + OFFSET_TO_PE_SIGNATURE_POINTER)
        )

        val processArchitecture: ProcessArchitecture = ProcessUtils.getProcessArchitecture(processHandle, moduleBaseAddress)

        val offsetToExportTable = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(
                moduleBaseAddress + offsetToPESignature + when (processArchitecture) {
                    ProcessArchitecture.X_86 -> EXPORT_TABLE_FROM_SIGNATURE_32
                    ProcessArchitecture.X_64 -> EXPORT_TABLE_FROM_SIGNATURE_64
                }
            )
        )

        val numberOfExportedFunctions = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(
                moduleBaseAddress + offsetToExportTable + NUMBER_OF_EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE
            )
        )

        val offsetToExportedFunctionNamesTable = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportTable + EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE)
        )

        val functionIndex = (0..<numberOfExportedFunctions)
            .map { i ->

                val offsetToFunctionName = ProcessUtils.readInt(
                    processHandle,
                    Pointer.createConstant(
                        moduleBaseAddress + offsetToExportedFunctionNamesTable + i * 4
                    )
                )

                val maxFunctionNameLength = name.length
                val functionName =
                    ProcessUtils.readProcessMemory(
                        processHandle,
                        Pointer.createConstant(moduleBaseAddress + offsetToFunctionName),
                        maxFunctionNameLength
                    ) { it: Memory ->
                        // it.getString(0) yields wrong results when the target process is running in x64 for some reason (reads over memory bounds)
                        Native.toString(it.getByteArray(0, maxFunctionNameLength))
                    }

                Pair(i, functionName)
            }
            .firstOrNull { (_, functionName) ->
                name.equals(functionName, true)
            }
            ?.first
            ?: return null

        val offsetToExportedFunctionOrdinalsTable = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportTable + EXPORTED_FUNCTION_ORDINALS_FROM_EXPORT_TABLE)
        )

        val functionOrdinal = ProcessUtils.readShort(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportedFunctionOrdinalsTable + functionIndex * 2)
        )

        val offsetToExportedFunctionAddressTable = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(
                moduleBaseAddress + offsetToExportTable + EXPORTED_FUNCTION_ADDRESSES_FROM_EXPORT_TABLE
            )
        )

        val functionAddress = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportedFunctionAddressTable + functionOrdinal * 4)
        )

        return Pointer.createConstant(moduleBaseAddress + functionAddress)
    }

    private fun getModuleBaseAddress(processHandle: WinNT.HANDLE, module: WinDef.HMODULE): WinNT.HANDLE {

        val moduleInfo = LPMODULEINFO()
        val successful = Psapi.INSTANCE.GetModuleInformation(
            processHandle,
            module,
            moduleInfo,
            moduleInfo.size()
        )

        if (!successful) {
            throw InjectionException("Failed to get module info, error code: ${Kernel32.INSTANCE.GetLastError()}")
        }

        return moduleInfo.lpBaseOfDll!!
    }
}
