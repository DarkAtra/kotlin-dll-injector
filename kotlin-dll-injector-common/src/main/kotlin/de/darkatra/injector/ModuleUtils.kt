package de.darkatra.injector

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinNT
import de.darkatra.injector.PEOffset.EXPORTED_FUNCTION_ADDRESSES_FROM_EXPORT_TABLE
import de.darkatra.injector.PEOffset.EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE
import de.darkatra.injector.PEOffset.EXPORTED_FUNCTION_ORDINALS_FROM_EXPORT_TABLE
import de.darkatra.injector.PEOffset.EXPORT_TABLE_FROM_SIGNATURE
import de.darkatra.injector.PEOffset.NUMBER_OF_EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE
import de.darkatra.injector.jna.Kernel32
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

        val offsetToExportTable = ProcessUtils.readPointer(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToPESignature + EXPORT_TABLE_FROM_SIGNATURE.getOffset(processArchitecture)),
            processArchitecture
        )

        val numberOfExportedFunctions = ProcessUtils.readInt(
            processHandle,
            Pointer.createConstant(
                moduleBaseAddress + offsetToExportTable + NUMBER_OF_EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE.getOffset(processArchitecture)
            )
        )

        val offsetToExportedFunctionNamesTable = ProcessUtils.readPointer(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportTable + EXPORTED_FUNCTION_NAMES_FROM_EXPORT_TABLE.getOffset(processArchitecture)),
            processArchitecture
        )

        val functionIndex = (0..<numberOfExportedFunctions)
            .map { i ->

                val offsetToFunctionName = ProcessUtils.readPointer(
                    processHandle,
                    Pointer.createConstant(
                        moduleBaseAddress + offsetToExportedFunctionNamesTable + i * when (processArchitecture) {
                            ProcessArchitecture.X_64 -> 8
                            ProcessArchitecture.X_86 -> 4
                        }
                    ),
                    processArchitecture
                )

                val maxFunctionNameLength = name.length
                val functionName =
                    ProcessUtils.readProcessMemory(
                        processHandle,
                        Pointer.createConstant(moduleBaseAddress + offsetToFunctionName),
                        maxFunctionNameLength
                    ) { it: Memory ->
                        it.getString(0)
                    }

                Pair(i, functionName)
            }
            .firstOrNull { (_, functionName) ->
                name.equals(functionName, true)
            }
            ?.first
            ?: return null

        val offsetToExportedFunctionOrdinalsTable = ProcessUtils.readPointer(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportTable + EXPORTED_FUNCTION_ORDINALS_FROM_EXPORT_TABLE.getOffset(processArchitecture)),
            processArchitecture
        )

        val functionOrdinal = ProcessUtils.readShort(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToExportedFunctionOrdinalsTable + functionIndex * 2)
        )

        val offsetToExportedFunctionAddressTable = ProcessUtils.readPointer(
            processHandle,
            Pointer.createConstant(
                moduleBaseAddress + offsetToExportTable + EXPORTED_FUNCTION_ADDRESSES_FROM_EXPORT_TABLE.getOffset(
                    processArchitecture
                )
            ),
            processArchitecture
        )

        val functionAddress = ProcessUtils.readPointer(
            processHandle,
            Pointer.createConstant(
                moduleBaseAddress + offsetToExportedFunctionAddressTable + functionOrdinal * when (processArchitecture) {
                    ProcessArchitecture.X_64 -> 8
                    ProcessArchitecture.X_86 -> 4
                }
            ),
            processArchitecture
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
