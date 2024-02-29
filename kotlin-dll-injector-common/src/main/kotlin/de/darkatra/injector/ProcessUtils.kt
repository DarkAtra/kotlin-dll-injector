package de.darkatra.injector

import com.sun.jna.Memory
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import de.darkatra.injector.jna.Psapi
import java.util.logging.Logger

internal object ProcessUtils {

    private val LOGGER = Logger.getLogger(ProcessUtils::class.qualifiedName)

    // x86
    private val IMAGE_FILE_MACHINE_I386: Short = 0x014cu.toShort()

    // x64
    private val IMAGE_FILE_MACHINE_AMD64: Short = 0x8664u.toShort()

    fun getProcessArchitecture(processHandle: WinNT.HANDLE, moduleBaseAddress: Long): ProcessArchitecture {

        val offsetToPESignature = readInt(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + OFFSET_TO_PE_SIGNATURE_POINTER)
        )

        val imageFileMachine = readShort(
            processHandle,
            Pointer.createConstant(moduleBaseAddress + offsetToPESignature + 4)
        )

        return when (imageFileMachine) {
            IMAGE_FILE_MACHINE_I386 -> ProcessArchitecture.X_86
            IMAGE_FILE_MACHINE_AMD64 -> ProcessArchitecture.X_64
            else -> throw InjectionException("Unsupported image file machine: $imageFileMachine")
        }
    }

    fun getRemoteModuleHandle(processHandle: WinNT.HANDLE, name: String): WinDef.HMODULE? {

        val modules = arrayOfNulls<WinDef.HMODULE>(1024)
        val modulesSizeNeeded = IntByReference()

        val successful = Psapi.INSTANCE.EnumProcessModulesEx(
            processHandle,
            modules,
            modules.size,
            modulesSizeNeeded,
            Psapi.LIST_MODULES_ALL
        )
        if (!successful) {
            throw InjectionException("Failed to enumerate process modules, error code: ${Kernel32.INSTANCE.GetLastError()}")
        }

        if (modulesSizeNeeded.value > modules.size) {
            LOGGER.warning("Only iterating the first ${modules.size} modules but this process has ${modulesSizeNeeded.value} modules.")
        }

        return modules.filterNotNull().firstOrNull { module ->

            val moduleName = try {
                ModuleUtils.getModuleName(processHandle, module)
            } catch (e: InjectionException) {
                LOGGER.warning(e.message)
                return@firstOrNull false
            }

            moduleName.equals(name, true)
        }
    }

    /**
     * Reads a 32-bit integer from the given address.
     */
    fun readInt(processHandle: WinNT.HANDLE, address: Pointer): Int {

        return readProcessMemory(
            processHandle,
            address,
            4
        ) { it: Memory ->
            it.getInt(0)
        }
    }

    /**
     * Reads a 16-bit integer from the given address.
     */
    fun readShort(processHandle: WinNT.HANDLE, address: Pointer): Short {

        return readProcessMemory(
            processHandle,
            address,
            2
        ) { it: Memory ->
            it.getShort(0)
        }
    }

    fun <T> readProcessMemory(processHandle: WinNT.HANDLE, address: Pointer, bytesToRead: Int, mappingFunction: (Memory) -> T): T {

        return Memory(bytesToRead.toLong()).use { memory ->

            val success = Kernel32.INSTANCE.ReadProcessMemory(
                processHandle,
                address,
                memory,
                bytesToRead,
                null
            )
            if (!success) {
                throw RuntimeException("Failed to read process memory, error code: ${Kernel32.INSTANCE.GetLastError()}")
            }

            mappingFunction(memory)
        }
    }
}
