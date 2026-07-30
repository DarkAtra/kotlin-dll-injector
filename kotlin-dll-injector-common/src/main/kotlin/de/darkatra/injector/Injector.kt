package de.darkatra.injector

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.platform.win32.WinNT.MEM_COMMIT
import com.sun.jna.platform.win32.WinNT.MEM_RELEASE
import com.sun.jna.platform.win32.WinNT.MEM_RESERVE
import com.sun.jna.platform.win32.WinNT.PAGE_EXECUTE_READWRITE
import de.darkatra.injector.logging.Logger
import de.darkatra.injector.logging.NoopLogger
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import kotlin.io.path.absolutePathString

@PublicApi
object Injector {

    @PublicApi
    fun injectDll(processId: Long, dllPath: Path, logger: Logger = NoopLogger()) {

        val dllPathString = dllPath.absolutePathString()

        logger.info("Attempting to inject '$dllPathString' into process with id '$processId'...")

        // get the handle to the process
        val processHandle = ProcessUtils.openHandleToProcess(processId)
            ?: throw InjectionException("Could not OpenProcess with pid '${processId}', error code: ${Kernel32.INSTANCE.GetLastError()}")

        logger.trace("* Process handle: $processHandle")

        val loadLibraryPointer = ModuleUtils.getRemoteProcAddress(
            processHandle,
            ProcessUtils.getRemoteModuleHandle(processHandle, "kernel32.dll", logger)!!,
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

        logger.trace("* Created remote thread to load the dll. Waiting until it completes...")

        // wait for remote thread to complete
        when (val threadExitCode = Kernel32.INSTANCE.WaitForSingleObject(remoteThread, Kernel32.INFINITE)) {
            Kernel32.WAIT_OBJECT_0 -> logger.trace("* Remote thread completed.")
            Kernel32.WAIT_FAILED -> logger.warn("* Could not wait for remote thread, error code: ${Kernel32.INSTANCE.GetLastError()}")
            // WAIT_ABANDONED and WAIT_TIMEOUT should never occur in this case
            else -> logger.warn("* Unknown error waiting for remote thread, thread exit code: $threadExitCode")
        }

        // free allocated memory for dll path string
        logger.trace("* Freeing allocated bytes for the ddl path string.")
        when {
            freeMemoryForString(processHandle, dllMemoryPointer) -> logger.trace("* Successfully freed allocated bytes for the ddl path string.")
            else -> logger.warn("* Failed to free allocated bytes for the ddl path string, error code: ${Kernel32.INSTANCE.GetLastError()}")
        }

        Kernel32.INSTANCE.CloseHandle(remoteThread)
        Kernel32.INSTANCE.CloseHandle(processHandle)

        logger.info("Successfully injected '$dllPathString' into process with id '$processId'.")
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

    private fun freeMemoryForString(processHandle: HANDLE, memoryPointer: Pointer): Boolean {

        return Kernel32.INSTANCE.VirtualFreeEx(
            processHandle,
            memoryPointer,
            BaseTSD.SIZE_T(0),
            MEM_RELEASE
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
