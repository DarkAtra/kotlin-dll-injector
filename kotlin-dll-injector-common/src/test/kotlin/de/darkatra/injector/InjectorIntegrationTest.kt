package de.darkatra.injector

import com.sun.jna.platform.win32.WinBase.CREATE_SUSPENDED
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION
import com.sun.jna.platform.win32.WinBase.STARTUPINFO
import com.sun.jna.platform.win32.WinDef.DWORD
import de.darkatra.injector.jna.Kernel32
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Timeout

class InjectorIntegrationTest {

    private companion object {
        const val WAIT_TIMEOUT = 0x00000102
    }

    @Test
    @Timeout(30)
    fun `remote thread injection loads x86 fixture`() {

        verifyRemoteThreadInjection("x86")
    }

    @Test
    @Timeout(30)
    fun `remote thread injection loads x64 fixture`() {

        verifyRemoteThreadInjection("x64")
    }

    @Test
    @Timeout(30)
    fun `suspended import injection loads x86 fixture before main`() {

        verifySuspendedImportInjection("x86")
    }

    @Test
    @Timeout(30)
    fun `suspended import injection loads x64 fixture before main`() {

        verifySuspendedImportInjection("x64")
    }

    private fun verifyRemoteThreadInjection(architecture: String) {

        val fixture = fixture(architecture)
        Files.deleteIfExists(fixture.dllMarker)
        Files.deleteIfExists(fixture.readyMarker)

        val process = ProcessBuilder(fixture.executable.absolutePathString())
            .directory(fixture.executable.parent.toFile())
            .start()
        try {
            awaitFile(fixture.readyMarker) { process.isAlive }
            assertFalse(fixture.dllMarker.exists(), "The marker must not exist before remote-thread injection.")

            Injector.injectDll(process.pid(), fixture.dll)

            awaitFile(fixture.dllMarker) { process.isAlive }
        } finally {
            process.destroyForcibly()
            process.waitFor()
            Files.deleteIfExists(fixture.dllMarker)
            Files.deleteIfExists(fixture.readyMarker)
        }
    }

    private fun verifySuspendedImportInjection(architecture: String) {

        val fixture = fixture(architecture)
        Files.deleteIfExists(fixture.dllMarker)
        Files.deleteIfExists(fixture.readyMarker)

        val startupInfo = STARTUPINFO()
        startupInfo.cb = DWORD(startupInfo.size().toLong())
        val processInformation = PROCESS_INFORMATION()
        val commandLine = "\"${fixture.executable.absolutePathString()}\" --expect-injected"
        val created = Kernel32.INSTANCE.CreateProcess(
            fixture.executable.absolutePathString(),
            commandLine,
            null,
            null,
            false,
            DWORD(CREATE_SUSPENDED.toLong()),
            null,
            fixture.executable.parent.absolutePathString(),
            startupInfo,
            processInformation
        )
        assertTrue(created, "CreateProcess failed with error code ${Kernel32.INSTANCE.GetLastError()}.")

        try {
            Injector.injectDllIntoSuspendedProcess(processInformation.dwProcessId.toLong(), fixture.dll)
            assertTrue(Kernel32.INSTANCE.ResumeThread(processInformation.hThread) != -1)

            awaitFile(fixture.readyMarker) {
                Kernel32.INSTANCE.WaitForSingleObject(processInformation.hProcess, 0) == WAIT_TIMEOUT
            }
            assertTrue(fixture.dllMarker.exists(), "The fixture DLL must load before the target enters main.")
        } finally {
            Kernel32.INSTANCE.TerminateProcess(processInformation.hProcess, 1)
            Kernel32.INSTANCE.CloseHandle(processInformation.hThread)
            Kernel32.INSTANCE.CloseHandle(processInformation.hProcess)
            Files.deleteIfExists(fixture.dllMarker)
            Files.deleteIfExists(fixture.readyMarker)
        }
    }

    private fun fixture(architecture: String): Fixture {

        assumeTrue(System.getProperty("os.name").startsWith("Windows"), "Native injection tests require Windows.")

        val executableValue = System.getProperty("injector.fixture.$architecture.exe")
        val dllValue = System.getProperty("injector.fixture.$architecture.dll")
        assumeTrue(executableValue != null && dllValue != null, "Native $architecture fixtures were not provided.")

        val executable = Path.of(requireNotNull(executableValue))
        val dll = Path.of(requireNotNull(dllValue))
        assumeTrue(Files.isRegularFile(executable) && Files.isRegularFile(dll), "Native $architecture fixtures are missing.")

        return Fixture(
            executable = executable,
            dll = dll,
            dllMarker = dll.resolveSibling("injector-fixture.mrk"),
            readyMarker = executable.resolveSibling("injection-target.ready")
        )
    }

    private fun awaitFile(path: Path, isProcessRunning: () -> Boolean) {

        val deadline = System.nanoTime() + 10_000_000_000L
        while (!path.exists() && System.nanoTime() < deadline) {
            assertTrue(isProcessRunning(), "The target process exited before creating '${path.fileName}'.")
            Thread.sleep(25)
        }
        assertTrue(path.exists(), "Timed out waiting for '${path.fileName}'.")
    }

    private data class Fixture(
        val executable: Path,
        val dll: Path,
        val dllMarker: Path,
        val readyMarker: Path
    )
}
