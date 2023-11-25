package de.darkatra.injector.jna

import com.sun.jna.Native
import com.sun.jna.Structure.*
import com.sun.jna.platform.win32.WinDef.DWORD
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.win32.W32APIOptions

internal interface Kernel32 : com.sun.jna.platform.win32.Kernel32 {

    companion object {

        val INSTANCE: Kernel32 = Native.load("kernel32", Kernel32::class.java, W32APIOptions.DEFAULT_OPTIONS)
    }

    /**
     * See: https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop
     *
     * BOOL DebugActiveProcessStop(
     *   [in] DWORD dwProcessId
     * );
     */
    fun DebugActiveProcessStop(
        dwProcessId: DWORD
    ): Boolean

    /**
     * See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadid
     *
     * DWORD GetThreadId(
     *   [in] HANDLE Thread
     * );
     */
    fun GetThreadId(
        thread: HANDLE
    ): DWORD
}
