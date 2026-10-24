package de.darkatra.injector.jna

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.W32APIOptions

internal interface Kernel32 : com.sun.jna.platform.win32.Kernel32 {

    companion object {

        val INSTANCE: Kernel32 = Native.load("kernel32", Kernel32::class.java, W32APIOptions.DEFAULT_OPTIONS)
    }

    /*
     * See: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
     *
     * BOOL VirtualProtectEx(
     *   [in]  HANDLE hProcess,
     *   [in]  LPVOID lpAddress,
     *   [in]  SIZE_T dwSize,
     *   [in]  DWORD  flNewProtect,
     *   [out] PDWORD lpflOldProtect
     * );
     */
    fun VirtualProtectEx(
        processHandle: HANDLE,
        address: Pointer,
        size: BaseTSD.SIZE_T,
        newProtection: Int,
        oldProtection: IntByReference
    ): Boolean

    /*
     * See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
     *
     * DWORD ResumeThread(
     *   [in] HANDLE hThread
     * );
     */
    fun ResumeThread(threadHandle: HANDLE): Int
}