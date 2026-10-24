package de.darkatra.injector.jna

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.WinNT.HANDLE
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.W32APIOptions

internal interface Ntdll : com.sun.jna.platform.win32.NtDll {

    companion object {

        const val PROCESS_BASIC_INFORMATION = 0x00
        const val PROCESS_WOW64_INFORMATION = 0x1a

        val INSTANCE: Ntdll = Native.load("ntdll", Ntdll::class.java, W32APIOptions.DEFAULT_OPTIONS)
    }

    /*
     * See: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
     *
     * NTSTATUS NtQueryInformationProcess(
     *   [in]            HANDLE           ProcessHandle,
     *   [in]            PROCESSINFOCLASS ProcessInformationClass,
     *   [out]           PVOID            ProcessInformation,
     *   [in]            ULONG            ProcessInformationLength,
     *   [out, optional] PULONG           ReturnLength
     * );
     */
    fun NtQueryInformationProcess(
        processHandle: HANDLE,
        processInformationClass: Int,
        processInformation: Pointer,
        processInformationLength: Int,
        returnLength: IntByReference?
    ): Int
}
