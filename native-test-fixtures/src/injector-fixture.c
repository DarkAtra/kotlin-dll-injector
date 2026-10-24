#include <windows.h>
#include <wchar.h>

static BOOL create_marker(HMODULE module, const WCHAR *extension) {
    WCHAR path[MAX_PATH];
    DWORD pathLength;
    WCHAR *dot;
    HANDLE marker;

    pathLength = GetModuleFileNameW(module, path, MAX_PATH);
    if (pathLength == 0 || pathLength >= MAX_PATH) {
        return FALSE;
    }

    dot = wcsrchr(path, L'.');
    if (dot == NULL || wcscpy_s(dot, MAX_PATH - (size_t)(dot - path), extension) != 0) {
        return FALSE;
    }

    marker = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    CloseHandle(marker);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        return create_marker(instance, L".mrk");
    }

    return TRUE;
}

void InjectorOrdinalOne(void) {
}
