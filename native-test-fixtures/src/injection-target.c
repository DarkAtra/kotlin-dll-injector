#include <windows.h>
#include <wchar.h>

static BOOL sibling_path(const WCHAR *fileName, WCHAR path[MAX_PATH]) {
    DWORD pathLength = GetModuleFileNameW(NULL, path, MAX_PATH);
    WCHAR *separator;

    if (pathLength == 0 || pathLength >= MAX_PATH) {
        return FALSE;
    }

    separator = wcsrchr(path, L'\\');
    if (separator == NULL) {
        separator = wcsrchr(path, L'/');
    }
    if (separator == NULL) {
        return FALSE;
    }

    return wcscpy_s(separator + 1, MAX_PATH - (size_t)(separator + 1 - path), fileName) == 0;
}

static BOOL file_exists(const WCHAR *path) {
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL create_marker(const WCHAR *path) {
    HANDLE marker = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    CloseHandle(marker);
    return TRUE;
}

int main(void) {
    WCHAR dllMarker[MAX_PATH];
    WCHAR readyMarker[MAX_PATH];

    if (!sibling_path(L"injector-fixture.mrk", dllMarker) ||
        !sibling_path(L"injection-target.ready", readyMarker)) {
        return 1;
    }

    if (wcsstr(GetCommandLineW(), L"--expect-injected") != NULL && !file_exists(dllMarker)) {
        return 2;
    }

    if (!create_marker(readyMarker)) {
        return 3;
    }

    Sleep(INFINITE);
    return 0;
}
