/* WCA controlled marker executable. Build for the appropriate architecture:
 * x86_64-w64-mingw32-gcc -Os -o marker.exe marker_exe.c
 * NEVER overwrite an existing executable; use only a verified writable search
 * candidate in the disposable authorized VM, then remove the test executable.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "proof_identity.h"
int main(void) {
    WCHAR path[MAX_PATH], name[256];
    DWORD size = sizeof(name) / sizeof(name[0]);
    DWORD n = GetTempPathW(MAX_PATH, path);
    if (!n || n + 24 >= MAX_PATH || !GetUserNameW(name, &size)) return 2;
    lstrcatW(path, L"WCA_EXE_LOAD_PROOF.txt");
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 3;
    char buffer[600];
    int count = snprintf(buffer, sizeof(buffer), "WCA_EXE_EXECUTED PID=%lu USER=%ls INTEGRITY_RID=%lu\r\n",
                         GetCurrentProcessId(), name, wca_integrity_rid());
    DWORD written = 0;
    if (count > 0 && count < (int)sizeof(buffer))
        WriteFile(file, buffer, (DWORD)count, &written, NULL);
    CloseHandle(file);
    return 0;
}
