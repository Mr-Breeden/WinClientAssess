/* WCA local-lab harmless DLL-loading marker; NOT a shell payload.
 * Compile to match the consumer process architecture (e.g. MinGW-w64):
 * x86_64-w64-mingw32-gcc -shared -Os -o Shared.dll marker_dll.c
 * Customize exported symbols only after inspecting the actual missing DLL.
 * Never overwrite an existing DLL. Run solely inside an authorized disposable VM.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "proof_identity.h"

static DWORD WINAPI write_marker(LPVOID unused) {
    WCHAR path[MAX_PATH], name[256];
    DWORD size = sizeof(name) / sizeof(name[0]);
    (void)unused;
    DWORD count = GetTempPathW(MAX_PATH, path);
    if (!count || count + 24 >= MAX_PATH || !GetUserNameW(name, &size)) return 0;
    lstrcatW(path, L"WCA_DLL_LOAD_PROOF.txt");
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    char buffer[600];
    int len = snprintf(buffer, sizeof(buffer), "WCA_DLL_LOADED PID=%lu USER=%ls INTEGRITY_RID=%lu\r\n",
                       GetCurrentProcessId(), name, wca_integrity_rid());
    if (len > 0 && len < (int)sizeof(buffer)) {
        DWORD written = 0;
        WriteFile(file, buffer, (DWORD)len, &written, NULL);
    }
    CloseHandle(file);
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(NULL, 0, write_marker, NULL, 0, NULL);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
