/* Shared harmless execution-token inspection; used only by local lab marker binaries. */
#ifndef WCA_PROOF_IDENTITY_H
#define WCA_PROOF_IDENTITY_H
#include <windows.h>
#include <stdio.h>
static DWORD wca_integrity_rid(void) {
    HANDLE token = NULL;
    DWORD size = 0, rid = 0;
    PTOKEN_MANDATORY_LABEL label;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &size);
    if (!size) { CloseHandle(token); return 0; }
    label = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, size);
    if (label && GetTokenInformation(token, TokenIntegrityLevel, label, size, &size)) {
        PSID sid = label->Label.Sid;
        PUCHAR count = GetSidSubAuthorityCount(sid);
        if (count && *count) rid = *GetSidSubAuthority(sid, *count - 1);
    }
    if (label) LocalFree(label);
    CloseHandle(token);
    return rid;
}
#endif
