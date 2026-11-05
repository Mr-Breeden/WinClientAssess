# WinClientAssess v2.2.3 — Release Notes

**Platform:** Windows 11 x64  
**Framework version:** 2.2.3  
**Status:** GitHub release package prepared from the Windows-accepted p20 RC1 candidate.

This release focuses on reducing repetitive manual review and improving the traceability of thick-client security evidence. The local GUI and CLI support Static and tester-controlled Full assessments, Guided Runtime observations, independent TC/WCR decisions, integrity checks, and a privacy-sanitized Client Appendix.

## Highlights

- **Evidence-first review:** Selected network endpoints, filesystem/storage ACLs, registry/pipe permissions, and runtime events appear alongside the relevant procedure, rather than unrelated report excerpts. ACL panels distinguish collected results from optional live verification.
- **Contextual guidance:** CFG, ASLR, DEP, ACL, IPC and other example interpretations appear within the applicable test steps; the WinDbg, Ghidra and Frida Getting Started guides appear in TC-AR-003 Step 5.
- **Network WCR consolidation:** Equivalent IPv4 and IPv6 wildcard bindings share a review, while per-family endpoint evidence and historical tester dispositions remain intact. A merged review requires an explicit decision.
- **PE hardening analysis:** DUMPBIN produces a concise run summary and exportable raw verification ZIP; missing metadata remains a review observation, not a confirmed exploitable condition.
- **Secrets and runtime signals:** Better structured-secret filtering, redacted persisted evidence, more accurate process/network correlation, and manual context for Windows Error Reporting events.
- **Operations and provenance:** Tool Readiness official setup links, safer path resolution for verified files, improved collection provenance and recoverable tool-cleanup reporting, and a separately sanitized Client Appendix.

## Installation

Extract `WCA-v2.2.3-Tester.zip` on a trusted Windows 11 system, then run from PowerShell:

```powershell
.\install_dependencies.ps1
python .\wca.py --version
python .\wca.py
```

Use `--cli` for the terminal interface. Approve Windows UAC when required and keep the localhost GUI session URL private. See `README.md` and `docs/getting-started.md` for details.

## Validation and scope

The assessor reported a successful Windows RC1 acceptance test. The p20 source baseline had 82 passing Python regression tests and 19 additional subtests, and the release package was audited separately. The distributed tester ZIP intentionally omits automated regression suites and historical patch/testing checklists. The source distribution retains developer tests. Release packaging does not assert that every optional third-party tool has been installed on every machine.

WCA does not automatically confirm vulnerabilities. Review candidates, security hardening gaps and tester dispositions are distinct from independently established findings. Tester notes remain optional. Collected evidence should be independently verified under the appropriate trust context.

## Assets

- `WCA-v2.2.3-Tester.zip` — operational Windows package.
- `WCA-v2.2.3-Source.zip` — application source plus regressions.
- `WCA-v2.2.3-SHA256SUMS.txt` — SHA-256 digest file.

Historical development patches are not individual production releases and are not included as release assets.
