# WCA v2.0.5 — Final Planned 2.0 Stabilization Candidate
> **Corrected v2.0.5 distribution (revision 2).** This package supersedes the original v2.0.5 ZIP without changing the framework or assessment schema version. It fixes non-authoritative GUI telemetry updates that could abort Windows Procmon capture, adds dismissible operation-specific GUI error notices with a recent-notifications panel, and isolates all GUI regression tests from tester Recent Assessments catalogs. The original permissions-attribution, checkbox sizing, and PowerShell release checks are retained. Native Windows capture acceptance is still required.


**Status:** Portable regression and packaging checks are part of the release build. **Windows 11 field acceptance is required** before this version replaces the previously validated baseline.

## Corrections

- Preserves PowerShell version normalization via `(Invoke-CheckedPython ... | Out-String).Trim()`, corrects the expected `WCA 2.0.5` version regex, and adds regression coverage so a stale version check blocks future releases.
- Includes the Windows-tested Full-assessment checkbox CSS fix. Option labels remain aligned beside 18px controls even under the global input styling.
- Tightens **Permissions Review** ownership attribution: unrelated software installed or updated during pre/post snapshots no longer automatically contributes hundreds of ACL candidates merely because it appears as a newly installed application **when a target service/task or explicit scope identifies authoritative target roots**. Legitimate service/task paths and out-of-tree target-correlated DLL search directories remain prioritized. Unattributed coverage and out-of-scope counts are disclosed; the raw installation differential is retained for internal review. No user-selected exclusion patterns are added and no evidence is deleted to silence findings.
- Adds focused regression tests for mixed target/background install traces, preserving DLL correlations, target-only ACL review, checkbox layout, and release/version consistency.
- Updates the README and full documentation set, especially clean Windows 11 setup, optional tools, GUI, Guided Runtime, Guided Review, Client Appendix, backend, troubleshooting, and versioned Windows acceptance.

## Preserved WCA behavior

- v2.0.4 GUI Guided Runtime's corrected Procmon callback and dedicated Stop control; real Windows capture previously recovered thousands of target events and the original review conditions.
- CLI and local-browser assessment options, completed assessment read compatibility, same-version mutation gates, exclusive operation locks, immutable integrity requirements, review note preservation, and Client Appendix sanitization.
- No automatic installation, target launch, service restart, login, PoC execution, or remote GUI exposure.

## Validate

Run ` .\install_dependencies.ps1 -TestDependencies ` and ` .\scripts\validate_windows.ps1 ` in a Windows 11 VM, then follow [Windows Acceptance](docs/windows-validation.md) on both your existing VM and a clean Windows 11 installation. Do not characterize v2.0.5 as Windows-accepted until those tests pass.
