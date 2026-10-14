# WCA v2.0.5 — Windows 11 Release Acceptance

**Two acceptance tracks:** existing assessment VM and fresh Windows 11 installation. Python tests and release packaging do not substitute for native Windows Procmon and GUI testing. Use only authorized/disposable test targets.

## A. Existing Windows assessment VM — targeted regression

Extract the official WCA v2.0.5 ZIP into a **new** folder, copy local `tool_paths.json` only when needed, open Windows PowerShell, then:

```powershell
.\install_dependencies.ps1 -TestDependencies
python .\wca.py --version
.\scripts\validate_windows.ps1
python .\wca.py --backend-action tool_readiness --backend-format text
python .\wca.py --gui
```

Expected: all included tests PASS or documented skips only; packaging audit PASS; **WCA 2.0.5** recognized; no version mismatch. The local `tool_paths.json` may exist on the VM but must not be present in the distributable ZIP.

- **GUI checks:** Overview/Recent Assessments switching, Browse, checkbox dimensions and option state in both Static/Full modes, all sidebar tabs, Help & About offline documentation, worker progress/scroll position, browser reload/reattachment, and Assessment Management availability explanations.
- **Review and evidence:** confirm ten-section validation guides, multiple sections opened together, optional notes retained, no repeated browser confirmation, and manifest integrity PASS after explicit save.
- **Runtime regression:** complete a new Full assessment in v2.0.5 (or reuse an intact same-version Full assessment). Start Guided Runtime, confirm **CAPTURING** only when Procmon is ready, manually exercise the approved client, press **Stop Guided Runtime Observation**, and wait for **PROCESSING** and completion. Confirm nonzero target-scoped events for a genuinely active target, useful correlations, no capture-controller exception, fresh review candidates, no raw full-host PML retention, and integrity PASS. Comparable candidate counts depend on comparable exercised workflows.
- **ACL attribution:** if pre/post snapshots contain changes from another unrelated updater, verify `permissions_review.txt` excludes its file trees from automatic target ACL queries when high-confidence target ownership roots are known. Confirm target services, tasks and DLL-correlated external directories remain. The full installation differential must remain available for examination. The output reports scoped/omitted path counts and processing limit.
- **Client Appendix:** only explicitly export a completed, reviewed and integrity-verified assessment. Check ZIP inventory, checksums, privacy sanitization, relative links, and that source manifest hashes did not change.

Do **not** bypass version-bound mutation gates, change assessment hashes manually, or infer capture success only from a PASS integrity result.

## B. Fresh Windows 11 VM — documentation walkthrough

Follow [Windows VM Setup](windows-environment-setup.md) from beginning to end on a new Windows 11 x64 VM. Record Python/.NET/7-Zip versions, elevation status, installer/source links used, PATH and tool detection. Run the tests and GUI launch above. Test at least one Static assessment and, when tooling is available, a Full installable assessment with manual target installation and Guided Runtime. Confirm required tools detected, missing optional tools identified without false PASS statements, no unrelated desktop installer execution by WCA, and successful sanitized Client Appendix where reviewed. Capture unclear/inaccurate instructions for the next maintenance patch.

## C. Older-assessment compatibility (read-only)

Completed earlier assessments may be read and exported when integrity and review requirements permit, but cannot be silently upgraded or modified with a different WCA version.

```powershell
$assessment = 'C:\Assessments\CompletedEarlierCase'
$manifest = Join-Path $assessment 'working\assessment_manifest.json'
$before = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash
python .\wca.py --backend-action status --backend-assessment $assessment --backend-format text
python .\wca.py --backend-action verify --backend-assessment $assessment --backend-format text
python .\wca.py --backend-action review --backend-assessment $assessment --backend-format text
$after = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash
Write-Host "Manifest unchanged: $($before -eq $after)"
```

Expect manifest unchanged. Separate Client Appendix export is always an explicit tester action and remains integrity/review-gated.

## Acceptance criteria

A release is **Windows-accepted** only after the new version passes its tests, the native GUI/Procmon smoke tests, privacy/integrity/export checks, and the clean-VM documentation walkthrough. Retain the previously accepted v1.9.6 CLI and v2.0.4 field-tested evidence as baselines during this acceptance cycle.

## Corrected v2.0.5 acceptance checks

The corrected ZIP preserves `WCA 2.0.5` as the framework version. Run the complete Windows suite, then exercise browser-controlled Guided Runtime on an intact same-version Full assessment. Confirm **Stop Guided Runtime Observation** appears after Procmon starts, telemetry updates are visible when available, capture continues despite a transient GUI telemetry warning, and the final report contains real target events and refreshed Guided Review conditions. Optional live-statistics failure must never be treated as an authoritative capture failure. Also verify Notifications can be dismissed and show action, safe code, outcome and next step. Running pytest should not add fake `case` assessments to Recent Assessments.
