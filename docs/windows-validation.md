# WCA v2.2.1 — Windows 11 Release Acceptance

**Two acceptance tracks:** existing assessment VM and fresh Windows 11 installation. Python tests and release packaging do not substitute for native Windows Procmon and GUI testing. Use only authorized/disposable test targets.

## A. Existing Windows assessment VM — targeted regression

Extract the complete **WCA v2.2.0 GitHub source distribution** (which includes `tests/`, `requirements-dev.txt`, and `scripts/validate_windows.ps1`) into a **new** folder. The slim tester release asset intentionally omits these release-validation components. Copy local `tool_paths.json` only when needed, open Windows PowerShell, then:

```powershell
.\install_dependencies.ps1 -TestDependencies
python .\wca.py --version
.\scripts\validate_windows.ps1
python .\wca.py --backend-action tool_readiness --backend-format text
python .\wca.py --gui
```

Expected: all included tests PASS or documented skips only; packaging audit PASS; **WCA 2.2.0** recognized; no version mismatch. The local `tool_paths.json` may exist on the VM but must not be present in the distributable ZIP.

- **GUI checks:** Overview/Recent Assessments switching, Browse, checkbox dimensions and option state in both Static/Full modes, all sidebar tabs, Help & About offline documentation, worker progress/scroll position, browser reload/reattachment, and Assessment Management availability explanations.
- **Review and evidence:** confirm ten-section validation guides, multiple sections opened together, optional notes retained, no repeated browser confirmation, and manifest integrity PASS after explicit save.
- **Runtime regression:** complete a new Full assessment in v2.2.0 (or reuse an intact same-version Full assessment). Start Guided Runtime, confirm **CAPTURING** only when Procmon is ready, manually exercise the approved client, press **Stop Guided Runtime Observation**, and wait for **PROCESSING** and completion. Confirm nonzero target-scoped events for a genuinely active target, useful correlations, no capture-controller exception, fresh review candidates, no raw full-host PML retention, and integrity PASS. Comparable candidate counts depend on comparable exercised workflows.
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

Full end-to-end **Windows release acceptance** requires regression tests, native GUI/Procmon functional evidence, privacy/integrity/export checks and a clean-VM walkthrough. WCA v2.1.0 was the previous published baseline. M2-p4 native Windows full functional testing, M2-p5 native UAC checks, and v2.2.0-RC1 tester-distribution GUI/assessment-access smoke passed. Previous releases remain available for rollback.

## Corrected v2.2.0 acceptance checks

The corrected ZIP preserves `WCA 2.2.0` as the framework version. Run the complete Windows suite, then exercise browser-controlled Guided Runtime on an intact same-version Full assessment. Confirm **Stop Guided Runtime Observation** appears after Procmon starts, telemetry updates are visible when available, capture continues despite a transient GUI telemetry warning, and the final report contains real target events and refreshed Guided Review conditions. Optional live-statistics failure must never be treated as an authoritative capture failure. Also verify Notifications can be dismissed and show action, safe code, outcome and next step. Running pytest should not add fake `case` assessments to Recent Assessments.

## v2.2.0 provenance acceptance

After a new assessment, verify `reports/collection_provenance.txt` exists, relevant `.txt` reports reference matching stable `PROV-xxxxx` IDs, recorded Procmon commands reflect actual execution, and skipped modules do not claim completed invocations. Review the report for tester profile names, target installer source paths, credentials and raw PowerShell bodies (none should appear). Run a supplemental Guided Runtime session and confirm IDs remain stable and the manifest still verifies. Review-only changes should not add execution events. Confirm the Client Appendix includes only sanitized `collection_provenance.txt`, not the working JSON. **Accepted baseline (October 15, 2026):** WCA v2.1.0 passed Windows automated validation (427/427) and release audit; its full-mode assessment, provenance evidence, integrity state, and Client Appendix were reviewed. WCA v2.2.0 production promotion uses the accepted M2-p4 Full/Guided Runtime/review/export, M2-p5 UAC and RC1 tester-package GUI acceptance. Continue clean-VM tool checks for new environments.


### Provenance usability patch regression (baseline accepted; live rechecks still advised)

- Check provenance appears **near the top** only in evidence reports; verify
  `test_cases.txt`, `tester_review.txt`, `findings.txt`,
  `findings_summary.txt`, and `coverage_summary.txt` have no provenance block.
- Inspect the central `collection_provenance.txt`: counts and failed executions
  must be visible before the full execution record list.
- Verify a live recheck command for services, ACLs, signing, PE flags, network
  listeners and named pipes against the actual target **on Windows**. It must
  reproduce only its explicitly stated subset of observations; it is not a
  claimed transcript of a WCA command.
- Verify no raw PowerShell body, source target path, tester profile name or
  secret appears in collected history or generated commands.
- Regenerate reports and ensure provenance IDs remain stable, no duplicate
  headers appear, and the assessment integrity manifest verifies after the
  supported regeneration action. Existing completed assessments must not be
  edited in place outside WCA's integrity-safe lifecycle.

## Historical v2.2.0 Tester Workflow acceptance (M1; superseded by Testing Queue)

1. Begin a fresh current-version Full assessment, complete tester-controlled runtime collection, and verify integrity.
2. Open Tester Workspace > Manual Test Cases; verify manual cases equal the applicable `test_cases.txt` entries. Filter by ID/title, status and category. Select TC-IN-001, review inline instructions and use its actual supporting-report buttons; confirm reports open in place without navigating to Reports. Confirm unavailable reports have no clickable link.
3. Save an IN PROGRESS and then a COMPLETED status with optional notes/evidence reference. Refresh and restart the GUI, confirming saved progress persists.
4. Verify Assessment Management integrity PASS and confirm the generated `test_cases.txt` byte content did not change.
5. Confirm Guided Review candidates retain independent dispositions and `attack_surface_test_plan.txt` remains a separate testing guide.
6. Open a v2.1.0 completed assessment in read-only mode; manual status editing must be disabled.
7. Generate the Client Appendix and verify it contains no private manual-test notes or supporting-state JSON.
8. Test failed save/locked assessment behavior and confirm the original verified state remains intact.
9. Confirm localhost token protection on manual-test listing/detail/save APIs.

10. Browser checkpoint double-submit regression: after acknowledging an in-browser checkpoint, a second response using the same ID must be rejected as already sent, whether the worker has retained or deleted its checkpoint file.

Passing unit tests on Linux is not a substitute for these native Windows acceptance checks.

## Historical v2.2.0-M2 navigation acceptance (superseded by M2-p4)

Confirm the single Tester Workspace navigation contains Overview, Guided Review, Manual Test Cases, Evidence & Guidance, and Final Checklist. Switch between tabs without clearing unsaved notes, and verify the legacy ten-section review guide still saves dispositions independently from manual case status. Check case filtering by ID/title/report, status, and category; selection of TC-IN-001 should link only existing verified installer reports, with an in-workspace read-only preview. Confirm no unintended assessment mutation occurs from filtering or opening reports. Test persistence after reload, integrity PASS after explicit saves, and legacy v2.1.x read-only behavior. Windows GUI acceptance remains pending until tested on the assessment VM.


## v2.2.0-M2-p5 — Administrator preflight / Windows UAC smoke test

This is a targeted **native Windows** test. An additional full DarkRelay assessment is not required solely for the elevation change if the earlier M2-p4 functional assessment remains accepted.

1. From a **non-elevated** PowerShell window with the WCA `.venv` active, run `python .\wca.py --version`, then `python .\wca.py --help`. Both should succeed without UAC.
2. Run `python .\wca.py --gui`. Verify UAC appears before the localhost server starts. Approve it. The unelevated parent must exit and WCA must start in a **new elevated console**, bound only to `127.0.0.1`, with a fresh private GUI session URL. Verify the Python executable remains the intended `.venv` interpreter. Keep this new console open while testing.
3. Stop that GUI, and repeat from normal PowerShell but **decline** UAC. WCA should report that elevation was declined/failed, must not start the GUI server or create an assessment, and must not repeatedly prompt.
4. From an **Administrator** PowerShell window launch `python .\wca.py --gui`. Verify no additional UAC dialog, normal private local URL, and normal GUI navigation.
5. Verify `python .\wca.py --backend-action capabilities --backend-format text` and a supported static CLI assessment remain accessible without elevation. A Full-mode CLI run and standalone Guided Runtime must request/admin-check before privileged collection; if UAC is declined, they must not create or mutate assessment state.
6. Test `python .\wca.py --gui --port 9002` from non-elevated PowerShell and confirm the approved elevated child uses port 9002 and the same working folder/interpreter. Test a UAC-denied launch with the same flag.

If UAC opens a separate console, do not use a URL/session fragment printed in the original parent. Treat the private GUI URL as an access credential; avoid sharing it in screenshots or logs. Automated tests simulate the OS calls and **do not** prove that native UAC actually works on the tester VM.


## v2.2.0 — Final package smoke (pending)

Use the production **Tester ZIP** rather than a development source directory for a light smoke test. Validate elevated GUI startup and browser token, open the completed integrity-verified M2-p4 assessment in read-only mode, inspect one TC with multiple linked WCRs and their separate cards, and review Evidence & Guidance and a sanitized Client Appendix. Do not modify the baseline assessment just to prove packaging. Use the **Source ZIP** for regression and audit commands. Complete a clean Windows installation walkthrough and compare both manifests/checksums. See [release validation](release-validation.md).

**Field-tested history:** M2-p4 full functional/assessment/export behavior and M2-p5 live UAC happy, denial and non-admin CLI checks were reported successful. A full new DarkRelay assessment is **not** a prerequisite unless production smoke uncovers a functional regression.
