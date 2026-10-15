# WCA v2.1.0 — Windows 11 Release Acceptance

**Two acceptance tracks:** existing assessment VM and fresh Windows 11 installation. Python tests and release packaging do not substitute for native Windows Procmon and GUI testing. Use only authorized/disposable test targets.

## A. Existing Windows assessment VM — targeted regression

Extract the complete **WCA v2.1.0 GitHub source distribution** (which includes `tests/`, `requirements-dev.txt`, and `scripts/validate_windows.ps1`) into a **new** folder. The slim tester release asset intentionally omits these release-validation components. Copy local `tool_paths.json` only when needed, open Windows PowerShell, then:

```powershell
.\install_dependencies.ps1 -TestDependencies
python .\wca.py --version
.\scripts\validate_windows.ps1
python .\wca.py --backend-action tool_readiness --backend-format text
python .\wca.py --gui
```

Expected: all included tests PASS or documented skips only; packaging audit PASS; **WCA 2.1.0** recognized; no version mismatch. The local `tool_paths.json` may exist on the VM but must not be present in the distributable ZIP.

- **GUI checks:** Overview/Recent Assessments switching, Browse, checkbox dimensions and option state in both Static/Full modes, all sidebar tabs, Help & About offline documentation, worker progress/scroll position, browser reload/reattachment, and Assessment Management availability explanations.
- **Review and evidence:** confirm ten-section validation guides, multiple sections opened together, optional notes retained, no repeated browser confirmation, and manifest integrity PASS after explicit save.
- **Runtime regression:** complete a new Full assessment in v2.1.0 (or reuse an intact same-version Full assessment). Start Guided Runtime, confirm **CAPTURING** only when Procmon is ready, manually exercise the approved client, press **Stop Guided Runtime Observation**, and wait for **PROCESSING** and completion. Confirm nonzero target-scoped events for a genuinely active target, useful correlations, no capture-controller exception, fresh review candidates, no raw full-host PML retention, and integrity PASS. Comparable candidate counts depend on comparable exercised workflows.
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

Full end-to-end **Windows GUI acceptance** requires the tests, native GUI/Procmon smoke tests, privacy/integrity/export checks and a clean-VM walkthrough. The project owner accepted v2.1.0 as the current baseline after Windows automated testing and field-artifact review; the remaining live GUI and clean-VM cases must still be recorded independently. Previous baselines remain available for rollback.

## Corrected v2.1.0 acceptance checks

The corrected ZIP preserves `WCA 2.1.0` as the framework version. Run the complete Windows suite, then exercise browser-controlled Guided Runtime on an intact same-version Full assessment. Confirm **Stop Guided Runtime Observation** appears after Procmon starts, telemetry updates are visible when available, capture continues despite a transient GUI telemetry warning, and the final report contains real target events and refreshed Guided Review conditions. Optional live-statistics failure must never be treated as an authoritative capture failure. Also verify Notifications can be dismissed and show action, safe code, outcome and next step. Running pytest should not add fake `case` assessments to Recent Assessments.

## v2.1.0 provenance acceptance

After a new assessment, verify `reports/collection_provenance.txt` exists, relevant `.txt` reports reference matching stable `PROV-xxxxx` IDs, recorded Procmon commands reflect actual execution, and skipped modules do not claim completed invocations. Review the report for tester profile names, target installer source paths, credentials and raw PowerShell bodies (none should appear). Run a supplemental Guided Runtime session and confirm IDs remain stable and the manifest still verifies. Review-only changes should not add execution events. Confirm the Client Appendix includes only sanitized `collection_provenance.txt`, not the working JSON. **Baseline status (October 15, 2026):** WCA v2.1.0 passed the Windows automated suite (427/427) and release audit. A full-mode Windows assessment, provenance reports, integrity evidence, and Client Appendix were reviewed. The project owner accepted v2.1.0 as the current baseline. This does **not** establish that all live browser GUI, Procmon-stop or clean-VM walkthrough checks below were independently witnessed; complete them before recording full end-to-end GUI acceptance.


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
