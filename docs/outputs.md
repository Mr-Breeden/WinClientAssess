# WCA assessment outputs

**Artifact catalog:** 2.0

WCA separates tester-facing interpreted reports under `reports/` from authoritative/supporting state under `working/`. A `.txt` report is preferred when it is the authoritative human-readable interpretation; JSON/CSV is retained only when it serves a distinct operational, integrity, recovery or evidence purpose.

## Core reporting artifacts

| Artifact | Purpose |
|---|---|
| `assessment_report.html` | Offline tester dashboard generated from persisted assessment/review state. |
| `application_profile.txt` | Cross-phase application identity/technology/system/runtime summary. |
| `module_status.txt` | Collector/analysis status and coverage gaps. |
| `coverage_summary.txt` | Effective collection coverage interpretation. |
| `findings.txt` / `findings_summary.txt` | Automated review-point summaries; not proof of exploitation. |
| `tester_review.txt` | Persistent tester dispositions keyed to stable review candidates. |
| `evidence_guide.txt` | Candidate-specific validation guidance. |
| `test_cases.txt` | Evidence-aware tester test cases. |
| `attack_surface_test_plan.txt` | Vendor-neutral Windows thick-client attack-surface methodology, including guided/unobserved/unavailable surfaces. |
| `artifact_manifest.txt` | Human-readable artifact inventory. |
| `tool_detection.txt` | Detected external-tool capabilities. |
| `collection_provenance.txt` | Execution-derived sanitized command/method history with per-report record references. |

## Static/target artifacts

Portable targets use `target_analysis.txt` for primary executable identity, hashes, size and available version metadata. Installable targets retain installer/package artifacts such as `installer_analysis.txt`, `installer_technology.txt`, `installer_extraction.txt` and `msi_analysis.txt` where applicable. Non-applicable target-type modules are explicitly represented as such rather than fabricated.

Common static outputs include:

- `application_scope.txt`
- `signature_review.txt`
- `file_inventory.csv` (distinct structured inventory used by downstream correlation)
- `binary_security_review.txt`
- `dotnet_analysis.txt` / `dotnet_source_review.txt`
- `configuration_review.txt`
- `secrets_review.txt`
- `electron_security_review.txt`
- `component_lifecycle_review.txt`
- `updater_review.txt`

`secrets_review.txt` can include text/config indicators and PE printable-string indicators. Actual detected secret values remain redacted; PE indicators include location/encoding metadata for local tester validation.

## System-state / privilege artifacts

Full mode can generate:

- `install_changes.txt`
- `filesystem_changes.txt`
- `registry_changes.txt`
- `installed_files.txt`
- `installed_directories.txt`
- `services_review.txt`
- `scheduled_tasks_review.txt`
- `permissions_review.txt`
- `local_storage_review.txt`
- `persistence_review.txt`
- `new_drivers.txt`
- `privilege_boundary_review.txt`
- `attack_surface_correlations.txt`

Some filenames retain historical `install`/`installed` terminology for compatibility even when the target is portable. In portable full mode they represent the observed baseline-to-post-activity system differential, not an assertion that installation occurred.

The authoritative snapshots remain structured JSON because they support correlation, recovery and integrity:

- `working/snapshot_pre.json`
- `working/snapshot_post.json`

## Runtime artifacts

When runtime/Guided Runtime collection is available, reports can include process activity, child processes, loaded images/DLLs, missing DLL lookups, file/registry/network activity, target handles/modules, advanced runtime review and `guided_runtime_observation.txt`.

Raw/full-host Procmon PML/CSV is temporary. Target-scoped sanitized structured evidence may be retained under `working/` because it supports reproducibility/correlation; duplicate interpreted CSV/JSON reports are not produced merely for convenience.

## Network / IPC artifacts

Applicable outputs include:

- `network_surface_review.txt`
- `target_firewall_rules.txt`
- `localhost_service_candidates.txt`
- `ipc_review.txt`
- `named_pipe_inventory.txt`
- `named_pipe_permissions.txt`

## Updater / maintenance artifacts

Where updater components are observed, WCA can retain updater component, permission, endpoint, runtime and security-correlation reports. No updater present is **NOT APPLICABLE**, not a fabricated PASS.

## Internal state

`working/assessment_state.json`, `working/assessment_manifest.json`, `working/tester_review_state.json`, `working/collection_provenance_state.json`, render state and required structured target/runtime evidence are operational state, not client-facing findings.

## Evidence-state semantics

Reports distinguish **OBSERVED**, **COLLECTED / NO OBSERVATION**, **NOT COLLECTED / SKIPPED**, and **COLLECTION UNAVAILABLE** where applicable. These labels describe evidence availability/observation, not vulnerability confirmation.

## Client Appendix output (external)

Client Appendix is deliberately a separate ZIP created **outside** the assessment tree. It is not a new authoritative tester report or assessment artifact; the source manifest and original reports remain unchanged. Its contents are strictly allowlisted: standalone `assessment_report.html`, `README.txt`, `SHA256SUMS.txt` and a small approved `evidence/*.txt` subset. See `client-appendix.md`.

## Collection provenance (v2.1.0)

Applicable `.txt` reports carry a concise Collection Provenance reference. See [Evidence Collection Provenance](collection-provenance.md) for command privacy, internal method attribution, record-ID stability, skipped modules and reproduction limitations. Raw binary/CSV/JSON evidence retains its original format.

## v2.2.0 manual testing state

- `working/manual_test_review.json`: private, integrity-manifest-tracked manual test-case decisions and optional evidence references/notes. **Not** a duplicate of `tester_review.txt` or `working/tester_review_state.json`. Not included in Client Appendix.
- `reports/test_cases.txt`: unchanged generated human-readable reference, not the authoritative completion-state file.
- GUI Tester Workspace: presents one integrity-verified Testing Queue. A completed manual test remains unresolved if any linked Guided Review candidate is pending or changed; underlying decisions remain separate and do not confirm security impact.

## v2.2.0 report inventory and consolidation decision

v2.2.0 retains existing report filenames and valid working-state records. No additional required testing is created by the attack-surface reference plan or optional generated `test_cases.txt`: all applicable completion is tracked once in the GUI Testing Queue. The detailed report-by-report audit is supplied separately in the RC1 handoff. Future installer/system-change/runtime/network-IPC grouping requires explicit file mapping, reference updates, provenance and integrity migration and regression coverage.

## M2-p3 reporting review

The full M2-p3 artifact audit supplied alongside the Windows development package inventories every observed Full Assessment report and the Client Appendix. Grouping options include installer/package details, system changes, IPC/network, and runtime/Procmon slices. **No existing report filenames are deleted in M2-p3.** Consumers and integrity tests still expect their existing separate evidence products, and older assessments must remain readable.
