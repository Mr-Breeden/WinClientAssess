# Changelog

### v2.0.5 corrected distribution (revision 2)
- Resilient, best-effort GUI-only telemetry updates: bounded Windows rename retries and a single sanitized warning; failure to update statistics cannot discard Procmon capture evidence. Stop Capture remains available from an initialized capture checkpoint when telemetry is unavailable. Evidence and integrity controls remain strict.
- Dismissible, operation-labelled GUI notifications with sanitized codes, outcome, suggested next step, copyable diagnostics and recent in-session history.
- GUI test fixtures use private temporary Recent Assessments catalogs rather than registering deleted test cases in the real tester catalog.
- Previously delivered v2.0.5 PowerShell version guard, checkbox CSS, permissions attribution, and documentation remain in effect.


## v2.0.5 — Evidence Quality, GUI Fixes, and Documentation Stabilization

- Carried forward the Windows-tested checkbox alignment fix and correct PowerShell version normalization/matching.
- Added release regression guard for CLI, pyproject, web metadata and Windows validator version consistency.
- Avoided promoting unrelated registered-application updates into ACL scope where service/task/tester-scoped target roots exist. Preserved DLL-correlated writable directories and original full installation differential.
- Added accurate ACL filtering counters, focused regression coverage, and a complete current Windows 11 setup, GUI and acceptance-documentation update.
- Preserved the v2.0.4 browser-controlled Procmon capture and all tester-controlled execution/integrity safeguards.
- Windows acceptance pending.

## v2.0.4 — Guided Runtime Capture Fix and Web Workflow Improvements (Windows acceptance candidate)

- Fix the Procmon collector → private GUI capture controller keyword-argument mismatch that prematurely ended v2.0.2/v2.0.3 guided captures (`procmon_path` rejected), yielding zero target events and fewer review candidates.
- Mark a failed capture-controller operation with an explicit `capture_controller` failure stage and no ostensibly successful zero-event Procmon CSV; retain non-Procmon point-in-time observations as available, with coverage gaps honestly reported.
- Require initialized, nonempty PML telemetry before enabling **Stop Guided Runtime Observation**; stopping acknowledges the tester's pending checkpoint, terminates Procmon through the existing collector, and continues sanitized filtering, correlations, report refresh and integrity verification.
- Add New Assessment choices for extraction, expanded filesystem snapshot inventory, Network/IPC review (on by default in Full mode), and optional Procmon capture (off by default). The browser preselects optional Yes/No decisions, leaving the manual install/activity checkpoint and, if requested, explicit Procmon Stop. The independent CLI keeps its existing prompts and collection methodology.
- Guided Review validation sections can remain open simultaneously; add **Expand All / Collapse All** and remember per-candidate expanded sections during navigation.
- Display a persistent worker-status control throughout GUI navigation, linking back to Overview for manual checkpoints.
- Add regression tests for the actual collector/controller call signature, controller errors, safety-gated options, capture readiness, stop controls, and GUI interactions. Preserve v1.9.6 as the known Windows-validated CLI baseline; this GUI update requires native Windows Procmon acceptance.

UI Usability, Runtime Visibility and Assessment Management (Windows acceptance candidate)

- Add a local recent-assessment catalog with bounded discovery of previously selected output folders and quick switching on Overview; the index lives outside assessments and is not treated as an integrity verification.
- Show integrity-verified Guided Runtime session history after GUI restarts; add prominent Starting/Capturing/Processing/Completed/Failed live status and browser Stop Capture controls.
- Preserve worker-log scroll position across polling, stop unnecessary polling of finished jobs, avoid overlapping requests and keep the Windows Browse event handlers intact.
- Consolidate Overview status/review/runtime summary into one endpoint; cache read-only validation cards briefly without caching mutation authorization.
- Add Assessment Management sidebar page for integrity verification, safe resume eligibility and explicitly confirmed derived-report regeneration; remove those maintenance controls from Overview.
- Add offline Help & About with Getting Started, Windows VM setup, supported tools and version metadata where safely verifiable from PE resources (without executing third-party tools).
- Preserve v1.9.6-derived collectors, CLI functionality, evidence schemas and tester-only target/PoC execution policy. Native Windows GUI acceptance required.

## v2.0.2 — Native Browser Assessment Jobs (Windows acceptance candidate)

- Run static, full, resume and Guided Runtime workflows in **private Python background workers** without opening a PowerShell window. Reuse the existing assessment engine and manual-only testing policy.
- Add an explicit checkpoint transport: browser Continue / Yes-No / path/choice responses are validated and delivered only to the pending worker checkpoint, with replay protection and per-assessment operation locks.
- Stream bounded privacy-normalized console status, authoritative lifecycle checkpoints, and guided Procmon live metrics to the local browser dashboard. Browser refresh reattaches to the active job; creating a second operation for the same assessment is refused.
- Guided Runtime supports browser Stop Capture while preserving target-scoped Procmon filtering and raw-host cleanup. No target process, PoC, service restart or installation is automated.
- Preserve v2.0.1 ten-section Guided Review, saved-notes handling, integrity-verified mutations, and Client Appendix export.
- Keep all 37 original assessment collector modules unchanged. Maintain methodology and artifact catalog 1.9 and the accepted v1.9.6 CLI baseline.

# Changelog

## v2.0.1 — Guided Review and GUI Reliability (Windows acceptance candidate)

- Preserve the initial offline loopback-only GUI (`--gui`, `--port 9001`) with the existing CLI fully retained.
- Upgrade Guided Review to a two-panel selection and ten-section candidate-specific playbook, searchable/filterable conditions, report links, copyable starting commands, loaded existing notes and a single explicit Save action.
- Add guarded save rollback with external temporary evidence backup and integrity recheck for caught write failures; preserve fail-closed behavior and backups when restoration cannot be verified. Existing damaged assessments are never silently repaired.
- Handle browser disconnects without retrying an HTTP response on a closed socket.
- Preserve assessment overview, tool readiness, text-only reports, Client Appendix, repairable derived reports and tester-controlled CLI job handoff.
- Local GUI authorization and origin checks; no remote listener, automatic target/PoC execution or collector changes.
- Correct PowerShell version-validation output normalization from v1.9.6 Windows acceptance.
- GUI regression, security-boundary and package tests; methodology/artifact catalog unchanged at 1.9.

## v1.9.6 — Windows subprocess UTF-8 compatibility patch

- Correct readable backend CLI subprocess tests to request UTF-8 *from the child Python process*, fixing Windows/Python 3.14 decoding errors without changing the user-facing JSON or text formats.
- Add a simulated legacy-codepage regression test so this behavior is tested on non-Windows systems as well.
- Fix the Windows validation script's incorrectly stale 1.9.4 version-match condition; update source/version assertions and clean Windows setup documentation.
- Preserve v1.9.5 test portability, local `tool_paths.json` package exclusion, security/privacy requirements, collector behavior, integrity and review rules, tester-only proof execution and methodology/artifact catalog 1.9.

## v1.9.5 — Windows acceptance fixes and readable backend presentation

- Correct Windows portability tests for `PSModulePath` capitalization and Rich console card borders/ANSI rendering while retaining substantive security/privacy and layout assertions.
- Allow testers to retain a local `tool_paths.json` during validation; explicitly exclude it from release packaging.
- Add optional `--backend-format text` for read-only backend commands, preserving JSON as the default and the schema 1.0 envelope unchanged.
- Update Windows validation, docs, release notes and regression coverage; no assessment engine or methodology change.

## v1.9.4 — Final pre-GUI stabilization and environment readiness

- Correct subprocess timeout output normalization (stdout and stderr always text) while preserving partial evidence and timeout status.
- Make Windows release validation fail closed on native command failures; provide opt-in `requirements-dev.txt` and `install_dependencies.ps1 -TestDependencies` without adding pytest to runtime requirements.
- Add operation-lock error/stale-lock regressions; retain explicit manual recovery and advisory-file-lock limitations.
- Correct Client Appendix version labeling to use the source assessment framework version rather than a stale hardcoded label; retain strict export safety controls.
- Remove unused legacy Guided Runtime checklist functions, preserving live capture behavior; integrate clean Windows VM setup guide and update docs, versions and release allowlist.
- No change to detectors, process attribution, methodology/catalog 1.9, report schemas or tester-controlled PoCs. Windows acceptance required; v1.9.2 remains the verified reference until v1.9.4 is accepted.

## v1.9.3 — Backend modernization, GUI readiness and documentation

- Preserve the Windows-validated v1.9.2 analysis modules, target scoping, stable review IDs, schema-1 manifests, methodology and artifact catalog 1.9.
- Isolate the existing CLI assessment engine into `_run_assessment_engine` without changing its collection stages or tester-controlled action policy.
- Add the in-process, JSON-safe `BackendService` with capabilities, tool readiness, status, integrity, review, appendix readiness, explicit reviewer decision, export and safe derived-report repair operations. Read-only CLI JSON commands use `--backend-action` and `--backend-assessment`; no GUI/HTTP server is shipped.
- Add per-assessment exclusive mutation locks covering CLI assessment execution, Guided Review, Guided Runtime, Client Appendix export and derived-report repair, as well as backend mutations. Contention refuses the action; stale locks require manual process verification before clearance.
- Require assessment integrity and an exact evidence fingerprint before programmatic review changes; re-render reports and refresh manifest after saved reviewer decisions. Explicit confirmation is required for all in-process writes.
- Exclude tester notes, secret values, live tool paths and raw manifests from backend responses; keep compatible older completed assessments read-only/exportable without silent state conversion or unsafe cross-version resume.
- Rewrite README and release notes; add root methodology overview and `docs/backend-service.md`. Normalize versioned Windows validation and retain changelog entries starting at v1.0.0 only.
- v1.9.3 is a Windows field-validation candidate; v1.9.2 remains the accepted baseline until verified on Windows.

## v1.9.2 — Stabilization
- Scope Process Create descendant collection to verified first-party directories rather than every launched process name.
- Preserve direct launch events without promoting external application descendants to target security candidates.
- Correct mobile coverage-status wrapping and tester dashboard action-center wording/completion summary.
- Preserve existing integrity, privacy, and explicit tester-execution safeguards.

## v1.9.1 — UCA-inspired offline HTML presentation and dual-theme reports

- Redesigned the **Client Appendix** as an offline technical overview with approved-footprint metrics, installation/privilege/network/IPC/storage summaries, security-area grouping, and a navigable sanitized evidence library.
- Redesigned the **tester HTML dashboard** around a searchable, filterable two-pane review workspace; long validation detail is shown only for the selected condition, while all no-JavaScript evidence remains present and readable.
- Both HTML deliverables default to a dark theme and offer an accessible light/dark switch with a browser-local preference (gracefully works when local storage is disabled).
- Use self-contained CSS and hash-authorized inline scripts in a restrictive offline Content Security Policy; no remote CSS, fonts, JavaScript or network connections.
- Preserve integrity-gated, copy-only Client Appendix export; complete tester review, sanitized strict report allowlist, no internal evidence or reviewer notes, no artificial vulnerability confirmation.
- Preserve installable/portable assessment collection and the v1.8.6 Windows-validated detection baseline; no automatic PoC or application execution changes.

## v1.9.0 — tester dashboard and integrity-gated Client Appendix

- Added a read-only Tester Action Center, reviewed-condition disposition grouping and compact Guided Runtime coverage chips. Avoid green styling for VALIDATED because review disposition does not independently prove a vulnerability.
- Added separately packaged, SHA-256-manifest-verified Client Appendix export with strict zero-pending, changed-evidence and critical-stage gates; portable offline HTML, README, checksum inventory and minimal sanitized TXT allowlist.
- Preserved an unchanged assessment source during export and tested pending/tampered/incomplete/path-inside-source blockers, portable relative links, checksums and exclusion of internal artifacts/tester notes.
- Separated static managed assembly identities from observed runtime process identities in managed context summaries.
- Raised methodology and artifact catalog metadata to 1.9, preserving 26 vendor-neutral surfaces and existing tester-executed PoC policy.

## v1.8.6 — portable attribution, privacy, and report consistency maintenance

- Normalize the current tester username inside Windows `UrlZonesSM_<username>` named-object identifiers in persisted IPC, handle, and derived reports, while preserving unrelated object names.
- Recover portable application storage roots from a **SHA-256-verified live primary executable**, even when the runtime trace does not include a self `Load Image` event. Continue to require target-process writes; retain privacy-safe paths and keep unrelated host writes out of local-storage reports.
- Restore static published-.NET-host context after a separate Guided Runtime session using the existing managed assembly inventory and verified primary identity. Distinguish static .NET host evidence from a CLR actually observed in Procmon; never infer native-only from absent CLR load events.
- Prevent multi-line credential-redaction patterns from consuming separator lines and emitting spurious `=<REDACTED>` artifacts. Actual named secret assignments remain redacted.
- Clarify the shrinking Guided Tester Review Pending counter as `Pending condition X of N remaining`, while preserving completed decisions and the All-view numbering.
- Correct version validation in `scripts/validate_windows.ps1` and allow expected local `.venv` / `.pytest_cache` created during setup/testing (never shipped in source ZIP).
- Keep attack-surface methodology and artifact catalog at **1.8**, and preserve installer-mode, tester-controlled PoCs, privacy and integrity policies. Windows follow-up acceptance requires only the portable application fixture; previous installable v1.8.5 field validation remains accepted for this focused patch.

## v1.8.5 — portable runtime identity and live observation stabilization

- Fixed portable runtime process discovery by matching the selected primary executable's SHA-256 against the live executable, then correlating only explicitly identified helper processes beneath its verified directory. Source locations remain private; unrelated same-named processes are not promoted.
- Added truthful live observation telemetry: detected process starts, CPU-time changes, I/O operation count changes, connection changes and last target-activity age. Procmon PML remains untouched until capture stops; trace growth is not presented as proof of target activity.
- Expanded portable local-storage discovery to target-written files beneath directories established by target-owned executable Load Image evidence, including logs, backups, temporary session data and SQLite sidecars; no secret values are retained.
- Reconciled Guided Runtime DLL-search ACL observations with the authoritative permissions_review.txt, without introducing duplicate reports.
- Restored portable product/version/publisher metadata from target_analysis.txt after Guided Runtime refresh.
- Added candidate-specific managed-source review commands tied to source category and first-party file/line locations.
- Preserved existing Guided Review decisions, privacy normalization, tester-controlled PoCs, release allowlist, version-gated state and methodology/artifact catalog 1.8.
- New regression tests cover the changed behaviors. Native Windows field validation is required before promotion to a baseline.

## v1.8.4 — first-party review coverage and reporting quality

- Fixed .NET source-review starvation: deterministic first-party and dependency scan budgets with per-category line deduplication and role/scope labeling. Six consolidated informational code-review categories are derived from first-party observations only.
- Added bounded, prioritized static sensitive-string triage and preserved XML/JSON redaction. Prevented dependency PE strings from consuming all report capacity.
- Preserved historical target-scoped Procmon network activity alongside live listener/connection enumeration after Guided Runtime refresh.
- Promoted target-identified sensitive registry key names to manual local-storage review without assuming they are readable to unauthorized principals; excluded Windows BAM/DAM execution history from app storage.
- Reduced DLL search-order review-queue noise while retaining the full underlying missing lookup evidence.
- Corrected Guided Runtime Procmon summary references to discarded temporary host data.
- Added regression tests and offline decompiled-source fixture validation. Version 1.8.4 is a Windows field-validation candidate, not yet the accepted baseline. Methodology and artifact catalog remain 1.8.

## v1.8.3 — portable/.NET static detection-quality enhancements

- Reordered .NET decompilation to prioritize the target's first-party managed assemblies and selected publishing sidecars ahead of framework dependencies. Maintained explicit 50-assembly limit and coverage warnings.
- Extended ILSpy source-review indicators for insecure crypto, TLS trust handling, SQL/data access, dynamic plugin loading, insecure deserialization, command execution, authorization gates, IPC, updater handling and memory/interop boundaries. Pattern hits remain manual code-review entry points.
- Added confidential XML and JSON credential-property triage in secrets review, with value-free reports and identifier/boolean exclusions to reduce noise.
- Added configuration security-setting indicators for XML, JSON and conventional key/value files, including disabled TLS checks, password logging, legacy ciphers/hashes, unsigned updates, plugin trust controls and HTTP update channels. Presence alone is not a vulnerability.
- Preserved static managed technology/candidate counts after Guided Runtime refresh; corrected transient `%USERPROFILE%` expansion for ACL probing and prevented unprobed ACLs from being represented as confirmed missing directories.
- Added targeted synthetic regression tests and kept version-bound assessment integrity compatibility. Windows field validation required before promoting v1.8.3 as a baseline; methodology/artifact catalog remain 1.8.

## v1.8.2 — portable targets and vendor-neutral thick-client attack-surface methodology

- Added first-class portable application assessments for standalone EXEs and application directories with explicit primary-executable selection. Portable targets are not treated as installers; installer/MSI modules become NOT APPLICABLE while shared PE/.NET/Electron/configuration/secrets/runtime analysis remains available.
- Generalized full-mode workflow to Baseline Snapshot → tester-controlled target activity → Post-Activity Snapshot → System Change Analysis. Installable targets pause for installation; portable targets pause for manual launch/exercise. WCA never launches or exploits the target automatically.
- Added privacy-safe `target_analysis.txt` and target identity/state handling for portable sources; directory assessments are pinned to the selected primary executable so legitimate adjacent runtime data does not invalidate the target.
- Replaced the fixed known-vulnerability framing with the extensible **Windows Thick Client Attack Surface Coverage** methodology and renamed outputs to `attack_surface_correlations.txt` / `attack_surface_test_plan.txt`. Current guidance spans 26 named surfaces while explicitly remaining extensible.
- Added bounded PE printable ASCII/UTF-16 sensitive-string triage to Secrets Review. Reports retain only indicator metadata, redacted values and locations/offsets for tester validation.
- Added/strengthened guided workflows for heap and stack corruption, reparse points, IFEO/SilentProcessExit, COM activation, process injection, network trust, cryptography, authentication/authorization and local data/input handling. PoC execution remains tester-controlled.
- Tightened local-storage registry attribution so generic Windows registry writes are not automatically promoted without target/product path identity.
- Advanced methodology and artifact catalog to **1.8**. Added portable-target regression coverage; v1.8.1 remains the Windows-validated baseline until v1.8.2 completes installable + portable Windows field validation.

## v1.8.1 — v1.8 field corrections and borderless terminal banner

- Corrected Local Storage Review target attribution so unrelated InstalledApplications churn cannot seed product identity. MSI/package identity, verified target roots/services/runtime targets and correlated uninstall entries now drive target identity; path matching uses exact segment tokens and publisher-wide names are not used for storage scoping.
- Added Application / Technology Profile identity fallback to persisted MSI Property data and the correlated target installed-app record. The profile now distinguishes target installed-app records from unrelated temporal installed-app changes.
- Corrected unquoted-service intermediate-path ACL semantics: `AppendData`/directory-create capability alone no longer proves the ability to create `C:\Program.exe` or another candidate executable. Candidate parents require create-file/write-equivalent rights before HIGH-confidence promotion.
- Replaced the boxed Rich startup panel with a terminal-width-aware, borderless WCA wordmark and centered product/author/version metadata.
- Renamed newly-created framework temporary prefixes to `wca-*`; legacy `winclientassess-snapshot-*` remains recognized for backwards-compatible filtering.
- Added regression coverage for host-churn exclusion, exact storage identity matching, MSI profile fallback, AppendData-vs-CreateFiles service-path semantics, and the wide borderless banner. Methodology/artifact catalog remain 1.7.

## v1.8.0 — Windows-specific analysis depth and application profiling

- Added cross-phase `application_profile.txt` for product/technology/install/runtime scoping.
- Added target-associated `local_storage_review.txt` for AppData/LocalAppData/ProgramData and registry evidence without retaining secret values; SQLite inspection is schema-only.
- Strengthened service, scheduled-task, driver, persistence and privilege-boundary correlation with path, ACL, signature and actual unquoted-service candidate context.
- Added staged updater package Authenticode context and clearer endpoint evidence semantics.
- Guided Runtime refreshes local-storage/profile outputs; reporting distinguishes collected/no-observation from skipped/unavailable evidence.
- Methodology/artifact catalog advanced to 1.7; tester-controlled PoC and clean-package policies preserved.

## v1.7.5 — usability, PoC guidance and artifact/package hygiene

- Added the block-letter **WCA** startup banner with the display order Windows Client Assessment → Author: Matthew B. → Version.
- Expanded candidate-specific PoC Resource guidance. C helpers now identify whether compilation is required, infer target x86/x64 architecture from existing PE evidence when possible, provide matching Visual Studio/MinGW-w64 recipes, expected output names, SHA-256 verification and PE-machine verification. PowerShell helpers now show direct candidate-specific invocation guidance. WCA never compiles or executes proof resources automatically.
- Added `scripts/package_release.py`, an explicit allowlist-based source-release builder/auditor. Current release ZIPs no longer carry historical validation scripts/docs, old replay helpers, `*.egg-info`, build/cache/venv artifacts, prior release files or the empty examples directory. Canonical validation files are now `scripts/validate_windows.ps1` and `docs/windows-validation.md`.
- Renamed retained regression-test files from historical version labels to feature-oriented names. Tests remain because they protect current functionality; obsolete replay-helper-only coverage was removed with the unsupported helper.
- Performed a generated-assessment artifact audit and bumped artifact catalog to **1.6**. Retired redundant `new_services.txt` and `new_scheduled_tasks.txt`; their quick-index content already exists in `services_review.txt` and `scheduled_tasks_review.txt`. Test-case prerequisites, contextual guidance, module-artifact mappings and stale-artifact cleanup were updated.
- Consolidated current source documentation into canonical non-versioned files; historical release progression remains in this CHANGELOG. Methodology remains **1.6**.

## v1.7.4 — WCA branding and project identity

- Renamed the displayed project/tool identity to **WCA**, while retaining **Windows Client Assessment** as the full descriptive name.
- Renamed the primary launcher from `winclientassess.py` to `wca.py`; package metadata now installs the `wca` console command.
- Added project attribution **Author: Matthew B.** to the CLI banner, `--version`, README, package metadata and release documentation. Author identity is intentionally not injected into generated assessment evidence or future client-facing assessment content.
- Updated current documentation, help text, report/dashboard product references and PoC guidance to use WCA / Windows Client Assessment terminology. Historical versioned release notes remain unchanged for auditability.
- Preserved the internal manifest framework identifier `WinClientAssess` and snapshot provenance token so existing structured assessments remain readable/verifiable without a schema migration. Methodology remains **1.6** and artifact catalog remains **1.5**.
- v1.7.3 Windows field validation passed and is the functional baseline. v1.7.4 contains no assessment-engine/detector/runtime behavior changes. Portable validation: **262/262 PASS**, compile PASS, offline wheel build PASS, and read-only v1.7.3 assessment integrity replay PASS.

## v1.7.3 — Target scoping and PoC Resource path correction

- Windows v1.7.2 field testing confirmed the Enter-only Guided Runtime workflow, large-trace progress reporting, streaming target sanitization and integrity refresh. It also exposed unrelated host software being promoted into target scope from the global filesystem differential and ambiguous relative PoC Resource paths.
- Runtime Target Discovery now requires stronger association for filesystem-added executables when static inventory is available: exact extracted/static filename+size match, a specific service/task launch root, or a path beneath a target root established by matched payload/service/task evidence. System-wide snapshot additions alone are no longer enough.
- Installed updater discovery uses the same association rules, preventing unrelated host update components from becoming updater/security candidates solely because they appeared between snapshots.
- Attack Surface Correlations no longer re-promotes every filesystem-added executable into the target-name set; it consumes the already scoped runtime target set.
- PoC Resource fields now resolve against the WinClientAssess source/tool tree. Live Guided Review shows the actual full path; persisted TXT/HTML guidance uses a privacy-safe tool-directory path and explicitly states that the resource is not located in the assessment output folder.
- Added negative regressions for unrelated Edge/OneDrive-style host updates plus full-path PoC resource rendering.
- Bumped framework version to **1.7.3**; methodology remains **1.6** and artifact catalog remains **1.5**. Portable regression suite: **259/259 PASS** before final packaging. Native Windows 11 v1.7.3 field validation remains pending.

## v1.7.2 — Guided Runtime stabilization and tester-controlled evidence guidance

- Removed Guided Runtime workflow-state hotkeys and the post-capture accept/revise questionnaire. The live Rich panel now shows a passive suggested-activity list; the tester exercises applicable application/service behavior and presses **Enter once** when finished. Runtime coverage is derived from collected telemetry rather than keyboard attestations.
- Added explicit post-capture stage feedback for Procmon stop, PML export, privacy sanitization/target filtering, runtime analysis, report/dashboard refresh and integrity verification. Quiet long-running conversion work emits elapsed-time heartbeat messages rather than an artificial percentage.
- Reworked Guided Runtime Procmon retention so the temporary raw CSV is streamed through **target/descendant filtering and privacy sanitization in one pass**. The prior large sanitized full-host intermediate is no longer written for Guided Runtime. Raw PML/full-host CSV remains temporary and is discarded.
- Added dynamic child/helper process-name tracking during streaming Process Create/Start handling so relevant descendant activity remains in target scope.
- Replaced the fixed five-minute large-trace export behavior with an adaptive, bounded PML-to-CSV timeout and preserved capture duration, final PML size, processing duration, failure stage and failure reason when conversion/sanitization cannot complete. Process/network/IPC collection can continue while Procmon is clearly labeled unavailable rather than reporting a false zero-duration clean session.
- Consolidated Guided Runtime derived-report/dashboard finalization to one complete pass per observation.
- Redesigned `evidence_guide.txt` to one tester-controlled manual-validation structure: **Observed Evidence → Why Validate It → Prerequisites → Starting Checks → Manual Validation Procedure → PoC Resource → Tester Execution → Expected Evidence → Interpretation → When Not to Report**. WinClientAssess may bundle/generate PoC resources but never runs them; the tester reviews and executes them manually.
- Removed routine cleanup/restore sections from current evidence guidance because the assessment workflow uses disposable snapshot-backed Windows VMs. Candidate-specific stop/safety conditions remain where materially necessary. No Client/Controlled, CTF/Lab or Guidance-Only execution modes were added.
- Updated the tester HTML candidate presentation to mirror the manual-validation model while preserving persisted review decisions/notes, privacy controls, stable WCR IDs, offline operation and later client-appendix separation.
- Bumped framework version to **1.7.2** and methodology version to **1.6**; artifact catalog remains 1.5 because no new artifact class is introduced. Portable regression suite: **254/254 PASS** before final packaging. Windows 11 field testing completed; the run confirmed Guided Runtime stabilization and exposed the target-scope/PoC-path issues corrected in v1.7.3.

## v1.7.1 — Integrated Guided Runtime refinement

- Replaced the silent Procmon wait with a live Rich runtime panel showing elapsed time, trace growth/idle state, current correlated target processes, processes seen during the session, and current target network connections. Workflow keys 1-6 cycle NOT EXERCISED / EXERCISED / NOT APPLICABLE while capture is active.
- Removed the six-question post-capture questionnaire. One compact coverage confirmation is shown; revision is available only when needed.
- Added visible stop/export/sanitization/correlation/report/dashboard/integrity progress and a meaningful completion summary with duration, target-event counts, process counts, workflow coverage and new review candidates.
- Integrated Guided Runtime target-scoped Procmon evidence back through Procmon Analysis, DLL Search Review, Runtime Process Review, Advanced .NET / Native Runtime Review, Network/IPC review and known-answer correlations. Effective runtime module status and test-case applicability are refreshed.
- The full Guided Runtime host CSV is no longer retained. Raw PML/full host CSV stays temporary; `working/guided_runtime_target_events.csv` is the retained sanitized target-scoped runtime evidence.
- Normalized only the current interactive tester SID as `CURRENT_USER_SID` while preserving security-relevant SYSTEM/service/domain SIDs.
- Split named-pipe/device writes from filesystem writes so `\Device\NamedPipe\...` events contribute to IPC activity rather than file-write counts.
- Guided Runtime now records start/stop/duration and distinguishes currently active processes from target/descendant process names observed during the session.
- Bumped methodology/artifact catalog versions to 1.5. Added v1.7.1 release notes and Windows validation guidance.
- Portable regression suite: **252/252 PASS** before packaging. Replay of the uploaded v1.7.0 target-scoped Guided Runtime evidence through the v1.7.1 Procmon classifier produced 20,250 target events, 14 filesystem writes, 2 IPC/device writes, 63 process events, 31 missing-DLL lookups and 11 observed process names. Native Windows 11 v1.7.1 field validation remains pending.

## v1.7.0 — Guided Windows Runtime Observation

- Added a separate **Guided Runtime Observation** main-menu/CLI operation for completed, integrity-PASS, full-mode v1.7.0 assessments. It is version-bound and never silently migrates older assessment state.
- Added a tester-operated runtime checklist for launch/relaunch, login/session, network functionality, service/helper or elevated behavior, file/config changes and an authorized update check. WinClientAssess does not perform those actions automatically.
- Reused the existing target identity, saved `--exclude-path` rules and `--target-only` scope, Procmon sanitizer/analyzer, psutil process correlation, network surface and IPC/named-pipe collectors to summarize process trees, service/helper context, loaded images, selected file/registry writes, network events/listeners, pipes and updater activity. Runtime surfaces explicitly report **OBSERVED**, **NOT OBSERVED** or **COLLECTION UNAVAILABLE**.
- Added `reports/guided_runtime_observation.txt` plus distinct sanitized working evidence/session state. Sanitized CSV evidence is staged outside the assessment until the tester completes the checklist, then committed with per-file atomic replacement; raw Procmon PML/CSV remains temporary. The baseline full-assessment runtime capture is not overwritten.
- Guided Runtime now regenerates applicable TXT/HTML/review outputs and the integrity manifest after a legitimate observation. Existing review IDs/notes/dispositions are preserved when evidence is unchanged; repeated known listener/pipe surfaces are not silently duplicated.
- Added a dedicated offline-dashboard Guided Runtime section with latest surface states and a local evidence link.
- Folded in the final v1.6.5 field correction: live guidance resolves bundled `scripts/poc/*.ps1` helpers directly from the running source tree; portable guidance rejects blank, missing, directory or wrong-script selections and reprompts instead of producing a raw PowerShell invocation error.
- Bumped methodology and artifact catalog versions to 1.4. Added v1.7.0 release notes, methodology/usage/output documentation and Windows validation script/checklist.
- Portable regression suite: **245/245 PASS** before packaging. v1.6.5 is the Windows-field-validated baseline; native Windows 11 Guided Runtime validation for v1.7.0 is still required.

## v1.6.5 — Windows validation-command reliability

- Guided Review live checks now use the exact executable path and filename variant returned by Tool Detection for integrated external tools. The named-pipe Handle check no longer assumes `handle64.exe` when `handle.exe` (or another configured supported variant) was actually detected.
- Portable/offline validation guidance remains privacy-safe: instead of persisting tester-specific tool paths it resolves the supported executable variants with `Get-Command` at execution time and emits a clear warning if the tool is unavailable.
- Hardened original-installer Authenticode/hash guidance: accidental surrounding quotes are stripped; directories, missing files and non-MSI/EXE paths are rejected; the tester is prompted again until an existing MSI/EXE file is supplied.
- Clarified clipboard success messaging: each executable PowerShell command is preserved as one line; multiple commands are intentionally separated by line breaks and can trigger Windows Terminal's normal multi-line paste warning.
- Added focused v1.6.5 regressions for detected-tool variant selection, portable tool discovery, guarded installer selection, command-line preservation and clipboard messaging. Portable regression suite: **239/239 PASS** before packaging; Windows-native v1.6.5 validation remains pending.

## v1.6.4 — v1.6.2 Windows field-run corrections

- Gate `TC-AR-001` on actual managed-runtime evidence, adapt its steps when decompiled source is unavailable, and filter Guided Review links to applicable generated cases.
- Add explicit `:multi` optional notes ending with `.`, with cancellation/clearing and preserved HTML line breaks.
- Segregate WindowsApps snapshot differences as **UNATTRIBUTED** in retained TXT inventories; preserve complete primary snapshot evidence and correlate before alleging installer causation.
- Accept uppercase/mixed-case `FULL` or `STATIC` in GUI-backed console and CLI selection.
- Number the five validation-guide sections consistently in Rich, plain text and generated TXT. Keep v1.6.3 clipboard commands and all v1.6.2 detectors and review/integrity safety.
- Added dedicated regression fixtures, original v1.6.2 assessment-copy replay and new Windows 11 field checklist. Portable 234/234 suite PASS; native Windows v1.6.4 validation pending.

## v1.6.3 — CWD-independent validation checks and opt-in clipboard copy (Windows field validation pending)

- Replaced working-directory-dependent `./reports`, `./working`, and `./scripts/poc` commands emitted by candidate-specific guidance with live absolute artifact paths or standalone file-selection prompts in portable reports. Resolved live paths are never written into the persistent HTML/TXT evidence guides.
- Added **C = Copy checks** in Guided Tester Review and its Validation Guide. Uses the native Windows Unicode clipboard to preserve complete unwrapped PowerShell command lines; investigation prose is exported as comments. No commands are executed by the copy action.
- Added positive/negative path resolution, private-path/symlink protection, multiline clipboard, review-state stability, and portable-dashboard regression tests. Existing known-answer detectors/PoCs and trusted assessment state are unchanged.
- Added a native Windows field checklist and read-only validation script for the new behavior. Windows 11 execution, native clipboard behavior, and app-specific validation remain to be field-tested.

# Changelog

## 1.6.2 — Target-scoped known-answer correlations and guarded PoC resources

- Developed against the actual v1.6.1 source ZIP. Added full-mode-only conservative correlations for target process missing EXE lookups + relevant ACL, target-associated post-install reparse changes, target-specific IFEO registry writes and per-user COM registration writes. Findings are informational indicators only; existing DLL/service/network/pipe/PE/signature detectors and remaining 13-category guided plans stay intact.
- Captures reparse-point metadata in new Windows filesystem snapshots; older 1.6.1 snapshots explicitly yield COLLECTION UNAVAILABLE rather than a false clean assessment. The existing built-in Procmon stage is post-install only; no installer-time tracing or automatic exploit confirmation is implied.
- Extends assessment-specific Starting Checks and keeps independent executable paths/registry keys as distinct stable WCR candidates. New coverage distinguishes AUTOMATIC INDICATOR / NOT OBSERVED / COLLECTION UNAVAILABLE in the authoritative TXT category plan and associated offline dashboard links.
- Packages non-shell marker DLL/EXE sources with an execution-token integrity RID, read-only pipe/COM/reparse probes and proof inspection. Exploit triggers, target replacement, service restarts and registry modifications remain human controlled. MSVC/MinGW compiler execution and successful Windows PoC behavior **have not been verified** in this non-Windows build.
- Preserves combined Assessment Status and integrity checking, conservative derived-only regeneration, optional reviewer notes without undocumented warnings, offline read-only HTML, privacy and the no-duplicate-report policy. `attack_surface_correlations.txt` is a source-backed evidence interpretation rather than a safe-to-reinvent derived summary; corruption must not trigger unsafe regeneration.
- Corrected evidence line preservation so two identical executable names at different paths keep independent stable review IDs and field-specific Starting Checks. Scoped reparse correlation to verified installed target families to exclude unrelated host junctions. Updated artifact/catalog docs, current full-mode known-answer test plan, Windows field checklist and regression fixtures. Portable regression and read-only v1.6.1 evidence replay outcomes are recorded in `docs/release-validation.md`. **Native Windows 11 field validation is pending.**


## 1.6.1 — Assessment-specific checks, controlled PoC guidance and clarity fixes

- Generates assessment-specific, PowerShell-safe Starting Checks from sanitized persisted evidence. A confirmed missing DLL search directory, pipe name, listener port and privileged service name now appear directly in the command. Broad-write ACL checks use only relevant matched paths; unrelated permissions are not incorrectly attributed to a service. Unresolved paths use discovery commands rather than fictional placeholders.
- Adds a fifth **Controlled PoC / Evidence** panel to Guided Tester Review and its TXT/HTML counterparts, including prerequisites, controlled test approach, evidence criteria, context-sensitive limits and cleanup. Includes benign source helpers for a marker DLL and EXE plus a non-invasive named-pipe connection probe under `scripts/poc/`. These are conditional demonstrations, not generic one-click exploits or automatic proof of privilege escalation.
- Generates `reports/attack_surface_test_plan.txt` for all **13** training fixture documented categories. Distinguishes linked automated observations from **GUIDED ONLY** manual test requirements, and retains that distinction in the dashboard. Complete automatic detection of all 13 vulnerabilities is still an open Windows-depth milestone; a completed assessment or a clicked VALIDATED decision does not prove those bugs exist.
- Removes the **Undocumented validated** dashboard metric, documentation-gap labels, text-summary counts and repeated CLI reminders. Notes remain optional in all dispositions and may be kept in the separate client penetration-test report. Existing saved notes, decisions, WCR candidate IDs and integrity-safe writes remain unchanged.
- Updater Security Correlation now distinguishes **NOT APPLICABLE** (full installed-state differential was collected and identified zero updater candidates) from **SKIPPED** (required installed-state evidence was not available). The module-health dashboard and coverage TXT present these states distinctly. Not applicable never implies an updater was security-tested.
- Retains the combined Assessment Status / integrity verification / conditional safe regeneration workflow introduced in v1.6.0. Adds targeted regressions for contextual commands, missing/ambiguous evidence, 13-category coverage plan, generated PoC panels, optional notes and updater applicability. **208 portable regression tests passed** in the edited working tree; native Windows acceptance remains pending.

## 1.6.0 — Offline tester dashboard and consolidated assessment status

- Upgraded the existing `reports/assessment_report.html` into the roadmap v1.6 tester dashboard. It now presents review progress/disposition metrics, per-candidate evidence relationships, tester notes, validation status/guidance, module health, critical versus optional coverage gaps, application/package technology context, and a browsable phase-grouped evidence index. Distinct candidate surfaces remain separately expandable rather than being collapsed into an aggregate finding.
- Dashboard content is generated only from persisted backend assessment/review state. The HTML is deliberately read-only: no JavaScript, forms, browser-local decisions, external fonts/scripts/styles, or network requests. Existing escaping, relative links, privacy filtering, responsive layout and printable output remain enforced.
- Consolidated the interactive main menu to `Start New Assessment`, `Assessment Status`, `Guided Tester Review`, and `Exit`. Assessment Status now automatically performs integrity verification. `Regenerate Derived Reports` appears only as a contextual action when the verifier proves that only approved derived reports are damaged and supporting state/evidence/payloads remain intact. Safe checkpoint Resume remains contextual when applicable.
- Preserved direct `--status`, `--resume`, `--verify-assessment`, `--regenerate-reports`, and `--review` CLI workflows. `--status` now reports lifecycle/recovery and integrity together. An unfinished structured assessment without a finalized manifest is labeled NOT FINALIZED rather than being presented as safely repairable.
- Added v1.6 dashboard/status regressions covering saved-review refresh, HTML escaping/privacy, static optional-gap rendering, candidate/evidence traceability and contextual repair/recovery actions. **203 automated tests pass** in the packaged portable suite; `compileall`, help/version smoke checks and a report-regeneration replay against the supplied v1.5.4 assessment also pass. Existing lifecycle, integrity, privacy, Guided Review, MSI/PE and runtime regressions remain required.
- The training fixture known-answer coverage matrix remains an explicit future analytic-coverage target. v1.6 improves visibility and validation guidance but does not claim that the detector/playbook gaps documented in `docs/attack-surface-coverage.md` are closed.

## 1.5.4 — Guided Review layout polish and coverage acceptance baseline

- Reworked the active Guided Tester Review card so the observed condition/finding name is a prominent heading **inside** the bordered panel rather than embedded in the border title. The border now carries only the condition position (for example, `Condition 3/11`).
- Split the card into visually distinct metadata, **VALIDATION SUMMARY**, **STARTING CHECK**, and **TESTER NOTES** sections. Renamed `Supporting report` to `Supporting File` and `Read-only starting check` to `Starting Check`, added spacing before the action menu, and retained a dedicated documentation-gap section for undocumented VALIDATED decisions.
- Capped Rich review/validation panels at a readable width instead of stretching across very wide terminals. Long descriptions and PowerShell commands continue to wrap safely; the full four-part validation guide uses the same width. Plain-text/non-Rich output mirrors the revised labels and hierarchy.
- Preserved all v1.5.3 review semantics: notes remain optional for every disposition, blank-note VALIDATED decisions save and advance but remain explicitly undocumented, the Evidence file/ID prompt stays removed, duplicate observations remain grouped, prior candidate IDs/references are preserved, and each write still requires and refreshes a valid assessment integrity manifest.
- Added `docs/attack-surface-coverage.md` as the explicit acceptance baseline for the intentionally vulnerable training fixture fixture. It records the known categories that still require detector/playbook work and prevents successful assessment completion from being interpreted as complete vulnerability coverage. This release does not falsely claim those remaining categories are implemented.
- Added v1.5.4 UI regressions and Windows acceptance guidance; all existing lifecycle, integrity, privacy, MSI/PE/runtime and reviewer regressions remain in the release suite.

## 1.5.3 — Optional tester notes and visible documentation gaps

- Removed both programmatic and interactive validation gates that prevented saving a `VALIDATED` disposition with blank tester notes. All four dispositions now accept optional notes and retain automatic advancement, including pending and all-conditions views. This addresses the repeated same-condition loop seen in the v1.5.2 Windows run.
- A blank-note `VALIDATED` selection is explicitly labeled **undocumented** in the generated `tester_review.txt`, `evidence_guide.txt` and `findings_summary.txt`. The reviewer displays a nonblocking reminder and does **not** assert that clicking Validate proves actual exploitability. Testers should add verification details before reporting a confirmed issue to a client.
- The notes prompt now states that it is optional; pressing Enter preserves an earlier note (or leaves it empty) and `:clear` deliberately removes a prior note. The removed Evidence file/ID prompt stays removed; old references remain intact internally. Every legitimate save still requires a PASS integrity manifest and atomically refreshes authoritative review state and derived reports.
- Added automated checks for blank notes across all dispositions, next-item advancement, saved-state persistence, documentation-gap labels, legacy references, tamper refusal, and complete fresh-ZIP regression validation. Existing completed v1.5.x assessments can be reviewed without rerunning collection; no detector or lifecycle schema changes.

## 1.5.2 — Readable validation guide and simplified review decisions

- Reorganized **View validation guide (8)** into four separate, scannable sections: what was observed, how to validate, Windows checks, and how to interpret results. The terminal view uses clearly labeled panels, color cues, syntax-highlighted starting commands and a short excerpt of source evidence, with the full observation still available in its supporting TXT report. Press Enter to return to the same candidate without changing its disposition.
- Reformatted the generated `reports/evidence_guide.txt` to the same four-section layout, wrapped procedure/outcome prose, numbered Windows checks and shortened long observed events. Existing test cases and complete module reports remain authoritative for detailed evidence.
- Removed the **Evidence file/ID** input and display from the interactive review and generated `tester_review.txt`. Tester notes remain the single editable explanatory field. Existing legacy `evidence_reference` metadata remains preserved in review JSON during edits, and report integrity is refreshed only after an authorized decision.
- Added targeted plain-text/Rich UI, persistence and backwards-compatibility regressions. This patch leaves existing collectors and v1.6.0's planned HTML dashboard scope unchanged.


## 1.5.1 — Guided Tester Review navigation and UX fix

- Corrected the field-tested reviewer navigation defect: a saved decision no longer leaves the tester on the same candidate in **All** view. Pending view advances after the reviewed condition leaves the pending queue. Enter/5 skips forward, 6 goes back, 7 displays a numbered index and supports jumping, 8 expands the validation playbook, 9 changes filters and 0 exits. Common text aliases and the earlier `v/n/i/p` dispositions remain accepted.
- Replaced the ambiguous single-line interactive prompt with a Rich review table and clearly labeled per-candidate panels, progress and numbered actions. New onboarding starts with a simple Pending/All/Status view; severity/module filters are available on demand.
- Added concrete, read-only Windows validation commands appropriate to PE hardening, Procmon/child-process review, network endpoints, named pipes, DLL searches, ACLs, services and other reviewed categories. Added these starting checks and observed-source record references to the derived `evidence_guide.txt`; tester notes still require independently verified impact for VALIDATED decisions.
- Consolidated exact duplicate runtime POI events in **new** assessment reviewer inventories, recording their original source labels and occurrence counts. The CLI groups matching legacy v1.5.0 records without discarding any original IDs or differing saved decisions; a single explicitly chosen disposition applies atomically to all identical pending records and then refreshes the integrity manifest.
- Verified the new CLI against the supplied real 13-candidate training fixture v1.5.0 assessment archive: its three identical first-party child-process events display as one review condition while all original IDs and the previously validated PE decision remain intact. No automatic migration or cross-version full-mode resume is performed.
- Added focused GUI/CLI navigation, duplicate-event, legacy-state preservation, tamper refusal and Windows-acceptance regressions. This patch does not advance or replace the planned v1.6.0 HTML tester dashboard.

## 1.5.0 — Persistent guided review, validation playbooks, privacy follow-up

- Added stable, evidence-scoped `WCR-` candidate IDs and an authoritative atomic `working/tester_review_state.json`. Distinct listener, pipe, DLL-search, privilege-boundary and advanced-runtime POIs receive separate review records even when an originating finding only contains an aggregate count. Existing `ARP-` labels remain in TXT/HTML for backward compatibility and cross-reference `WCR-` candidates.
- Added `--review ASSESSMENT_DIR` and the Guided Tester Review main-menu item. Filter by disposition, severity or module; navigate next/previous; save notes, evidence reference and PENDING/VALIDATED/NOT APPLICABLE/INFORMATIONAL decision. A validated decision requires documented impact. Review progress survives restart. Unchanged evidence preserves decisions; changed evidence is flagged and returns to PENDING.
- Added derived `reports/tester_review.txt` and `reports/evidence_guide.txt` including component-linked evidence, related test cases, practical Windows validation, expected secure behavior, potential weaknesses and conditions not to report. Enhanced the existing mode-aware `test_cases.txt` format without introducing redundant report JSON/CSV.
- Findings summary now distinguishes automated points from tester-validated candidates and reports review progress/disposition totals. HTML remains the existing v1.4.0 navigation report; an interactive review dashboard is reserved for v1.6.0.
- Integrity verification protects review-state JSON and the two new generated reports. Reviewer saves require a verified assessment; legitimate review changes atomically refresh the derived reports and SHA-256 manifest. Report-only regeneration preserves verified reviewer decisions but refuses corrupt supporting evidence.
- Extended current-user/workstation privacy normalization to identity-bearing registry/task labels, URL-encoded profile paths, host FQDN prefix and retained Procmon CSV/snapshot strings. Recognized security-sensitive service run-as accounts are preserved. The user-owned original imported Procmon CSV is never modified.
- Added synthetic stable-identity, evidence-change, integrity/refusal, live-review CLI, privacy and existing training fixture-artifact replay tests, plus Windows field-validation documentation/script. Portable tests do not replace the Windows-native MSI/full-mode acceptance test.


## 1.4.0 — Integrity, safe regeneration, and privacy

- Added a versioned SHA-256/size assessment manifest for reports, supporting evidence and retained extracted/decompiled payloads, plus deterministic payload tree hashes and a readable `artifact_manifest.txt`.
- Added a read-only integrity verifier with PASS/WARN/ATTN/FAIL categories, mode-aware inventory checks, orphaned temporary-write detection and exit code 9 for integrity failure. Optional skipped modules are not fabricated as missing evidence.
- Added conservative derived-report regeneration (`module_status.txt`, `coverage_summary.txt`, `findings.txt`, `findings_summary.txt`, `assessment_report.html`, and the human-readable manifest) from a hashed internal rendering recipe. Regeneration refuses source-evidence/state corruption and refreshes the manifest only after an approved regeneration. Derived TXT/HTML and manifest updates use atomic writes.
- Pre/post snapshot checkpoints are separately pinned by SHA-256 and size. Resuming missing/modified checkpoints halts; legacy v1.3.0 assessments remain readable but cannot be silently resumed using unverified checkpoints.
- Recovery clears the framework-owned extraction directory before re-extraction to prevent duplicate static analysis across 7-Zip and lessmsi runs. No external folders or other evidence are cleared.
- Process Create/Start environment blocks are excluded from persisted sanitized Procmon CSV and interpreted runtime reports. Known identity assignments are redacted; persisted snapshot environment-variable values are limited to a short, privacy-filtered path-related allowlist. Secret indicator names/counts are preserved.
- Added read-only Windows acceptance script and focused integrity/privacy/extraction regression tests. Windows field validation is pending.


## 1.3.0 — Assessment lifecycle and state foundation

- Added structured `reports/` and `working/` assessment directories with backward-compatible flat-layout reads.
- Added atomic, versioned `working/assessment_state.json` with non-personal assessment identity, installer filename/SHA-256, option flags, module state, checkpoints, tool availability, and timestamps.
- Added interactive Start New Assessment / Assessment Status & Recovery menu plus `--status` and `--resume`.
- Added checkpointing across static, pre-install, installation confirmation, post-install, installed-state, runtime, surface, reporting, and completion stages.
- Added safe recovery rules that refuse incomplete pre-install baselines and require installer hash verification before resume.
- Added resumable analysis from trusted pre/post snapshots with `%USERPROFILE%` expansion for privacy-normalized persisted snapshot paths.
- Preserved legacy flat assessments without silent overwrite/conversion.
- Moved snapshots, Procmon raw/sanitized evidence, extracted payloads, and decompiled source into `working/`; interpreted tester outputs remain in `reports/`.
- Reconciled DLL-search user-writable classification so a broad-write ACE also marks the searched directory as likely user-writable for triage.

## 1.2.3-p5 — DLL-search ACL correlation and compact Procmon working evidence

- Refreshes the **existing** `permissions_review.txt` after a successful target-filtered Procmon + DLL Search Review. Newly discovered application-specific DLL-search directories, including paths outside the installation root, receive ACL triage. Existing service/task/differential ACL paths are de-duplicated; DLL record IDs and observed process names are linked to the relevant ACL entry. Unrelated Windows/system and unconfirmed missing directories are excluded. Broad-write entries are **review candidates**, not confirmed vulnerabilities.
- Keeps the existing module count and finding IDs stable; an already-emitted Permissions Review finding is not added a second time. Failure to finish requested runtime ACL correlation is reflected in module coverage instead of silently preserving a false PASS.
- During the existing Procmon analysis pass, writes **only target-associated and discovered child-process events** into `working/procmon_target_events.csv` using a streaming, sanitizing, atomic write. Retains the existing complete sanitized CSV (`procmon_runtime_capture.csv` for automated capture or `procmon_runtime_sanitized.csv` for imports) unchanged by filtering. If no targets are known, no duplicate working CSV is created.
- Adds the distinct internal operational CSV to the artifact cleanup inventory and deliberately excludes it from HTML/client report links. Preserves user-authored files in the working directory, and does not restore duplicate JSON/CSV copies of interpreted findings.
- Includes portable regression coverage, read-only Windows replay helper, field-test guidance and documentation.

**Validation:** Portable regression suite and offline replay of the user's real p4 training fixture sanitized Procmon CSV completed. Replay processed 1,127,373 events and retained 20,593 target events in a 3,468,079-byte working CSV; reconstructed training fixture DLL/ACL cross-correlation included `C:\ProgramData\LabClient` (ACL fixture derived from the earlier report, **not** a new live Windows ACL query). Windows-native p5 full-mode field retest remains **PENDING**.

## 1.2.3-p4 — PE header discovery and verified mitigation-analysis coverage (training fixture field-test patch)

- Discovers PE files by DOS `MZ` header, `e_lfanew` and `PE\0\0` NT signature, not only `.exe`/`.dll` filename extensions. This includes the twelve extensionless training fixture MSI payload files observed in the p3 Windows field test. Both shared-inventory and root-directory paths use the same header check; duplicate paths are analyzed only once.
- Separately reports **PE files discovered**, **successfully analyzed**, and **parse failures** in `binary_security_review.txt` and the module status. Zero detected PEs is reported explicitly rather than described as zero files analyzed without context.
- Missing `pefile` or an unreadable/malformed discovered PE is a coverage-affecting `ERROR`, leading to `INCOMPLETE` rather than a false PASS. Mitigation-only gaps remain `WARN`, not automatic confirmed vulnerabilities.
- Added synthetic header, malformed file, inventory-deduplication, parser failure and coverage-grade regressions plus a read-only Windows smoke script for the existing training fixture p3 extraction. No vulnerable binaries, MSI or duplicate report formats are distributed.
- Preserved p3's now field-tested MSI extraction/analysis fixes, p2 runtime process correlation, flat output layout, and prior privacy rules. ACL cross-correlation and Procmon volume reduction are deferred.

**Validation:** Portable automated regressions and offline training fixture header replay completed; Windows `pefile` parsing / smoke validation still **PENDING**.

## 1.2.3-p3 — MSI table discovery and field extraction (training fixture field-test patch)

- Queries the read-only Windows Installer `_Tables` and `_Columns` catalogs before reading MSI data. Missing optional `ServiceInstall`, `ServiceControl`, `Environment`, and `Shortcut` tables are reported as **ABSENT**, not failed SQL queries. True errors reading present tables remain coverage-affecting failures.
- Reads indexed MSI COM record fields using explicit column numbers/types and `GetProperty` dispatch rather than relying on PowerShell `Record.FieldCount`, which produced empty CustomAction and Registry rows on the v1.2.3-p2 Windows field test.
- Renders decoded MSI column names and values, highlights the custom-action source/type/target and correlates named custom actions with their InstallExecuteSequence condition/position. Binary stream contents are never copied into the interpreted TXT report.
- Validates non-empty row identifiers and mandatory core/custom-action fields before reporting successful coverage; failed or empty record decoding is **ERROR**, not a false PASS. Generated MSI text is privacy- and secret-filtered.
- Added training fixture-shaped synthetic table regressions, read-only Windows MSI smoke-check script (`scripts/validate_windows_1_2_3_patch3.ps1`), and Windows retest guidance. No third-party MSI, deliberately vulnerable program or duplicate JSON/CSV report is bundled.
- Preserves the v1.2.3-p2 runtime correlation, optional coverage gap handling, ACL scoping, snapshot/report privacy and installer behavior. DLL/ACL cross-correlation and Procmon volume improvements are deferred to a later scoped release.

**Validation:** Portable Python regressions and packaging checks run on Linux. Windows-native COM query execution and end-to-end MSI/full-mode validation remain **PENDING** until the tester reruns the training fixture fixture.

## 1.2.3-p2 — Runtime coverage and target-scoped ACL triage

- Reports `WARN` and optional coverage gaps when selected network/IPC/runtime-process collectors run without identifying a live assessed-application process. Separates zero observed endpoints for a **correlated** process from unobserved target processes; does not claim an absent network or IPC surface based on an empty collection.
- Distinguishes connection collection failures, target Handle failures, and pipe-permission collection failures from findings; retains informative text reports and coverage summary. Generated surface test cases are applicable only when the selected network/IPC evidence was successfully correlated.
- Adds an optional interactive deployed-folder prompt for identified .NET apphosts lacking exact-stem sidecars; the `--application-dir` CLI option remains supported. No arbitrary neighbor-directory enumeration or automatic execution is introduced.
- Restricts automatic filesystem-derived ACL candidate triage to positively associated install locations and newly installed service/task executable roots when available. Service and task candidates stay prioritized. When no reliable root is found, the prior broad review is preserved. The full installation differential and snapshots remain unchanged, with a report note on skipped background ACL candidates.
- Adds focused p2 regression tests and Windows MSI/runtime field-test guidance. Linux automated tests do not establish Windows-native training fixture/MSI compatibility; those field tests remain pending.

## 1.2.3-p1 — internal regression field-test patch

- Reclassified an observed unsigned Authenticode result as a **review warning**, not a failure of the signature collector. A failed/unavailable `Get-AuthenticodeSignature` query is now an `ERROR` and appropriately makes coverage incomplete.
- Added read-only published-.NET-apphost / portable application detection with exact-stem sidecars, bounded directory inventory, and optional `--application-dir` for nonstandard deployments. Adds one authoritative `application_scope.txt` report to the artifact catalog and dashboard.
- Scopes companion managed DLLs and nested deployed assets into the existing static PE, .NET, configuration, secrets, lifecycle, and updater analyses; indicates when an apphost is potentially single-file, an expected managed payload is missing, or ILSpyCmd fails. No executable is run by static discovery and arbitrary neighboring files are not inventoried for unknown EXEs.
- Distinguishes a non-archive application EXE (`SKIPPED` extraction with an explanation) from an actual recognized installer extraction failure (coverage-affecting `WARN`). Existing MSI/7-Zip/lessmsi extraction remains supported.
- Removes framework-created `winclientassess-snapshot-*` TEMP folders from PowerShell snapshot filesystem inventory, in-memory/persisted snapshot state, and derived installation diffs; records excluded records where applicable. Does not suppress unrelated Windows background activity.
- Makes full-mode installation-differential status informative for deployed/portable applications with no install footprint, while flagging empty conventional setup workflows for verification.
- Includes focused regression fixtures and a Windows field retest script. Linux-side tests do **not** replace real elevated Windows MSI/EXE/portable-app validation.

## 1.2.3

### Baseline fixes and privacy safeguards

- Fixed Windows-style executable basename detection for PowerShell process environments regardless of the Python host OS; Windows PowerShell no longer inherits a PowerShell 7 `PSModulePath` when invoked using an absolute Windows path.
- Fixed the full installer-path leak in the HTML report when a `C:\...` installer was analyzed from a non-Windows host. Static installer analysis and module summaries now retain only the installer filename/hash rather than the tester's original installer directory.
- Added conservative, known-identity redaction for current-user profile paths, account names, computer names and explicitly labeled credentials in generated TXT/HTML; sanitized inventory CSV and Windows pre/post snapshots before persisting them while preserving raw in-memory state for *current-run* correlation.
- Collect raw PowerShell snapshots outside assessment output in an automatically cleaned temporary location; store the privacy-filtered snapshot and sanitized differential report in the assessment directory. Interrupted runs can leave sensitive temporary files and require tester cleanup.
- Removed leaked prefixes/suffixes from static secret-value previews; strengthened Procmon CSV redaction for quoted and space-containing secrets, CLI credentials, private-key names and bearer tokens. Imported source CSV files remain unchanged and sensitive.
- Marked raw `procmon_runtime_capture.pml` cleanup-only in the artifact catalog. It remains eligible for stale-file removal, is not linked by HTML, and is not a retained assessment deliverable. The unique sanitized CSV evidence formats remain supported.
- Kept the v1.2.2 CLI, flat assessment-directory layout, Windows-specific evidence modules and no-duplicate interpreted JSON/CSV policy.

### Validation

- Expanded cross-platform regressions for Windows path parsing, HTML/TXT/inventory privacy, snapshot persistence, full secret masking, imported Procmon sanitation and PML catalog handling.
- Added `scripts/validate_windows_1_2_3.ps1` and `docs/windows-validation-v1.2.3.md` to establish clean, hashed Windows 11 static MSI/EXE and elevated full MSI/EXE fixture baselines.
- Linux-side Python/CLI/static smoke checks are not Windows field validation. All four real Windows fixture results remain **PENDING** until executed on a clean Windows 11 assessment VM.

## 1.2.2

### Assessment scoping and noise reduction

- Added repeatable `--exclude-path PATH_OR_GLOB` filtering for path-associated installation-differential, runtime-target, live-process, network, IPC, and updater evidence.
- Added `--target-only` to suppress unrelated host-wide pipe inventory while retaining target-associated pipe, permission, and RPC/ALPC evidence.
- Preserved raw pre/post snapshots and raw/imported Procmon evidence while recording applied filters and removed differential counts in `assessment_filters.txt`.
- Changed live-process correlation to require path evidence when an executable path is readable, preventing unrelated installed versions with the same basename from being treated as targets.
- Added regression coverage for prefix/glob exclusions, differential filtering, updater/runtime filtering, path-aware process matching, and filter reporting.

## 1.2.1

### Correctness and evidence quality

- Analyze an automated Procmon capture directly from its already-sanitized retained CSV instead of creating a duplicate sanitized copy.
- Distinguish target-associated named-pipe handles from endpoint ownership and suppress product POIs for well-known Windows system pipes such as `lsass`.
- Report failed optional evidence collection and unobserved updater workflows as `COMPLETE_WITH_OPTIONAL_GAPS` rather than `COMPLETE`.
- Expanded Procmon guidance to request a full client relaunch and an authorized update check so process and updater activity are more likely to be captured.
- Added regression coverage for sanitized-capture deduplication, system-pipe classification, updater gaps, and coverage grading.

## 1.2.0

### Consolidated reporting

- Added a self-contained offline `assessment_report.html` as the primary assessment navigation layer.
- Embedded the coverage grade, module status, module details, and severity-sorted Automated Review Points.
- Added originating-module provenance and evidence-file references to consolidated findings.
- Linked modules and review points only to artifacts actually generated by the current assessment.
- Added a phase-grouped evidence index with retained-artifact type and size.
- Used relative links and no external scripts, fonts, styles, or network resources so assessment directories remain portable.
- Escaped assessment- and installer-derived content before HTML rendering and persisted only the installer filename in the report header.
- Retained all existing text, CSV, JSON, and sanitized runtime evidence as the authoritative underlying artifacts.

### Validation

- Added regression tests for report creation, severity ordering, HTML escaping, evidence linking, absent-artifact handling, and artifact catalog integration.
- Retained the v1.1.2 privilege-result correction and all v1.1.2 security-analysis and runtime-privacy behavior.

## 1.1.2

### Security analysis

- Added Electron renderer trust-boundary review for Node integration, context isolation, remote access, webviews, loopback HTTP loading, unsafe CSP directives, navigation controls, certificate overrides, and secret-in-URL flows.
- Added dated offline lifecycle review for detected OpenSSL and Electron versions, with explicit SBOM/backport/reachability limitations.
- Split baseline ASLR/DEP gaps from CFG-only hardening observations so affected binaries and impact are visible in consolidated findings.
- Correlated application-declared port configuration with non-standard loopback listeners instead of relying only on a common-port list.

### Runtime evidence privacy

- Sanitizes Procmon CSV fields before analysis and redacts credential-bearing environment variables, query parameters, and bearer authorization values.
- Adds `runtime_secrets_review.txt` and a consolidated review point when sensitive values are observed.
- Automated Procmon capture now uses temporary raw PML/CSV files, retains only sanitized CSV evidence, and discards raw PML by default.

### Correlation quality

- Requires product/updater identity for installation-differential staging artifacts and updater-process ownership for Procmon staging writes, reducing unrelated user-profile and OS activity.
- Adds an explicit coverage-gap review point when Procmon evidence exists but no updater workflow activity was observed.
- Added regression coverage for all v1.1.2 analysis and privacy changes.

## 1.1.1

### Fixed

- Prevented Windows PowerShell from inheriting a PowerShell 7 `PSModulePath`, which could load incompatible modules and break Windows-native collectors.
- Made scheduled-task snapshot serialization tolerate null principals, actions, and triggers.
- Changed empty Authenticode objects into explicit unavailable-query warnings instead of blank signature results.
- Corrected privilege-boundary test-case capability detection to consume the Privilege Boundary Review result rather than the Services Review result.
- Restored managed-candidate name extraction used by Advanced .NET / Native Runtime Review.
- Made advanced runtime privilege correlation PID-aware and stopped treating Procmon `Process Start` rows as additional child launches.

## 1.1.0

### Evidence validity

- Full mode now requires an elevated Windows terminal.
- Windows PowerShell is preferred over PowerShell 7 for Windows-native COM, CIM, ScheduledTasks, registry, and ACL providers.
- Snapshot collection records per-collector failures and invalidates partial service/task/driver baselines.
- MSI analysis records collection errors, validates required core tables, and returns `ERROR` instead of a false `PASS` for empty results.
- Added `coverage_summary.txt` with `COMPLETE`, `COMPLETE_WITH_OPTIONAL_GAPS`, or `INCOMPLETE` grading.

### Analysis quality

- Failed AccessChk named-pipe queries now produce `WARN` and are not treated as successful permission evidence.
- Excluded front-end `bootstrap*.js` libraries from updater discovery.
- Added privileged-service correlation with related broadly writable ProgramData vendor directories.
- Made service/task/driver/privilege/localhost test cases evidence-count aware.
- Fixed duplicate secret identifiers and suppressed consolidated findings for low-confidence-only secret matches.
- Added PEM block classification so certificate bundles are not described as private keys.
- Included CFG in PE mitigation review counts and descriptions.
- Added configuration/script review priorities that deprioritize localization, node_modules, and minified JavaScript.

### Reliability fixes retained

- Preserves v1.0.2 updater path handling, Procmon encoding/process-tree fixes, assessment-name validation, CSV formula neutralization, and 7-Zip warning handling.

## 1.0.2

### Fixed

- Fixed `Updater Security Correlation` failing with `name 'ntpath' is not defined`.
- `_candidate_parent_paths()` now uses the shared Windows path helper `parent_path()` instead of directly calling `ntpath.dirname()`.
- Added a regression test that exercises updater candidate parent-path correlation using Windows-style paths.

### Preserved

- v1.0.1 output-format cleanup, privacy normalization, and distribution cleanup.
- v1.0.0 / v0.6.4 validated assessment engine behavior.

## 1.0.1

### Output cleanup

- Removed duplicate `binary_security_review.csv`; `binary_security_review.txt` is authoritative.
- Removed duplicate `install_changes.json`; `install_changes.txt` is authoritative.
- Removed duplicate `network_surface_review.json`; `network_surface_review.txt` is authoritative.
- Removed duplicate `advanced_runtime_review.json`, `dll_search_review.json`, `ipc_review.json`, `privilege_boundary_review.json`, `runtime_processes.json`, `runtime_targets.json`, `updater_security_review.json`, and `procmon_analysis.json`.
- Preserved structured/raw formats with distinct operational value: `snapshot_pre.json`, `snapshot_post.json`, `file_inventory.csv`, `procmon_runtime_capture.pml`, and `procmon_runtime_capture.csv`.

### Privacy

- Current interactive tester account values in persisted runtime/network/IPC reports are normalized to `CURRENT_USER`.
- Security-relevant service/task/system execution accounts remain visible.

### Distribution cleanup

- Release ZIP no longer includes `.github/`, `build/`, `dist/`, `winclientassess.egg-info/`, any `*.egg-info/`, `__pycache__/`, or `*.pyc` artifacts.
- Updated artifact catalog, test-case prerequisites, output documentation, and regression tests for the simplified output set.

### Preserved

- Assessment logic remains based on the validated v1.0.0 / v0.6.4 engine.

## 1.0.0

### Stable release

- Promoted the field-tested v0.6.4 assessment engine to the first stable release.
- No intentional changes to validated assessment logic or phase sequencing.
- Added GitHub-ready repository metadata and project documentation.
- Rewrote README around the current stable workflow.
- Added complete Windows 11 installation and optional-tool documentation.
- Added usage, methodology, output, troubleshooting, and release-validation documentation.
- Added `pyproject.toml` and a `winclientassess` console entry point while preserving direct `python .\winclientassess.py` execution.
- Added standard-library regression tests and a Windows GitHub Actions workflow.
- Added `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore`, and `.gitattributes`.
- Expanded `tool_paths.example.json` to document every detected external tool.

### Validated baseline

- Full MSI assessment: field-tested successfully.
- Full EXE assessment: field-tested successfully.
- Pre/post snapshot flow, service/task review, permissions/ACL reuse, and updater correlation reviewed without discovered issues.
