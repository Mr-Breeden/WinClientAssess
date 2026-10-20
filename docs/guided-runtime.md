# WCA Guided Runtime Observation

Guided Runtime Observation is a post-completion operation for a verified **full-mode** assessment. It observes target-associated activity while the tester manually exercises the application.

WCA does not launch, authenticate to, update or otherwise exercise the target automatically.

## Tester Workspace entry point (v2.2.1)

After a verified Full Assessment, open **Tester Workspace**. When no successful Guided Runtime session is recorded, **1 · Runtime Observation** appears first, before Testing Queue and final reporting. **Start Guided Runtime Observation** uses the existing tester-controlled worker; **Skip for this assessment (this browser)** hides the recommendation locally and allows normal testing without modifying evidence, manifests, statuses or client exports. The Tester Workspace Overview provides an option to reconsider a skipped observation. If a successful session is already present, the step is omitted. Failed and incomplete sessions do not count as completed. Older framework-version assessments remain readable but runtime capture is blocked for version safety.

## Eligibility

The assessment must be structured, full mode, completed, created by the active framework version, integrity-PASS, and have valid target/system-state evidence for runtime correlation. Both installable and portable targets are supported.

## Capture workflow

During capture WCA displays elapsed time, full-host Procmon trace growth, verified current/seen target processes, current connections, and passively sampled target CPU/I/O and connection activity deltas. The live counters do not represent detailed Procmon events. If no target process is currently matched the UI says so, rather than treating Procmon file growth as proof of target activity. Portable primary executable identity is verified by its saved SHA-256 (without saving the source path); explicitly inventoried helpers can be correlated beneath the verified executable directory. The tester exercises applicable workflows, returns to WCA and presses **Enter once** to finish.

## Target scope

Broad baseline/post-activity snapshots can include unrelated host maintenance. WCA promotes executable/updater paths into target scope only when stronger evidence associates them with the assessed application, such as static payload matching, selected portable scope, service/task launch paths, runtime ancestry, or paths beneath established target roots.

Guided Runtime follows target descendants observed during the session without treating unrelated host processes as application scope.

## Evidence processing

Procmon PML is exported to temporary CSV, then privacy sanitization and target/descendant filtering are performed in a streaming pass. Only target-scoped sanitized evidence is retained; raw PML/full-host CSV is discarded.

Surface states distinguish observation/collection availability and never imply exploitation by themselves.

After processing, WCA refreshes runtime analysis, Local Storage Review, permissions for scoped DLL-search paths when eligible, Application / Technology Profile, test cases, review candidates, dashboard and integrity manifest. Existing review decisions/notes are preserved when evidence is unchanged.
