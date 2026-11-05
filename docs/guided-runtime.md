# WCA Guided Runtime Observation

Guided Runtime Observation is a post-completion operation for a verified **full-mode** assessment. It observes target-associated activity while the tester manually exercises the application.

WCA does not launch, authenticate to, update or otherwise exercise the target automatically.

## Tester Workspace entry point

After a verified Full Assessment, open **Tester Workspace**. When no successful Guided Runtime session is recorded, **1 · Runtime Observation** appears first, before Testing Queue and final reporting. **Start Guided Runtime Observation** uses the existing tester-controlled worker; **Skip for this assessment (this browser)** hides the recommendation locally and allows normal testing without modifying evidence, manifests, statuses or client exports. The Tester Workspace Overview provides an option to reconsider a skipped observation. If a successful session is already present, the step is omitted. Failed and incomplete sessions do not count as completed. Older framework-version assessments remain readable but runtime capture is blocked for version safety.

## Eligibility

The assessment must be structured, full mode, completed, created by the active framework version, integrity-PASS, and have valid target/system-state evidence for runtime correlation. Both installable and portable targets are supported.

## Capture workflow

During capture WCA displays elapsed time, full-host Procmon trace growth, verified current/seen target processes, current connections, and passively sampled target CPU/I/O and connection activity deltas. The live counters do not represent detailed Procmon events. If no target process is currently matched the UI says so, rather than treating Procmon file growth as proof of target activity. Portable primary executable identity is verified by its saved SHA-256 (without saving the source path); explicitly inventoried helpers can be correlated beneath the verified executable directory. The tester chooses a broad, non-sensitive workflow category (for example, Login and session or Updater check), then manually exercises the application. In the browser GUI, click **Stop Guided Runtime Observation** to end capture. In the CLI, press **Enter once** when prompted.

## Target scope

Broad baseline/post-activity snapshots can include unrelated host maintenance. WCA promotes executable/updater paths into target scope only when stronger evidence associates them with the assessed application, such as static payload matching, selected portable scope, service/task launch paths, runtime ancestry, or paths beneath established target roots.

Guided Runtime follows target descendants observed during the session without treating unrelated host processes as application scope.

## Evidence processing

Procmon PML is exported to temporary CSV, then privacy sanitization and target/descendant filtering are performed in a streaming pass. Only target-scoped sanitized evidence is retained; raw PML/full-host CSV is discarded. As of p11, each new session archives its distinct target-scoped evidence under `working/guided_runtime_sessions/<session-id>/`, covered by the assessment SHA-256 integrity manifest. Previously collected p10 sessions cannot be retroactively recovered. The latest-workflow reports remain latest-session views, and old process IDs, socket states, and ACLs require fresh validation; archived sessions are historical context, not current security state. Prior WCR decisions and voluntarily supplied notes are retained when an item is retired. Changed evidence resets the active status to PENDING.

Surface states distinguish observation/collection availability and never imply exploitation by themselves.

After processing, WCA refreshes runtime analysis, Local Storage Review, permissions for scoped DLL-search paths when eligible, Application / Technology Profile, test cases, review candidates, dashboard and integrity manifest. Existing review decisions/notes are preserved when evidence is unchanged.

## Capture context and session history (p11)

The tester may select a broad workflow label for each capture. WCA saves this label, the capture timestamp, status and per-session observation counts, not account names, tenant identifiers, credential values or detailed workflow notes. Overview shows a chronological session history and count comparison; a difference in counts across observation windows is not a security verdict or a merged runtime baseline. Tester notes remain optional.

## p13 updater observation refresh

When a verified Full assessment contains installed updater candidates, Guided Runtime also refreshes the updater security correlation using the new target-scoped Procmon evidence and verified installed-state differential. Updater staging, runtime activity and network endpoint reports are refreshed. WCA does not launch update checks itself or invent an updater where no target-associated candidate was observed. Historical sessions remain archived separately; new updater reports describe the latest session only, and earlier review decisions are not auto-applied to changed evidence.
