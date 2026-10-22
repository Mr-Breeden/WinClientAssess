# WCA v2.2.2 — Local GUI guide

WCA v2.2.2 retains the Windows-local, offline browser GUI and tester-controlled Full Assessment / Guided Runtime engine. Windows field testing covered R1 Full/Guided Runtime/export, R2 Static/Tool Readiness and R3 report-viewer controls. No new collector or automated target-side action was introduced for the final production promotion.

## Launch

From the extracted WCA directory on Windows 11:

```powershell
.\install_dependencies.ps1
python .\wca.py --gui
```

The launcher opens a private session URL automatically. **If the browser does not open, copy the complete URL printed in the terminal, including its `#session=` fragment.** The plain `http://127.0.0.1:9001/` address alone does not grant access. The fragment is never sent to the HTTP server and is removed from browser history after the tab saves the token in session storage. Keep the launch URL private. To choose a different local port:

```powershell
python .\wca.py --gui --port 9002
```

The listener binds **only `127.0.0.1`**, never an external interface. `--port` only selects a local port; there is no `--host` or remote exposure option. Stop the listener with Ctrl+C in the terminal. There is no service installation, background daemon, automatic application launch, or external/cloud dependency. Leave the WCA terminal running while using the GUI. The WCA GUI requires an elevated Windows process; launching from standard PowerShell now requests Windows UAC approval **before** the local listener opens. If approved, the GUI starts in a **new elevated console**. If declined, it does not start. CLI Full mode and Guided Runtime retain Administrator checks; read-only and static CLI operations remain available unelevated.

## v2.2.2 Tester Workspace

After collection, open **Tester Workspace**. The primary panels are **Overview**, **Testing Queue**, **Evidence & Guidance**, and **Final Checklist**. A conditional first panel, **1 · Runtime Observation**, appears for integrity-verified Full Assessments that have no successful Guided Runtime session. Start capture or explicitly skip in this browser before continuing; neither action runs automatically. The Testing Queue joins applicable manual cases and their linked WCR candidates into one activity, with all related WCR cards independently expandable and savable; unmatched WCR candidates remain separately listed. Manual Test Completion is visually separated from WCR dispositions. Supporting report previews are linked directly from activities. Evidence & Guidance offers optional reference material rather than a duplicate checklist. Tester decisions and notes are independently integrity-protected. See [Manual Testing Workflow](manual-testing-workflow.md).

## Workflow

1. **Overview:** Enter or browse to an existing completed assessment directory. Saved selection remains in *this browser's* local storage; **Recent Assessments** also remembers explicitly opened projects in a tester-local file outside assessment evidence. Discovery is limited to previously selected output parents and is bounded. Its summaries do not replace integrity verification. View lifecycle checkpoints, coverage, integrity and review counts. Read-only refresh is allowed for earlier completed assessments.
2. **New assessment:** Select MSI/EXE or portable application, output folder and mode; press Start. The browser launches the original WCA engine in a private background worker, **not a PowerShell window**. Observe log/checkpoint progress and use the explicit Continue button once you have manually installed/launched/exercised the target. The new-assessment checkboxes preselect optional runtime/network choices; manual installation/activity and Procmon Stop remain explicit browser checkpoints. WCA requests elevation at GUI launch, before full-mode collectors are available. Same-version interrupted assessments alone may be eligible for resume.
3. **Guided Runtime:** For an intact completed **same-version** Full assessment, click Start Guided Runtime from the optional Tester Workspace step or Overview. The dedicated **Guided Runtime Observation** panel displays Starting, Capturing, Processing and completion/failure states plus target process/connection counts, trace growth and final integrity. Perform tester-controlled target activity and press **Stop capture** when finished. Neither target applications nor PoCs are launched by WCA. Completed observation session history is loaded from integrity-verified `working/guided_runtime_observations.json` after restarting the GUI, without initiating a new capture.
4. **Tester Workspace > Testing Queue:** Select an activity in Remaining, Pending Guided Review, Pending Manual Testing, Addressed or All. For cases with linked candidates, all WCRs appear in separate expandable cards, including the original ten-section validation guides. Each WCR disposition and notes save independently; the manual test status remains separate. All applicable work must be addressed before the activity leaves Remaining. Candidate VALIDATED is not proof of exploitability; saves verify assessment integrity and the evidence fingerprint. The candidate-only activities are also in the same queue.
5. **Reports:** Browse bounded, sanitized, human-readable `.txt`, `.md` and `.html` artifacts from the selected assessment's `reports` directory. The preview renders report contents strictly as **plain text**; HTML/JavaScript from assessment files is not executed within the GUI. Use the existing standalone `assessment_report.html` in a trusted offline viewer when interactive dashboard features are needed.
6. **Client Appendix:** Available only when assessment integrity is PASS and required review is completed. Explicitly confirm a separate ZIP output path **outside** the assessment. Backend export includes its existing sanitization, integrity and evidence-selection gates. No unsanitized working files or raw capture are sent to the browser.
7. **Assessment Management:** Open the dedicated sidebar tab to run fresh integrity verification, see safe checkpoint resume options, and explicitly regenerate only eligible derived reports when the verified state marks that action repairable. Explanations identify why buttons are disabled. Never force recovery for damaged source evidence.
8. **Help & About:** Read offline Getting Started, Windows VM Setup, Optional Tools and GUI guides; inspect WCA/framework/CLI version information, Python version and detected external executable file versions where they can be verified without executing a program.

## Current v2.2.2 report preview and tool setup

- **Tool readiness:** Missing supported executables can be configured with **Configure tool location → Browse → Save and verify**. Overrides are stored only in the workstation-local `tool_paths.json`; the UI confirms actual detection and preserves other overrides. Clearing an override restores automatic discovery. WCA does not download, install or execute the selected tools when configuring paths.
- **Testing Queue supporting reports:** Open a report from its activity to display a **read-only inline preview beneath the selected link**; the page does not jump to the top. Find/Next/Previous navigate matching lines locally. **Copy report path** copies the actual selected assessment report location. **Copy PowerShell search** is disabled until a nonempty search term is entered; it copies an optional literal, read-only `Select-String` command and never launches Notepad. MSI custom-action/sequence shortcuts prepopulate search terms.
- **Integrity-protected evidence:** Preview, search and copy do not alter reports. A persistent warning explains that saving edits to an original protected file can invalidate SHA-256 assessment integrity; testers needing edits should work on separate copies. WCA never silently re-hashes externally modified reports.
- **Assessment-start validation:** Wrong target type, missing/unsupported file and existing assessment names are rejected. Current safe notifications explain known errors without exposing a tester's full local paths. Choose **Installable MSI/EXE** for `.msi` installers; **Portable EXE / application folder** is not the MSI workflow.
- **Static progress:** completed applicable stages are counted separately from not-applicable stages; this display does not change collected evidence.

## Performance and worker-log behavior

Worker output uses one persistent scroll area. If the tester is reading the latest messages, new lines remain visible; if scrolled upward, WCA preserves the position. Only active jobs poll every 2.5 seconds. Overview combines status, review counts and runtime history in one response, and the Testing Queue reuses recently loaded cards for display only. Explicit saves, Client Appendix exports, regeneration and Assessment Management continue performing fresh integrity verification.

## Safety and access boundaries

- The GUI uses an ephemeral random session token delivered only in the terminal's private launch URL fragment, never in the public HTML. The browser keeps it in tab-scoped session storage and sends it in a required custom header for API requests. Host, Origin, fetch-site and loopback bind are checked. Cookies, public API access, external resources and permissive CORS are not used. Local host access should still be protected as part of the tester's workstation security; other processes running as the same user or local administrators are **not** a security boundary that the GUI can defend against.
- A single operation lock protects every cooperating mutating assessment operation. Stale locks are **never** automatically stolen: verify the previous process has stopped and check integrity before manual intervention.
- No tester notes, passwords, arbitrary raw assessment state, raw Procmon PML or full-host CSV are returned by the general read-only backend actions. The private, token-protected `/api/review-detail` endpoint returns only the selected condition's notes to the active local GUI session; this is necessary for safe note preservation. The GUI preview applies privacy normalization and imposes report size and location restrictions. Optional HTML report preview is rendered as text only.
- Workers are launched as Python subprocesses with CREATE_NO_WINDOW on Windows, without arbitrary shell interpolation or a second terminal. The browser confirms checkpoints through validated JSON responses, and the worker blocks until they are acknowledged. Reloading the browser restores the job ID; stopping the server does not constitute a clean worker completion and may leave a paused/failed assessment. Do not shut down your VM during critical collection.
- The first GUI requires paths to existing files/directories. Native Windows path pickers are available where supported, with text entry as a fallback. The browser's own file input cannot reveal local filesystem paths for security reasons.

## GUI acceptance — Windows 11 (current v2.2.2)

Run `./install_dependencies.ps1 -TestDependencies` and `./scripts/validate_windows.ps1`; validate the Python GUI HTTP tests in the regression suite. Then:

1. Run `python .\wca.py --gui` from Windows PowerShell; confirm it opens ONLY on `127.0.0.1:9001`, and an alternate port works via `--port 9002`.
2. Open completed, intact **earlier-version installable and portable** assessment directories. Confirm checkpoints, integrity, review, file list and Appendix readiness match the CLI. Compare manifest SHA-256 before and after all read-only GUI operations.
3. Verify Guided Review instructions match `evidence_guide.txt`, existing notes load without modification, one Save action records an explicit change without a popup, changed evidence causes refusal, and successful saves leave integrity PASS. Force a controlled rendering error only on a disposable regression fixture; verify guarded rollback restores previous state.
4. Test Client Appendix export for a completed reviewed assessment; verify checksum, sanitized contents and **unchanged assessment manifest**. Confirm pending review and damaged source block export.
5. Run one small static and one full GUI assessment on authorized fixtures. Confirm no additional PowerShell window opens, browser checkpoints wait for explicit tester action, snapshot and module statuses update, and final integrity passes. Run one Guided Runtime browser capture, stop it with the button, and check sanitized evidence and no retained full-host PML/CSV. Refresh the page at a checkpoint and verify that it reconnects to the same running job. Do not run any PoC automatically.
6. Confirm forbidden Host/Origin requests, missing tokens, report traversal and cross-site POSTs fail; test selected-assessment reload and GUI close/reopen. Confirm release package excludes `tool_paths.json` and any generated GUI logs.

**Compatibility:** v1.9.2 and subsequent completed assessments remain readable without migration. Interrupted assessments from a different release must not be silently resumed. The current v2.2.2 GUI uses the accepted unified Testing Queue. Historical milestone-specific tab layouts should not be used as current acceptance criteria.

## Interrupted review-save and integrity failures

Opening `assessment_report.html` or viewing review conditions is read-only. A GUI Save action regenerates several integrity-tracked reports. If power or the WCA process stops mid-save, a changed `working/tester_review_state.json` and a `reports/*.tmp` may remain. **Do not manually delete the temporary files or recertify the manifest.** Stop modifying the assessment, preserve a complete forensic copy, and inspect the decision timestamps and integrity results. v2.0.1 attempts an integrity-verified rollback on caught errors, but does **not** silently reconstruct already-damaged evidence or recover after abrupt process termination. An interrupted v2.0.1 review may leave a `.wca-review-backup-*` folder beside the assessment for manual investigation; do not discard it before verifying state. Restoring an assessment from a known-good VM/filesystem snapshot is preferable to ad hoc manifest regeneration. Client Appendix export remains blocked until integrity is PASS.

## v2.2.0 — Full assessment preselection and one-checkpoint workflow

On **New Assessment**, choose extraction and expanded filesystem inventory options. Full mode additionally enables Network/IPC review by default and leaves optional Procmon capture disabled by default. These selections are made once; optional Yes/No questions and a second network-readiness prompt are skipped for GUI-started jobs. **Install, launch and exercise the target yourself** before confirming the required installation/activity checkpoint. WCA never controls the target. If you opt into Procmon capture, explicitly stop it when manual testing is complete. Standalone Guided Runtime remains available after completing a verified Full assessment.

**Guided Runtime observation:** the Overview capture panel shows STARTING until the Procmon PML backing file is created and populated. Only then does **Stop Guided Runtime Observation** become available. Selecting it sends the explicit Stop checkpoint, then the existing collector gracefully terminates Procmon and processes the sanitized target-scoped trace. A controller failure reports `capture_controller` and collection WARN; it must not show a successful zero-event analysis. Keep the GUI PowerShell host alive until processing and integrity checks finish.

**Guided Review:** expand multiple sections independently, or use Expand All/Collapse All. Expansion state for each condition is preserved when switching candidates. The persistent worker-status control on the top bar indicates RUNNING/Action required and takes you back to Overview.

## v2.2.0 release-quality notes

The **New Assessment** toggles use fixed-width checkbox controls on Windows. They preselect options before collection; WCA still requires an explicit manual install/activity checkpoint and a tester-controlled Procmon Stop. Assessment Management contains integrity verification, safe resume and derived-report regeneration; unavailable actions explain the gating condition. Switching tabs does not end a running background job, but the GUI server must remain active. The Recent Assessments list remains local and separate from assessment evidence.

Permissions Review now excludes unrelated registered-application update trees when installed target services, scheduled tasks or tester-defined roots establish target ownership. The full installation differential remains available for manual corroboration; this is not a reason to disregard shared/out-of-tree components.

## Corrected v2.2.0 distribution: telemetry and notifications

A temporary Windows access-denied/share-lock during a **GUI telemetry** update can prevent a live statistics refresh. The worker now retries a few times, then shows one sanitized warning and **continues actual Procmon collection**. This is specific to browser-only statistics: it does **not** weaken atomic assessment report, evidence or manifest updates. The Stop Guided Runtime Observation control uses the verified capture checkpoint, even when `telemetry.json` is temporarily unavailable. Verify the final capture status and target events using the retained Guided Runtime report.

Only errors or attention-requiring problems trigger global notifications; ordinary saves, copy actions, and job-start progress update their local UI without an informational popup. GUI issue notifications have an explicit **Dismiss** control and a top-bar **Notifications** history button. For rejected actions they display the operation, sanitized code, a not-confirmed outcome, and a next step. Never assume a failed save was committed: verify integrity and the recorded decision first. Recent notification history lasts for this browser page session; it is not persisted to assessment evidence or exported. Copy Diagnostics contains only the displayed, sanitized fields.

GUI regression tests use a temporary Recent Assessments catalog and do not register test-case folders in the normal tester-local catalog. Older stale `case` entries are not deleted automatically; the tester may reset that catalog separately, after backing it up.

## Collection provenance (v2.2.0)

A completed v2.2.0 assessment provides `collection_provenance.txt` in the report browser. Each applicable `.txt` report has a concise provenance reference. The main provenance report lists actual execution records, privacy-preserving command shapes and WCA-internal analysis methods. Its working JSON stays internal and is not part of the Client Appendix; see [Collection Provenance](collection-provenance.md).

## M2-p2 Tester Workspace

Use **Testing Queue** as the single remaining-activity list after assessment collection and Guided Runtime. It embeds case-specific procedures, related candidates and verified report links in one place. The old separate editors are retained internally for state compatibility. Manual `ADDRESSED IN GUIDED REVIEW` is explicit and never inferred from a candidate disposition. See [Tester Workspace Workflow](manual-testing-workflow.md). Client-Facing Notes are clearly labeled as included in client deliverables; Internal Tester Notes are not.


### M2-p4 Testing Queue and references

Selecting a manual activity presents all linked WCR candidates in their own expandable cards, with pending reviews expanded. Save each WCR independently. The **Manual Test Completion** heading marks the separate TC-level procedure and status. Completing a TC does not hide pending WCR candidates. Evidence & Guidance is now a reference view with supplemental, scope-dependent testing cards and collection/provenance shortcuts; it does not add a second checklist. The detailed attack-surface plan remains available as an optional reference.

## R2 error handling and report reader

New Assessment gives safe rejection reasons for existing output directories, invalid names, missing targets and missing output parents. The selected target's user-profile location triggers a non-blocking staging advisory. In the Testing Queue, Supporting reports open next to their reference; use literal in-report search with match navigation. Copy report path is always available for verified reports; Copy PowerShell search requires a nonempty literal in-report search term and copies a read-only `Select-String` command. A persistent integrity notice reminds testers not to save edits to the original report; copy it elsewhere first. Older-version assessments remain read-only.
