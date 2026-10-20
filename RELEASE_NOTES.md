# WCA v2.2.1 — Optional Runtime Step in Tester Workspace

Focused follow-up to the accepted v2.2.0 release baseline.

- On a completed, integrity-PASS Full Assessment without any successful Guided Runtime session, Tester Workspace places **1 · Runtime Observation** before Overview and Testing Queue.
- Presents a non-blocking recommendation with **Start Guided Runtime Observation** and **Skip for this assessment (this browser)**. Start uses the existing authorized tester-controlled worker, then transitions to its existing Overview monitoring/Stop controls.
- A skipped recommendation is kept only in the local browser storage, not written to integrity-tracked assessment data or exported as test evidence. The Tester Workspace Overview allows returning to the optional step.
- Successful Guided Runtime sessions suppress the recommendation. Failed/interrupted-only histories do not. Static and incomplete assessments do not display it. Earlier framework-version assessments remain readable but cannot start an incompatible capture.
- No changes to runtime collection, test cases, WCR disposition, artifact catalog 2.0, integrity format, or Client Appendix content.
- **Windows field acceptance is pending** for the new workspace controls. The v2.2.0 baseline was Windows-tested.

---

# WCA v2.2.0 — Production Release

**Released:** October 16, 2026 · **Internal framework version:** `2.2.0` · **Previous published release:** v2.1.0.

## Highlights

- **Unified Tester Workspace:** A single Testing Queue coordinates manual test cases and linked Guided Review candidates. All related WCR candidates appear as independent expandable cards, with pending candidates expanded by default and an explicit Manual Test Completion section. Completion counts remain accurate when WCR work is pending.
- **Contextual Evidence & Guidance:** Concise supplemental testing guidance and report previews support the queue without creating a second mandatory checklist. Existing technical `.txt` reports and immutable `test_cases.txt` remain traceable offline references.
- **Manual review persistence and privacy:** Manual states and WCR dispositions remain independent and integrity-protected; internal notes remain private, and only explicitly authored client-facing notes enter a sanitized Client Appendix.
- **Guided Runtime and provenance:** Improved scope-aware Procmon/runtime review, coverage refresh, collection provenance, lifecycle handling and source evidence integrity.
- **Early Windows UAC preflight:** The GUI requests Administrator elevation before startup when necessary; declined requests exit cleanly, while `--help`, `--version`, read-only commands and supported Static CLI workflows stay available unelevated.
- **Two release distributions:** A streamlined tester ZIP and a complete source ZIP with tests, plus SHA-256 checksums. Versioned illustrative cover art is included with source; it does not depict actual WCA assessment results.

## Verified acceptance

Earlier M2-p4 Windows testing covered Full Assessment, Guided Runtime, GUI testing decisions, and Client Appendix; M2-p5 covered administrator elevation/cancellation; RC1 tester use was accepted after a fresh dependency installation, successful `--help`/`--version`, UAC GUI startup, and opening the prior Full Assessment. Source and clean-extraction portable regression suites passed **484/484 tests** at RC1. The final distribution applies only documentation, branding and packaging adjustments to that accepted engine; no assessment collection or runtime logic was changed after RC1.

Native Windows validation is still installation/environment-specific. Run the included Windows validation script from the **source** ZIP if needed, and verify the required optional utilities. The local GUI session URL is a credential; never paste it into public issues or screenshots.

## Compatibility, artifacts and migration

- Internal assessment version and existing evidence/report filenames stay `2.2.0` and unchanged; prior version assessments remain read-only where required.
- Existing `.txt` evidence reports remain authoritative. Potential future consolidation does not warrant deleting linked artifacts without a verified migration.
- No tester host metadata, local tool configuration, raw Procmon PML or assessment evidence is included in the release packages. Source contains regression tests; tester ZIP excludes them.
- Tester notes are optional; `VALIDATED` records a tester decision, **not** proof of exploitability.

## Installation

Extract the ZIP into a trusted Windows directory and run `./install_dependencies.ps1` followed by `python ./wca.py --gui` in PowerShell. Follow [Getting Started](docs/getting-started.md) for virtual environment and runtime setup. The source distribution supports `./scripts/validate_windows.ps1`.

---

## Historical development milestones

# WCA v2.2.0-RC1 — Windows release candidate (October 16, 2026)

**Status:** release-candidate build for final Windows package acceptance; **not** an official GitHub v2.2.0 release. Internal engine/versioned assessment schema remain `2.2.0`. The accepted v2.1.0 baseline remains unchanged.

### What RC1 contains

- The accepted M2-p4 Full Assessment, Guided Runtime, unified Testing Queue (all linked WCR cards), Evidence & Guidance improvements, review integrity and Client Appendix privacy/export behavior.
- The accepted M2-p5 Administrator preflight: native Windows UAC on unelevated GUI launch, clean cancellation, no duplicate prompts from elevated launch and non-elevated help/version/static mode.
- Source and lean tester distribution options with explicit packaging audit and unchanged runtime report inventory. No new collectors, automatic target actions, or changes to persisted assessment integrity contracts.

### Validation status

- M2-p4 Full Assessment / Client Appendix field test was reported successful and its integrity and export inventories reviewed; M2-p5 native Windows UAC approval, denial, elevated launch and read-only CLI scenarios were accepted.
- RC1 source and tester package regressions, checksum results and verification details are recorded **outside** the archives in the RC1 Validation Record. RC1 itself has not yet completed a clean Windows VM walkthrough or complete release-candidate distribution acceptance.
- The original approved `WinClientAssess Cybersecurity Dashboard.png` is not included: only a nonmaterializable Library record was available. No new or unapproved logo has been substituted.

### Reporting inventory decision

Keep current authoritative TXT reports, required structured working state, raw target-scoped correlation evidence, source manifests and sanitized Client Appendix allowlist. Continue to use the single Testing Queue; `test_cases.txt` and `attack_surface_test_plan.txt` remain optional offline references, **not** additional required checklist activities. Planned mergers (installer, system-change, runtime, IPC/network) require dependency/provenance/integrity migration and are **deferred**, not silently removed.

### Final release gates

1. Run the RC1 distribution Windows validation and open the private GUI from both normal and Administrator PowerShell.
2. Verify local assessment read-only access, a representative existing compatible M2-p4 report/queue, privacy-safe Client Appendix, and manifest integrity; avoid re-running full collection unless a regression is discovered.
3. Complete clean-VM installation/documentation walkthrough; approve original PNG or accept deliberate deferral; review source/tester ZIP manifests and SHA-256.
4. Confirm final release notes and manually authorize GitHub v2.2.0 publication.

---

## WCA v2.2.0-M2-p5 — Administrator elevation preflight (Windows validation candidate)

This patch focuses only on early Administrator privilege checks. Launching `python .\wca.py --gui` from a normal Windows PowerShell session requests UAC **before** any localhost server or GUI assessment is started. Approving it opens a **new elevated console** using the same Python executable (including `.venv`), arguments, and working directory. Cancelling leaves the GUI stopped and reports why; repeated automatic UAC prompts are prevented. GUI background workers cannot initiate independent elevation.

Standalone Guided Runtime and explicitly selected Full-mode CLI operations request/require elevation before beginning privileged collection. Static-mode CLI, `--help`, `--version`, and read-only backend features do not need Administrator privileges. This patch does not change the accepted M2-p4 evidence/reporting workflows or the versioned integrity format; the internal framework version remains `2.2.0`.

**Windows acceptance required:** A native UAC approval, refusal, Administrator-start, custom GUI port, and non-elevated CLI-read-only check must be performed on the user's Windows 11 VM. Portable automated UAC tests mock Windows APIs; they cannot exercise the actual secure desktop prompt. See [Windows Validation](docs/windows-validation.md).

# WCA v2.2.0 — M2 patch p4 (Windows field candidate)

**Internal framework version:** 2.2.0 · **Accepted GitHub baseline:** v2.1.0 (unchanged)

## All linked WCRs in one activity

- Show every related WCR candidate as an independently expandable card, with pending candidates open by default; do not switch a single shared editor between candidates.
- Keep each candidate's ten-section validation guide, disposition, internal notes, client-facing notes and independent save operation. Saving one candidate refreshes queue progress without rebuilding sibling cards or clearing unsaved manual notes.
- Visually separate related WCRs from the new **Manual Test Completion — TC-xxxx** section. Manual completion and Guided Review remain separately persisted and jointly determine activity completion.

## Evidence & Guidance without duplicate test lists

- Remove the standalone `test_cases.txt` launcher from the main Evidence & Guidance section. The Testing Queue is the sole in-GUI place to track applicable manual tests and WCR review. The original generated TXT is preserved for offline use, integrity fingerprints, and existing references.
- Present compact, readable scope-dependent cards for HTTP/API security, deep code/runtime analysis, and application-specific trust boundaries, with a link into the corresponding Testing Queue activity when applicable. They are not new required checklists.
- Leave `attack_surface_test_plan.txt` as an **optional** full methodology reference. Its generated text now includes a quick index with suggested TC IDs and reminders not to duplicate already completed work; this remains reference material, never an automatic completion decision.
- Prioritize collection coverage, module execution status, provenance and findings summary as the primary report shortcuts in Evidence & Guidance. Preserve previous report filenames and privacy/evidence controls.

## Acceptance

Windows GUI retest: verify multiple WCRs are simultaneously visible under one TC, save each independently, confirm unsaved sibling/manual inputs survive WCR saves, check manual completion separation, and verify Overview/Final Checklist counts and Client Appendix after saves. Validate that Evidence & Guidance no longer prompts duplicate testing.

Portable regression and packaging checks: see M2-p4 validation record. **Native Windows acceptance is pending.** WCA v2.2.0-M2-p4 is a development build; no GitHub release.

---

# WCA v2.2.0 — M2 patch p3 (Windows field candidate)

**Internal framework version:** 2.2.0 · **Accepted GitHub baseline:** v2.1.0 (unchanged)

## M2-p3: Tester Workspace correctness

- One authoritative integrity-verified Testing Queue projection is shared between the GUI list, Overview, and Final Checklist. A manual test recorded COMPLETED or NOT APPLICABLE remains outstanding while its linked WCR candidates remain pending or changed. Candidate-only observations continue to appear independently.
- Added Pending Guided Review and Pending Manual Testing queue filters and pending-WCR counts in activity summaries.
- Related WCR candidates are reviewed *inside* the associated manual test activity; the next pending candidate opens by default, with navigation among other linked candidates. Manual status and Guided Review dispositions remain separately persisted.
- Hide/disable ADDRESSED IN GUIDED REVIEW when no candidate is linked, a linked candidate is pending, or evidence changed. Backend independently enforces eligibility.
- Saving a manual decision with pending WCR candidates reports exactly how many reviews remain, without discarding the manual decision or auto-dispositioning any candidate.
- After Guided Runtime, refresh the recorded lifecycle summary to reflect effective coverage. Initial collection history and provenance are preserved.

## Report and documentation audit

The release includes a separate **M2-p3 Artifact Audit** covering each report in the M2-p2 DarkRelay fixture, operational working state, client appendix, and all current documentation. The patch does not silently merge/delete existing authoritative evidence reports, because those names are cross-referenced by tester procedures, provenance and report manifests. The audit provides consolidation options prioritized by migration risk. No duplicate report copies or additional runtime report files are introduced by this patch.

## Validation and scope

See the accompanying M2-p3 validation record for portable automated tests and packaging audit. **Native Windows GUI acceptance remains required.** Retest linked WCR editing, manual completion counts, dropdown eligibility, Guided Runtime coverage summary, and sanitized Client Appendix. No new collectors or target-side actions were added.

WCA v2.2.0-M2-p3 is a **development build**, not a GitHub release.

---

# WCA v2.2.0 — M2 patch p2 (Windows field candidate)

**Internal framework version:** 2.2.0 · **Accepted GitHub baseline:** v2.1.0 (unchanged)

## Changes in M2-p2

- One **Testing Queue** joins case procedures, directly related Guided Review observations, existing verified report links, and review actions. Candidate-only observations remain visible. Legacy review/manual state remains independent; existing decisions are never overwritten.
- Added an explicit `ADDRESSED IN GUIDED REVIEW` manual outcome, permitted only after associated candidates are reviewed and the tester confirms all relevant steps were performed. Pending/revalidated candidate evidence reopens these activities. Overview and Final Checklist use the same queue totals.
- `TC-AS-001` consolidates broader scope-specific testing with Burp Suite, Ghidra/ILSpy, Frida/WinDbg and other tools where applicable. The 26-area attack-surface plan is reference guidance, not a mandatory second checklist.
- Added **Internal Tester Notes** and **Client-Facing Notes** in both review editors. Only explicitly authored client-facing notes enter a standalone Client Appendix HTML section; no supporting report is required. Legacy evidence-reference input is hidden but its saved data is retained privately.
- Replaced in-thread Tkinter picker with a dedicated main-thread Python dialog process. File/folder cancellation is silent and real failures are safely returned.
- Immediate Guided Runtime Starting feedback and duplicate start-button suppression. Backend concurrency controls remain authoritative.
- All existing M2-p1 improvements retained: reduced notifications, in-workspace report previews, no legacy v0.x runtime wording, Final Checklist export, approved-evidence handling.

## Acceptance

Portable regression and packaging results: see `WCA-v2.2.0-M2-p2-Validation.txt` supplied next to the ZIP. **Windows 11 native GUI validation is still required**, including native Browse, Full Assessment, Guided Runtime Start/Stop, editing Guided/manual/client notes, queue integrity after saving, and Client Appendix export/review. No new target collectors, auto-execution paths, or PoCs are introduced.

WCA v2.2.0-M2-p2 is a development build, **not** a GitHub release.
