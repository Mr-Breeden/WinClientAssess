# WCA v2.2.2 — Unified Tester Workspace

One **Testing Queue** replaces the former sequence of separate Guided Review, Manual Test Cases and a second attack-surface checklist. WCA still preserves independent, integrity-protected candidate dispositions and manual case decisions; a candidate disposition **does not** automatically prove test completion or exploitability.

## Intended workflow

1. Install required tools, open the local GUI and finish a Full or Static Assessment. For an integrity-verified Full Assessment without a successful Guided Runtime session, **Tester Workspace first presents 1 · Runtime Observation**. Review the recommendation, then explicitly start a capture or skip it in this browser. Skipping is an acknowledgement, not evidence of runtime completion. The queue remains accessible either way; Static assessments are not prompted.
2. Open **Tester Workspace > Testing Queue**. The default filter shows only outstanding activities; use Pending Guided Review or Pending Manual Testing to identify outstanding work, and Addressed or All to inspect completed work. A linked candidate and its applicable manual test case appear as **one activity**, with every related candidate's independent, collapsible validation guide and editor shown inline (pending candidates expanded), alongside the case procedure and verified report links. Unlinked candidates appear separately. No test runs automatically.
3. For an activity with a manual case, review the procedure and any linked candidate. If testing is complete, choose **COMPLETED**; if fully performed in the linked Guided Review, explicitly choose **ADDRESSED IN GUIDED REVIEW** after dispositioning all associated candidates and confirming that every required step was actually done. Otherwise use NOT STARTED, IN PROGRESS, BLOCKED or NOT APPLICABLE. A validated candidate alone **never** sets manual status. A completed manual test stays in Remaining while related candidates are pending, and the interface shows their count. ADDRESSED IN GUIDED REVIEW is offered only when at least one linked candidate exists and all are dispositioned with current evidence.
4. Where the attack-surface report is present, **TC-AS-001 — Application-Level and External-Tool Security Review** consolidates broader in-scope application testing not already covered by other activities. It links to the attack-surface methodology and includes Burp, Ghidra/ILSpy, Frida/WinDbg and client-side trust testing where relevant. The plan is supporting guidance, not another checklist to complete separately.
5. Inspect **Evidence & Guidance** only when needing technical detail, provenance, coverage or module errors. WCA should not require acknowledgements of every report merely to mark testing complete.
6. In **Final Checklist**, reconcile the same queue's remaining count and use **Generate Client Appendix**. Export remains explicitly tester-initiated, rechecks integrity, blocks pending candidate reviews and warns about incomplete manual work. Formal vulnerabilities, screenshots and exploitation evidence belong in the separate penetration-test report.

## Optional notes and privacy

Each review editor has **Internal Tester Notes** (never in client deliverables) and **Client-Facing Notes** (explicitly included in the generated Client Appendix). Both are optional. The former manual Evidence Reference text box is hidden; old saved references remain in the internal record to avoid data loss, and testers may add new references directly to internal notes. Client-facing notes receive sanitization and HTML escaping; verify the Client Appendix preview before distribution. Client notes are not automatically migrated from internal notes and do not confer vulnerability status.

## Status integrity and continuity

Manual decisions persist in `working/manual_test_review.json`; candidate decisions persist in `working/tester_review_state.json`. Both are included in the assessment integrity manifest. `test_cases.txt` remains immutable. If a linked candidate becomes pending again, or a test's fingerprint changes, a previous guided-coverage affirmation no longer counts as addressed. Older incompatible framework versions remain read-only. The M2-p4 workflow and RC1 tester startup/compatible-assessment access were field tested on Windows; each new assessment environment still needs its own tool and integrity checks.

## Windows picker and Guided Runtime

The native file/folder picker runs in a dedicated Python process, ensuring Tkinter executes on its own main GUI thread instead of the server's HTTP request thread. Cancellation returns an empty selection without a failure notice. The Guided Runtime Start button is disabled while starting or running; backend assessment locks remain authoritative.


## M2-p4 usability

Each selected TC displays **all** related WCR candidates as independent collapsible cards, with pending candidates expanded by default. Candidate review controls appear inside each card; each WCR saves independently. A full-width **Manual Test Completion** heading separates those reviews from the TC's own procedure and status. The Overview and Final Checklist calculate outstanding work using both applicable manual requirements and pending WCR dispositions.

Evidence & Guidance no longer offers `test_cases.txt` as a second tester workflow. The lengthy `attack_surface_test_plan.txt` remains an optional offline reference, while supplemental guidance cards display scope-dependent security testing themes and navigate back to the Testing Queue.

## R2 report review and applicability

Click a linked **Supporting reports** file to read it beneath the corresponding case or candidate. Use the built-in literal Find, Next and Previous controls to inspect matched lines with adjacent context; copy path/PowerShell searches are optional, never run by WCA. Excluded manual cases and their mode, evidence and prerequisite limitations appear in an expandable read-only explanation. These are not new queue activities or evidence of security defects.
