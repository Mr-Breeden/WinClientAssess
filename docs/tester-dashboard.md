# WCA v2.0.5 — Offline tester dashboard

`reports/assessment_report.html` is the self-contained offline, printable, read-only tester dashboard generated from verified review and assessment state.

The **Tester Action Center** highlights pending reviewer decisions, source module gaps, and evidence-collection limitations before the supporting analysis. Review conditions are grouped under Pending, Validated, Informational, and Not Applicable sections; each condition links to the corresponding evidence and manual validation guidance. A VALIDATED disposition uses a neutral color and never independently represents a proven vulnerability.

Guided Runtime displays a summary of capture/processing durations, current/seen processes, target event totals, new review candidates, Procmon collection status, followed by compact per-surface **Coverage observations** chips. Post-processing evidence counts are not represented as live Procmon events.

Other sections retain an application/technology profile, module health, coverage limitations, automated review points, attack-surface test plan, and phase-grouped evidence links. Generated links are relative to the assessment root, HTML is escaped, tester identifiers are privacy-normalized and no remote scripts/fonts/assets are loaded.

**The standalone `assessment_report.html` is read-only and never directly saves reviewer state.** Tester decisions are edited through the WCA CLI or the authenticated local WCA GUI Guided Review tab, which applies integrity and evidence-fingerprint checks. For a separately shareable, restricted technical summary after review completion, use the integrity-gated [Client Appendix workflow](client-appendix.md), not a copy of the tester dashboard.

## Current review workspace and themes

The generated offline HTML defaults to dark mode. Use **Light theme** in the sticky navigation to change palettes. The browser may retain the preference locally; the choice never modifies assessment evidence, review state or the integrity manifest.

The review section uses a searchable two-pane workspace when JavaScript is available: filter by status, module, or text; choose a condition to display its evidence and optional validation procedure. A restrictive hash-authorized offline script implements only local presentation. When scripts are disabled, the original grouped review details remain visible for browsing without data loss. Review decisions are saved through the WCA CLI or the local GUI Guided Review tab, never directly through the standalone report.

Automated review points are source indicators, not confirmed vulnerabilities. Candidate notes remain tester-only and are never copied to the Client Appendix.
