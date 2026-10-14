# WCA Client Appendix export

The **Client Appendix** is a portable, copy-only, *reviewed technical summary* of a completed assessment. It does not create reportable penetration-test findings and does not infer exploitation or impact from an automated indicator or a VALIDATED reviewer disposition.

## Invocation

From the main menu, select **Export Client Appendix**. Or run:

```powershell
python .\wca.py --client-appendix 'C:\Assessments\Client-Full' --appendix-output 'C:\Deliverables\Client-Appendix.zip'
```

A destination outside the assessment folder is mandatory. Explicit `--appendix-output` is the noninteractive export action; the interactive menu asks for confirmation.

## Safety gates

Export fails closed when:

- the assessment SHA-256 manifest or any report, supporting evidence, or extraction hash fails verification;
- the assessment is not finalized or any required lifecycle/snapshot/reporting stage is incomplete;
- module collection contains unresolved `ERROR` status;
- Guided Review is missing, includes any PENDING condition, or records evidence changed since a decision;
- an approved report or link cannot be trusted, or the ZIP cannot be verified.

Optional coverage gaps may still exist on a completed assessment; they must remain visible in the included coverage summary. An accepted export does **not** assert full vulnerability coverage.

## Export contents

- `assessment_report.html` — portable offline technical overview with an evidence-grounded scope and footprint, grouped reviewed observations, theme switch and approved evidence navigation; no tester notes or confirmation claims;
- `README.txt` — interpretation and provenance notice;
- `SHA256SUMS.txt` — checksum for every other included file;
- `evidence/*.txt` — present reports from a strict sanitized allowlist: application profile, coverage, signing, PE security, configuration, service, permissions, network and IPC summaries.

The export never includes secret-scanner details, raw/working Procmon records, snapshots, source/decompiled files, internal state/manifests, reviewer notes, or NOT APPLICABLE items. Only already generated and approved reports are copied. The original assessment tree, state, manifests and reviewer decisions are unchanged.

Inspect the client appendix for appropriate disclosure scope before sending it. The full tester dashboard and backend assessment should not be treated as equivalent deliverables.

## HTML presentation

The client appendix defaults to a dark theme; a **Light theme** control toggles locally between two accessible palettes. No external scripts, fonts, images, or network calls are used. Only data from strictly approved sanitized reports is summarized. Metrics missing from approved evidence are shown as “Not recorded,” never guessed. Grouped review items remain observations, not verified findings.
