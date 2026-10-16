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

- `assessment_report.html` — portable offline technical overview with an evidence-grounded scope and footprint, grouped reviewed observations, theme switch, approved evidence navigation, and **explicitly entered client-facing notes only**; no internal tester notes or vulnerability confirmation claims;
- `README.txt` — interpretation and provenance notice;
- `SHA256SUMS.txt` — checksum for every other included file;
- `evidence/*.txt` — present reports from a strict sanitized allowlist: application profile, coverage, signing, PE security, configuration, service, permissions, network and IPC summaries, plus `collection_provenance.txt` when present and integrity-verified.

The export never includes secret-scanner details, raw/working Procmon records, snapshots, source/decompiled files, internal state/manifests, internal tester notes, or NOT APPLICABLE observation rows. Explicit client-facing notes may describe N/A testing context. Only already generated and approved reports are copied. The original assessment tree, state, manifests and reviewer decisions are unchanged.

Inspect the client appendix for appropriate disclosure scope before sending it. The full tester dashboard and backend assessment should not be treated as equivalent deliverables.

## HTML presentation

The client appendix defaults to a dark theme; a **Light theme** control toggles locally between two accessible palettes. No external scripts, fonts, images, or network calls are used. Only data from strictly approved sanitized reports is summarized. Metrics missing from approved evidence are shown as “Not recorded,” never guessed. Grouped review items remain observations, not verified findings.

## Collection provenance

The optional v2.1.0 [Collection Provenance](collection-provenance.md) report contains privacy-preserving invocation shapes and collector identifiers, never raw PowerShell scripts, positional arguments, environment variables, or secrets. The exporter includes this report only when present in the verified evidence allowlist and never exports `working/collection_provenance_state.json`. Review approved technical evidence for engagement-specific disclosure before delivery.

## Optional tester-approved notes (M2-p2)

Both Guided Review and Manual Test Case activity editors offer a distinct **Client-Facing Notes** field. Text entered there will appear under **Tester-approved assessment notes** in `assessment_report.html`, even when the associated manual case has no approved technical report in the sanitized ZIP. No screenshot or separate evidence reference is required. The internal notes field and prior internal evidence reference are never exported. Do not use these notes to duplicate the formal pentest findings report. WCA sanitizes and HTML-escapes output, but the tester must review the exported result before delivery.
