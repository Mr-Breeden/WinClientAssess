# Collection provenance and live recheck (v2.1.0 accepted baseline)

WCA provides a provenance section in **technical evidence reports** only. Its
purpose is to tell an assessor (1) which tools/methods actually produced the
recorded data and (2) how to independently verify selected observations during
a client walkthrough. This is not a vulnerability confirmation mechanism.

## What receives the provenance section

Reports from collector/evidence phases (`static`, `installed_state`, `runtime`,
`surface`, and `updater_security`) receive a **COLLECTION PROVENANCE** section
immediately below their title. Examples: `services_review.txt`,
`binary_security_review.txt`, `permissions_review.txt`,
`network_surface_review.txt`, `named_pipe_permissions.txt`,
`signature_review.txt`, and `local_storage_review.txt`.

Synthesis, administrative and tester-planning reports **do not** carry the
section: `test_cases.txt`, `tester_review.txt`, `findings.txt`,
`findings_summary.txt`, `coverage_summary.txt`, `module_status.txt`,
`attack_surface_test_plan.txt`, `evidence_guide.txt`, and analogous summaries.
Static plans and capture instructions are also excluded. The underlying
provenance state remains available for reconciliation.

## Two different kinds of information

1. **Execution references** (`PROV-xxxxx`) refer to real WCA-tracked tool
   invocations or explicit internal Python collection/analysis methods. Those
   IDs are stable across report re-rendering and Guided Runtime additions.
   The central `reports/collection_provenance.txt` file provides the full
   execution audit, per-report index and command **shape**, but never raw
   scripts or private positional arguments.
2. **LIVE RECHECK** commands are separately labeled, curated **manual examples**
   for independent verification. These examples were **not necessarily run by
   WCA** and must not be presented as recorded invocation logs. Replace
   `<PLACEHOLDER>` tokens with the relevant assessed target name/path/PID. The
   recommended commands only verify their stated subset of the report.
   Missing or nonuniform observations deliberately have no fabricated one-line
   replay command.

For example, a services report can suggest:

```powershell
Get-CimInstance Win32_Service -Filter "Name='<SERVICE_NAME>'" |
    Select-Object Name,StartName,PathName,StartMode,State
```

This independently checks the current service configuration but does not
verify effective ACLs, exploitable unquoted search paths or other inferred
security conclusions. Such conclusions need additional review.

A `COMPLETED` execution means a command returned successfully, not that a
vulnerability or particular measurement was validated. A noncompleted
execution is called out near the top of the central report and remains in the
full audit history. A failed Procmon termination command does not *by itself*
mean that a capture failed; inspect the capture and evidence reports.

## Layout of the central report

1. `AT A GLANCE`: counts of recorded executions, failures, and evidence reports.
2. `COLLECTION ISSUES`: noncompleted executions with stable IDs.
3. `RECHECK COMMANDS`: curated commands with prerequisites/scope limitations.
4. `EVIDENCE REPORT INDEX`: links report filenames to recorded execution IDs.
5. `EXECUTION AUDIT`: full history of sanitized command shapes and native
   collection methods, grouped by stable ID.

## Safety, evidence integrity, and limitations

- Only the approved, static command examples are written to tester reports.
  Never persist or copy raw PowerShell bodies, arbitrary arguments, profile
  paths, credentials, or secrets to the provenance log.
- Recheck procedures may depend on installed tools, permissions, current
  runtime state and target availability. A read-only command may still display
  sensitive results; review before presenting or exporting it.
- Some reports rely on snapshots, Procmon, Python parsing or correlation rather
  than one repeatable shell command; those reports show collection methods and
  record IDs without claiming live single-command reproducibility.
- `working/collection_provenance_state.json` remains operational state. It is
  integrity-verified and is **never** copied into the client appendix.
- `reports/collection_provenance.txt` is the authoritative human-readable
  record, included in the client appendix only through the existing sanitized
  allowlist and integrity-verified copy-only export.
- Report regeneration is idempotent. It never invents or backfills execution
  history for older assessments. Provenance source state is unchanged when
  the readable report presentation changes.

For validation, see `docs/windows-validation.md` and the provenance regression
tests. Run native Windows validation before treating this patch as a release.
