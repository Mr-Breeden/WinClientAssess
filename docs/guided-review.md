# WCA Guided Tester Review

Guided Tester Review is the authoritative interface for dispositioning automated review candidates. Automated observations are not automatically confirmed vulnerabilities.

## Candidate state

Each candidate uses a stable `WCR-...` ID and one disposition:

- `PENDING`
- `VALIDATED`
- `NOT APPLICABLE`
- `INFORMATIONAL`

Tester notes are optional for every disposition. Enter preserves existing notes; `:clear` removes them; `:multi` supports multiline notes. Exact duplicate source events can be grouped while distinct endpoints/components/evidence remain independent.

Review state is stored in `working/tester_review_state.json`. Generated TXT/HTML reflects that state; editing generated reports does not change authoritative review status.

## Interface

The queue is numbered and color-coded. The active condition card shows severity, disposition, module, stable candidate ID, supporting report(s), related test cases, validation summary, starting check and tester notes.

Useful actions include next/back, list/jump, filters, validation guide and **C = Copy checks**. Copied commands are not executed by WCA.

## Validation guide

The persisted `reports/evidence_guide.txt` uses a candidate-specific structure:

1. Observed Evidence
2. Why Validate It
3. Prerequisites
4. Starting Checks
5. Manual Validation Procedure
6. PoC Resource
7. Tester Execution
8. Expected Evidence
9. Interpretation
10. When Not to Report

The live Rich guide groups the same content into six readable panels.

When a bundled PoC resource applies, WCA resolves it against the tool/source directory. C helpers include compilation requirements, inferred target architecture when reliable PE evidence is available, build recipes, expected output and verification commands. PowerShell helpers include direct invocation guidance.

WCA never compiles or executes a PoC automatically. The tester performs every proof action manually on the authorized assessment VM.
