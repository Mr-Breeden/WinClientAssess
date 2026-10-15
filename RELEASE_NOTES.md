# WCA v2.1.0 — Evidence Collection Provenance

**Release status: accepted project baseline (October 15, 2026).** Windows validation: **427/427 tests passed** and **release audit PASS**. full-mode Windows assessment evidence, integrity records, provenance and the Client Appendix underwent artifact review. **Live browser/GUI acceptance and a clean-VM installation walkthrough remain open checks**; the accepted baseline designation does not claim these were completed. Built from the revised v2.0.5 baseline. Do not modify completed v2.0.5 assessments with v2.1.0; create a new v2.1.0 assessment for new collection and use older assessments read-only under the existing version gates.

## Included changes

- Two-tier provenance: short tool/command references in each applicable `.txt` report and a central `reports/collection_provenance.txt` with stable `PROV-xxxxx` identifiers, status, tool, internal method, and executed command shapes.
- Actual invocation tracking from the shared command runner and direct Procmon process invocations. Skipped/unavailable modules are distinguished from successful execution; native Python analysis never claims an external tool ran.
- Privacy: PowerShell script bodies are replaced with `<SCRIPT_REDACTED>` plus recognized cmdlet names; external command arguments and URLs are normalized to placeholders. No original script bodies, environment variables or command output are stored.
- `working/collection_provenance_state.json` is operational state, included in the SHA-256 manifest. It preserves execution identifiers through Guided Runtime, review re-renders and safe derived-report regeneration.
- Client Appendix copies verified, sanitized provenance through the existing report allowlist, without exporting working state or modifying the assessment.
- Documentation, tests and Windows validation were updated for v2.1.0. Existing GUI, Procmon, privilege review, integrity controls, explicit tester-only target interactions, and assessment engine remain available.

See [Evidence Collection Provenance](docs/collection-provenance.md), [Windows validation](docs/windows-validation.md), and [CHANGELOG.md](CHANGELOG.md). The provenance usability patch places references at the beginning of technical evidence reports only; summary, review and test-case reports have no provenance header. Live recheck examples are distinct from executed commands. Complete any remaining GUI/clean-install acceptance cases before claiming full environment acceptance.
