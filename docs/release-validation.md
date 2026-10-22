# WCA v2.2.2 — Release Validation and Sign-off

## Production version and artifacts

- Freeze: **v2.2.2-R3** is the functionality baseline. The production promotion changes only version metadata, tests that assert version strings, and release documentation. No collection, analysis, Guided Runtime, GUI, review-state, manifest schema or Client Appendix behavior changes are intended.
- Version agreement: `wca.py` (`VERSION`), `pyproject.toml`, backend defaults, PowerShell validator and relevant regressions all identify **2.2.2**. The artifact catalog remains **2.0** and methodology remains **1.9**.
- Source: `WCA-v2.2.2.zip` (full regression suite, audit scripts and version-neutral/historical illustrative art). Tester: `WCA-v2.2.2-Tester.zip` (runtime, docs, approved PoC helpers; **no** tests, developer packaging tools, assessment evidence or private `tool_paths.json`). Verify published SHA-256 checksums.
- No GitHub tag, release or repository update is implied by building the packages. Publication is a separate approved step.

## Automated and package validation

1. From a clean extraction of the **source** ZIP, run `python -m pytest -q` (after `./install_dependencies.ps1 -TestDependencies` on Windows) and `python scripts/package_release.py --audit-only`, or `./scripts/validate_windows.ps1` on Windows. Record skipped tests, if any; never claim unrun native Windows integration tests passed.
2. Confirm `python ./wca.py --version`, `--help`, capabilities, `tool_readiness` and Python import checks. Ensure `wca.py`, `pyproject.toml`, and validation script agree on the production version.
3. Confirm both ZIPs extract without errors and contain no `.venv`, caches, `tool_paths.json`, assessment data, raw PML, private API tokens, historical duplicate validation scripts or nested releases.
4. Compare current runtime source with accepted R3 after normalizing **version-only** references. Any other engine or GUI change requires renewed review and acceptance.
5. Verify the SHA-256 checksum manifest against the actual ZIP bytes. The approved version-free promotional PNG is shipped with the GitHub upload assets; source archive artwork must be audited independently.

## Native Windows acceptance status and remaining smoke test

**Previously completed on Windows:** R1 DarkRelay Static/Full installation, one Guided Runtime session, WCR/manual review and client appendix; R2 Static MSI collection, GUI `lessmsi` path configuration/persistence, inline report viewer and duplicate-assessment error; R3 opening of an R2 Static assessment, read-only report search/copy, MSI quick-search, integrity warning and manifest PASS.

**Latest field result:** The assessor reported completing a full native Windows v2.2.2 assessment with Guided Runtime/review and Client Appendix with no issues. The test answers were synthetic and cannot be cited as validated target vulnerabilities. **Additional publication checks:** New clean extraction, GUI/UAC, tool readiness, version, read-only previous assessment, and integrity smoke are recommended on a Windows 11 VM. Re-run the production **full-source** regression/validation suite after the original source ZIP is available; it is not contained in the lean tester distribution.

**Cross-version safety:** Assessments from v2.2.2-R3/R2/R1 are readable under supported integrity checks but are not writable by production v2.2.2. For a new production assessment or Guided Runtime capture, create a same-version assessment. Do not bypass version gates or re-hash modified evidence.

## Security and privacy acceptance

- Client Appendix: preserve allowlist, sanitation, relative links and checksums; never include `working/`, source snapshots, extracted binaries, raw Procmon captures, tester-private notes, host secrets or `tool_paths.json`.
- Report previews are read-only. Confirm the integrity warning is visible near external-use controls. Saving edits to a protected original report should cause manifest verification failure; WCA must **not** silently accept or rehash it.
- The `Copy PowerShell search` action requires a nonempty term, uses a literal escaped path/pattern and never executes it for the tester. `Copy report path` is separate.
- Candidate `VALIDATED` is an analyst review status, not proof of exploitability; testcase completion is separately recorded. External tool readiness is distinct from assessment coverage.
- Path/ACL staging warnings are advisory. Per-user install locations can be legitimate; the Appian tester's reported 3-vs-7 case discrepancy is unresolved and was not validated using client files. DarkRelay Static path comparisons did not reproduce it.

## Historical acceptance provenance (not current instructions)

- **v2.2.0:** M2-p4 Full/Guided Runtime/review/Client Appendix; M2-p5 native UAC; RC1 start and previous-assessment inspection. Published baseline followed release source/tester packaging.
- **v2.2.1:** Guided Runtime optional first-step recommendation accepted, including a second observation that restored the expected DarkRelay correlation candidate.
- **v2.2.2-R1:** DarkRelay Full and Static assessment validation; discovery of lowercase tool-path override and inactive report-preview copy-control defects.
- **v2.2.2-R2:** Corrected tool overrides and unified report preview, static applicable-stage progress, actionable input rejection and test-case exclusions; native Windows usability checks completed.
- **v2.2.2-R3:** Integrity warning and nonempty search-driven PowerShell copy verified on Windows against an earlier assessment; 514 portable regression tests passed in three nonoverlapping batches in the R3 development run.

See [current Windows Acceptance Checklist](windows-validation.md) and [Getting Started](getting-started.md) for operational instructions.
