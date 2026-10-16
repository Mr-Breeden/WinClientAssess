# WCA v2.2.0 — Release Validation and Sign-off

- Validate the source and an independently extracted release ZIP with `python -m pytest -q` and `python scripts/package_release.py --audit-only`. `scripts/validate_windows.ps1` runs both with explicit exit-code handling and verifies metadata.
- Source `wca.VERSION`, `pyproject.toml` and the PowerShell validation regex must agree on **2.2.0**. Regression tests reject mismatches.
- Compare against the previous release, documenting any modified assessment modules and their exact impact. Do not modify a validated collector unnecessarily.
- On Windows, validate a real browser-controlled Procmon Start → Capture → Stop → Process cycle; a mocked callback does not substitute for actual collection.
- Confirm target-specific ACL scope does not grow to include unrelated software updates, while preserving target service/task and runtime DLL candidate evidence. The original differential remains available.
- Complete a clean Windows VM setup walkthrough using [the installation guide](windows-environment-setup.md), and confirm installer, GUI, external-tool paths, CLI, integrity, reports and Client Appendix instructions are accurate.
- Report Windows validation separately from portable tests. v2.1.0 was accepted as the project baseline on October 15, 2026 after 427 Windows regression tests passed and its full-mode assessment artifacts were reviewed. Outstanding live GUI and clean-VM checks must be labeled as pending, not implied to be completed.

## v2.2.0 additional acceptance

Confirm manual test-case persistence, case fingerprint protection, notes privacy, integrity manifest updates, rollback on a failed save, legacy read-only behavior, and unchanged Client Appendix export rules. Complete live browser/GUI testing on Windows 11 before considering v2.2.0 an accepted baseline.


## Package acceptance and field-validation history

**Previously accepted native Windows field work:** M2-p4 full DarkRelay Full Assessment, Guided Runtime, Testing Queue and Client Appendix; M2-p5 UAC approval/denial, elevated GUI start, and non-admin `--help`/`--version`. These are separate from independent release package/regression validation.

1. **Source distribution:** SHA-256 verify, clean extract, run `python -m pytest -q` and `python scripts/package_release.py --audit-only` (or `./scripts/validate_windows.ps1`). Compare engine/version metadata. Verify no assessment evidence, private `.venv`, local `tool_paths.json` or caches ship.
2. **Tester distribution:** SHA-256 verify, clean extract and confirm `wca.py`, `gui`, `modules`, `utils`, `requirements.txt`, installation helper and approved `scripts/poc` helper files are present. Confirm `tests/`, developer packaging/test tooling and `requirements-dev.txt` are absent. Verify GUI, `--help`, `--version` and read-only backend commands from this ZIP.
3. **Release distribution smoke (Windows):** elevated GUI starts from unelevated PowerShell via a UAC prompt; denial exits cleanly; already-elevated launch is prompt-free. Open a verified earlier `2.2.0` assessment **read-only first**. Review all linked WCR cards, queue filters, manual-completion separation, supporting report previews and optional Evidence & Guidance without saving over test data. Verify integrity and a Client Appendix export with source manifest unchanged.
4. **Clean VM/compatibility:** fresh tool/detection install walkthrough, localhost access and credentials handling, and a completed legacy v2.1.x assessment inspected read-only. Reuse earlier field evidence instead of automatically repeating target installation or Procmon for an unchanged engine.
5. **Security/privacy:** keep the restricted Client Appendix evidence allowlist; verify excluded tester notes/working state, extracted private paths, raw Procmon and hidden user data. Validate `SHA256SUMS.txt` and offline links.
6. **Decisions:** Versioned v2.2.0 illustrative artwork is included in the **source** distribution and README, using the updated user-requested banner. Tester runtime behavior is unchanged. Structural report consolidation deferred; existing linked report IDs and artifacts remain intact. Obtain explicit approval of any remaining branding exception before GA.

**Accepted RC1 tester feedback (used for v2.2.0):** Fresh Windows dependency setup completed, `--help`/`--version` returned 2.2.0, UAC launched the elevated GUI, and a prior Full Assessment opened without issues. Earlier M2-p4/p5 field tests covered Full Assessment/Guided Runtime/export and UAC denial/already-elevated paths. The production source/tester distributions differ from the accepted RC1 only in release documentation, artwork and packaging. No assessment engine or GUI modules changed. Each new tester VM still requires appropriate dependency/tool/permissions checks.
