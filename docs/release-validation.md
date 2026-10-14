# WCA v2.0.5 — Release Validation Policy

- Validate the source and an independently extracted release ZIP with `python -m pytest -q` and `python scripts/package_release.py --audit-only`. `scripts/validate_windows.ps1` runs both with explicit exit-code handling and verifies metadata.
- Source `wca.VERSION`, `pyproject.toml` and the PowerShell validation regex must agree on **2.0.5**. Regression tests reject mismatches.
- Compare against the previous release, documenting any modified assessment modules and their exact impact. Do not modify a validated collector unnecessarily.
- On Windows, validate a real browser-controlled Procmon Start → Capture → Stop → Process cycle; a mocked callback does not substitute for actual collection.
- Confirm target-specific ACL scope does not grow to include unrelated software updates, while preserving target service/task and runtime DLL candidate evidence. The original differential remains available.
- Complete a clean Windows VM setup walkthrough using [the installation guide](windows-environment-setup.md), and confirm installer, GUI, external-tool paths, CLI, integrity, reports and Client Appendix instructions are accurate.
- Report Windows validation separately from portable tests. Retain the last accepted release until v2.0.5 passes Windows native acceptance.
