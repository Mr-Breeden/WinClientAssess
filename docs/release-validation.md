# WCA v2.1.0 — Release Validation Policy

- Validate the source and an independently extracted release ZIP with `python -m pytest -q` and `python scripts/package_release.py --audit-only`. `scripts/validate_windows.ps1` runs both with explicit exit-code handling and verifies metadata.
- Source `wca.VERSION`, `pyproject.toml` and the PowerShell validation regex must agree on **2.1.0**. Regression tests reject mismatches.
- Compare against the previous release, documenting any modified assessment modules and their exact impact. Do not modify a validated collector unnecessarily.
- On Windows, validate a real browser-controlled Procmon Start → Capture → Stop → Process cycle; a mocked callback does not substitute for actual collection.
- Confirm target-specific ACL scope does not grow to include unrelated software updates, while preserving target service/task and runtime DLL candidate evidence. The original differential remains available.
- Complete a clean Windows VM setup walkthrough using [the installation guide](windows-environment-setup.md), and confirm installer, GUI, external-tool paths, CLI, integrity, reports and Client Appendix instructions are accurate.
- Report Windows validation separately from portable tests. v2.1.0 was accepted as the project baseline on October 15, 2026 after 427 Windows regression tests passed and its full-mode assessment artifacts were reviewed. Outstanding live GUI and clean-VM checks must be labeled as pending, not implied to be completed.
