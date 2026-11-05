# WinClientAssess (WCA) — Windows Client Assessment

**Version:** v2.2.3 · **Author:** Matthew B. · **Platform:** Windows 11 x64

WCA is a local Windows thick-client assessment framework for authorized MSI/EXE and portable-application testing. It combines static package review, tester-controlled full installation/runtime observation, scoped filesystem and registry inspection, PE and component analysis, a browser-based Tester Workspace, evidence provenance, and sanitized Client Appendix exports. The web interface is served only on localhost with a session-token URL. WCA never installs, authenticates to, or exploits the target for you.

## Getting started

1. Extract `WCA-v2.2.3-Tester.zip` to a trusted folder on Windows 11. Do not run inside the ZIP. See [Windows environment setup](docs/windows-environment-setup.md) for Python, 7-Zip, optional Sysinternals and VM preparation.
2. In Windows PowerShell from the extracted folder, run:

```powershell
.\install_dependencies.ps1
python .\wca.py --version
python .\wca.py
```

3. Approve UAC if starting the GUI from a standard shell. Keep the elevated WCA console open and use its complete private `http://127.0.0.1:9001/#session=...` URL. `--cli` launches the terminal interface; `--help` and `--version` do not require elevation. `--gui` remains a compatibility alias.
4. Use **Tool Readiness** to configure the locations of optional installed tools; WCA does not download or install them automatically. Local `tool_paths.json` is private and is never part of release or client evidence.
5. Create a **Static** or **Full** assessment, following the checkpoints. Full-mode installation and Guided Runtime are explicitly tester-controlled; Static mode does not collect runtime artifacts.
6. In **Tester Workspace → Testing Queue**, inspect case-specific evidence and linked WCR candidates, perform applicable manual checks, and save their independent decisions. Reviewer notes remain optional. Interpretation examples appear beside the relevant procedure steps.
7. Verify assessment integrity; then export and inspect the sanitized **Client Appendix**. WCA candidates and mitigation observations are not automatically validated vulnerabilities.

See [Getting Started](docs/getting-started.md), [GUI Guide](docs/gui-guide.md), [Usage](docs/usage.md), [Methodology](docs/methodology.md), [Structured Secrets](docs/secrets-review.md), [Artifact Policy](docs/artifact-policy.md), and [Troubleshooting](docs/troubleshooting.md).

## What's new in v2.2.3

- Evidence-first manual test cases with contextual ACL, registry, named-pipe, PE and runtime examples; selected-target attribution and optional read-only rechecks.
- Improved ACL visibility for selected files and their parents, plus more accurate network PID/endpoint correlation.
- A single network WCR for equivalent IPv4/IPv6 wildcard listeners, preserving original decisions and notes in review history and requiring a new combined disposition.
- Clearer CFG/ASLR/DEP guidance, compact DUMPBIN results, direct DUMPBIN evidence ZIP export, and official advanced-analysis tool references in the applicable procedure.
- More discriminating embedded-secret candidate validation, with persistent evidence redaction and a dedicated review interface.
- Multiple Guided Runtime observation sessions, more explicit collection provenance, non-target activity attribution, and context for potential process crashes.
- Cleaner Tester Workspace navigation, optional Tool Readiness download references, and report search/path controls.

## Security, privacy, and limitations

The tool runs with elevated rights when required. Protect the local machine, private session URL, assessment artifacts and optional manual evidence. Collected evidence is historical until independently revalidated; privileged-token observations do not establish standard-user effective access. Missing hardening flags, wildcard listeners, suspected secrets and noisy Procmon events require context and testing before reporting a security issue. The Client Appendix intentionally excludes raw full-host Procmon data and private working state. See [Security](SECURITY.md), [Integrity](docs/assessment-integrity.md), and [Client Appendix](docs/client-appendix.md).

## Distribution

- **`WCA-v2.2.3-Tester.zip`** — Windows-ready tester package, with application code, setup tools, operational documentation and optional PoC helpers; excludes regression tests and release-development checklists.
- **`WCA-v2.2.3-Source.zip`** — same application with Python regression tests for maintainers and developers.
- **`WCA-v2.2.3-SHA256SUMS.txt`** — SHA-256 checksums of the release ZIPs.

The v2.2.3 RC1 Windows acceptance run was reported successful by the assessor. Portable regression, package integrity and link checks were performed during release packaging; these do not replace a clean-machine verification of the final ZIP bytes.

License terms are in [LICENSE](LICENSE).
