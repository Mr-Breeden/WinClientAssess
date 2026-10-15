# WCA — Windows Client Assessment

**Version:** v2.1.0 · **Author:** Matthew B. · **OS:** Windows 11 x64 · **Deployment:** locally hosted browser GUI and CLI

WCA supports authorized assessments of Windows installable MSI/EXE clients and portable EXE/application directories. It combines static analysis, tester-controlled installation snapshots, Windows runtime and IPC inspection, Guided Review, evidence integrity, execution-derived collection provenance and a separately sanitized Client Appendix. The default GUI runs locally on `127.0.0.1:9001` with offline assets. It does **not** automatically install, launch, authenticate to, or exploit targets; testers control every target action and PoC.

## Get started on a Windows 11 VM

1. Follow [Clean Windows VM Setup](docs/windows-environment-setup.md) for OS preparation, required and optional tools, Python, Sysinternals, and snapshot guidance. For the short version see [Getting Started](docs/getting-started.md).
2. Extract **WCA-v2.1.0.zip** to a tester-approved directory. Never run it from inside the archive. Copy `tool_paths.example.json` to `tool_paths.json` **only when custom paths are needed**; do not include that private file in a release or client deliverable.
3. Open Windows PowerShell in the WCA directory. Full system-state and Procmon workflows require elevation.

```powershell
.\install_dependencies.ps1
python .\wca.py --version
python .\wca.py --gui
```

The GUI prints a private local URL; keep the complete `#session=` fragment. Keep the hosting PowerShell window open; background collectors execute without opening another terminal. Use `python .\wca.py` for the fully supported CLI instead. To change the local GUI port use `python .\wca.py --gui --port 9002`.

## Everyday workflow

1. **New Assessment:** choose installable/portable target, Static or Full mode, output folder, and optional collection checkboxes. Static mode does not prompt to install or run the client.
2. **Full mode:** WCA takes a baseline snapshot, pauses for you to install and exercise the client, and continues only after explicit browser confirmation. Network/IPC and optional Procmon collection follow your preselected choices. If Procmon is selected, stop the capture deliberately.
3. **Overview:** monitor background jobs, checkpoints, recent assessments, completion, coverage, integrity and runtime observation history. Page navigation/refresh does not stop the worker while the GUI server remains running.
4. **Guided Runtime Observation:** on a **completed, integrity-verified, same-version Full assessment**, start additional target-scoped capture and press **Stop Guided Runtime Observation** to trigger processing. A previous session does not prevent another. Cross-version evidence modifications remain blocked.
5. **Guided Review:** follow the candidate-specific validation guide; sections expand independently. Save dispositions and optional notes through an explicitly verified operation. A `VALIDATED` choice does not establish exploitability by itself.
6. **Client Appendix:** export a reviewed, integrity-verified and sanitized ZIP. Source snapshots and raw full-host Procmon evidence are excluded; validate deliverables before sharing.

## Requirements and optional capabilities

**Core:** Python 3.10+, Windows PowerShell, 7-Zip, dependencies in `requirements.txt`. Recommended integrated utilities include Sysinternals Procmon/AccessChk/Handle/ListDLLs, Detect It Easy, lessmsi and ILSpyCmd (with a suitable .NET SDK). Some utilities need elevation; absent optional utilities degrade specific coverage rather than implying a vulnerability. See [Optional Tools](docs/optional-tools.md), [Windows Setup](docs/windows-environment-setup.md), and [Tool Readiness in the GUI](docs/gui-guide.md). `install_dependencies.ps1` installs Python packages, **not** third-party desktop tools.

## Verification and release acceptance

```powershell
.\install_dependencies.ps1 -TestDependencies
.\scripts\validate_windows.ps1
python .\wca.py --backend-action capabilities --backend-format text
```

The validation script enforces Python exit codes, runs the test suite and release audit, and checks CLI/backend metadata. A full Windows GUI/Procmon acceptance test is separate; see [Windows Acceptance Checklist](docs/windows-validation.md). **v2.1.0 was accepted as the project baseline on October 15, 2026**, following 427/427 Windows regression tests, a PASS release audit, and review of the full-mode Windows assessment and Client Appendix artifacts. This baseline designation is not a claim that all live GUI acceptance cases or clean-VM walkthroughs have been completed. Those checks remain documented in the Windows acceptance checklist.

## Evidence provenance (v2.1.0 accepted baseline)

Applicable technical evidence `.txt` reports (not summaries, test cases, or tester review) now reference a central `reports/collection_provenance.txt` with the **actual tools and sanitized command structures** recorded during assessment. Where a curated read-only live-recheck command exists, it is explicitly labeled as an independent manual example, not as an executed WCA command. Native Python analysis and skipped collectors are differentiated from external invocations; raw PowerShell scripts and sensitive arguments are never retained. The separate working-state JSON preserves stable execution references through Guided Runtime and review regeneration, and the Client Appendix receives only the allowlisted sanitized `.txt`. See [Collection Provenance](docs/collection-provenance.md).

## Documentation

- [GUI User Guide](docs/gui-guide.md) · [CLI Usage](docs/usage.md) · [Guided Runtime](docs/guided-runtime.md) · [Guided Review](docs/guided-review.md)
- [Assessment Methodology](METHODOLOGY.md) · [Artifact Catalog](docs/outputs.md) · [Integrity and Recovery](docs/assessment-integrity.md) · [Client Appendix](docs/client-appendix.md)
- [Backend Service](docs/backend-service.md) · [Troubleshooting](docs/troubleshooting.md) · [Release Notes](RELEASE_NOTES.md) · [Changelog](CHANGELOG.md)

**Security and privacy:** Local GUI is bound to loopback with a session token and request checks, but the private URL is an access credential. WCA retains distinct internal evidence under `working/` and tester-facing reports under `reports/`. Review exports for engagement-specific sensitive data. WCA is an assistance tool; findings require human verification.
