# WCA installation

WCA is designed for an authorized Windows 11 assessment VM. Keep the VM disposable/snapshot-backed because full mode intentionally observes Windows state before and after tester-controlled target activity.

## Core setup

From a fresh source extraction:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python .\wca.py --version
```

Or run:

```powershell
.\install_dependencies.ps1
```

Core Python requirements include Rich, pefile and psutil. For source development or Windows release checks, install `requirements-dev.txt` or run `.\install_dependencies.ps1 -TestDependencies` to add pytest; the standard installer intentionally does not install test-only dependencies. 7-Zip is expected for normal package/archive work. See `optional-tools.md` for external tool integrations.

## Assessment VM preparation

Before a full assessment:

- restore a known-good VM snapshot;
- copy the authorized target package/application into the VM;
- ensure sufficient disk space for snapshots, extraction and temporary Procmon capture;
- install/configure desired optional tools;
- close unrelated high-churn applications where practical;
- do not run the target before WCA captures its baseline unless the methodology for that assessment explicitly requires otherwise.

## Installable applications

Choose **installable** for MSI or installer EXE packages. WCA performs read-only static/package analysis, captures the baseline, then pauses so the tester can install the application using the approved procedure.

## Portable applications

Choose **portable** for a standalone EXE or portable application directory. If the directory contains multiple executables, identify the intended primary executable. WCA captures the baseline and then pauses so the tester can manually launch/exercise the application.

Portable mode does not invent an installation stage or treat a normal application EXE as an installer.

## External tools

WCA detects supported tools at runtime and records whether they are required, recommended, optional, integrated, fallback or manual-guided. Missing optional tools should create an accurate coverage limitation rather than a false result.

Start with [Clean Windows 11 VM setup](windows-environment-setup.md) for a complete setup checklist, then see `optional-tools.md` for supported tooling and verification commands.
