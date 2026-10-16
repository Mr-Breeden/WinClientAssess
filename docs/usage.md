# WCA usage

WCA supports interactive and CLI-driven static/full Windows client assessments. The primary launcher is `wca.py`; `pip install .` also exposes the `wca` console command.

## Local browser GUI (v2.1.0)

```powershell
python .\wca.py --gui
# Alternate loopback port:
python .\wca.py --gui --port 9002
```

GUI runs only on `127.0.0.1`. Full assessments and Guided Runtime now run in a background Python worker with explicit browser checkpoints and live status; no additional terminal is opened. GUI use on Windows requires acceptance testing; see [GUI guide](gui-guide.md). `--no-gui` continues to mean **disable native file pickers in the CLI** and is not a synonym for `--gui`.

## Interactive workflow

```powershell
python .\wca.py
```

The main menu provides Start New Assessment, Assessment Status, Guided Tester Review, Guided Runtime Observation, Export Client Appendix, and Exit. Native Windows file/folder pickers are used when available; `--no-gui` forces text prompts.

During a new assessment WCA asks for the target type:

- installable MSI/installer EXE; or
- portable EXE/application directory.

## Installable target examples

Static:

```powershell
python .\wca.py `
  --target-type installable `
  --target 'C:\Installers\ClientSetup.msi' `
  -n 'Client-Static' `
  -o 'C:\Assessments' `
  -m static `
  --no-gui
```

`-i/--installer` remains accepted for backward-compatible installable input.

Full:

```powershell
python .\wca.py `
  --target-type installable `
  -t 'C:\Installers\ClientSetup.exe' `
  -n 'Client-Full' `
  -o 'C:\Assessments' `
  -m full `
  --runtime-capture `
  --surface-review `
  --target-only
```

WCA pauses for the tester to install the application manually.

## Portable target examples

Standalone executable:

```powershell
python .\wca.py `
  --target-type portable `
  -t 'C:\Tools\PortableClient\Client.exe' `
  -n 'Portable-Static' `
  -o 'C:\Assessments' `
  -m static `
  --no-gui
```

Application directory:

```powershell
python .\wca.py `
  --target-type portable `
  -t 'C:\Tools\PortableClient' `
  --primary-executable 'Client.exe' `
  -n 'Portable-Full' `
  -o 'C:\Assessments' `
  -m full `
  --surface-review `
  --target-only `
  --no-gui
```

If an interactive portable directory contains more than one EXE candidate, WCA prompts the tester to choose the primary executable. Non-interactive use must specify `--primary-executable` when the choice is ambiguous.

Full portable mode pauses after the baseline so the tester can manually launch/exercise representative workflows. WCA does not launch, authenticate to, update or exploit the application automatically.

## Useful assessment options

- `--no-extract`
- `--application-dir DIRECTORY`
- `--no-filesystem-snapshot`
- `--runtime-capture`
- `--runtime-seconds N`
- `--procmon-csv FILE`
- `--surface-review`
- repeatable `--exclude-path PATH_OR_GLOB`
- `--target-only`

Run `python .\wca.py --help` for authoritative syntax.

## Assessment status and integrity

```powershell
python .\wca.py --status C:\Assessments\Client-Full
```

Assessment Status reports lifecycle/checkpoint state and automatically verifies integrity. Safe report-only regeneration is offered only when derived reports are damaged and authoritative supporting evidence verifies intact.

```powershell
python .\wca.py --verify-assessment C:\Assessments\Client-Full
python .\wca.py --regenerate-reports C:\Assessments\Client-Full
python .\wca.py --resume C:\Assessments\Client-Full
```

Cross-version resume remains conservative.

## Guided Runtime Observation

```powershell
python .\wca.py --guided-runtime C:\Assessments\Client-Full
```

Eligibility requires a completed, integrity-PASS full assessment created by the active framework version. The tester exercises applicable workflows and presses **Enter once** when finished. Raw/full-host capture remains temporary; only target-scoped sanitized evidence is retained.

## Guided Tester Review

```powershell
python .\wca.py --review C:\Assessments\Client-Full
```

Review states are `PENDING`, `VALIDATED`, `NOT APPLICABLE` and `INFORMATIONAL`. Tester notes are optional. Use **8** for candidate-specific validation guidance and **C** to copy unwrapped Windows checks. WCA never executes copied commands or PoC resources.

## Imported Procmon evidence

```powershell
python .\wca.py `
  --target-type installable `
  -t 'C:\Installers\ClientSetup.exe' `
  -n 'Client-Procmon' `
  -o 'C:\Assessments' `
  -m full `
  --procmon-csv 'C:\Evidence\client-procmon.csv'
```

Original imported evidence is not modified. WCA produces sanitized/target-scoped derived evidence where required.

## Privacy

Portable reports avoid persisting the tester's personal username, hostname, original personal source/package location, raw process environment and secret values where those fields are not security-relevant. Service/task run-as identities are retained where they matter to the security boundary.

## Reviewed Client Appendix

```powershell
python .\wca.py --client-appendix 'C:\Assessments\Client-Full' --appendix-output 'C:\Deliverables\Client-Appendix.zip'
```

This is a copy-only, gated technical appendix, not a vulnerability report. Export requires a completed, integrity-PASS assessment and fully processed Guided Review with no pending or changed-evidence conditions. The destination must be outside the source assessment. See `client-appendix.md`.

## JSON-safe status and tool readiness (v2.1.0)

For a read-only frontend, use `python .\wca.py --backend-action capabilities` and `--backend-action status --backend-assessment C:\Assessments\Case`. Other read-only operations: `tool_readiness`, `verify`, `review`, `appendix_readiness`. JSON output contains `schema`, `ok`, `code`, `message`, `data`, and `errors`; this does not launch a GUI. See `docs/backend-service.md`.


### Windows Administrator privilege preflight (M2-p5)

On Windows, `python .\wca.py --gui` requests UAC elevation at startup when launched from a normal user console. UAC approval launches a new WCA process using the current Python interpreter, same arguments, and current working directory; use the new elevated console's private GUI URL. Canceling UAC cleanly exits without starting the GUI. Full-mode CLI and standalone Guided Runtime request elevation as needed; background GUI workers do not invoke UAC. Read-only CLI operations, `--help`, `--version`, and static-mode CLI do not require Administrator privileges. If the elevated token is still unavailable, WCA refuses to enter a UAC prompt loop.
