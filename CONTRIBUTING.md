# Contributing to Windows Client Assessment

Windows Client Assessment favors conservative changes because assessment outputs are used as evidence and tester guidance.

## Before making a change

- Preserve the distinction between **points of interest** and confirmed vulnerabilities.
- Do not turn certificate/signature absence, writable paths, missing DLL lookups, listeners, named pipes, or updater indicators into confirmed findings without validation logic.
- Preserve static/full artifact applicability.
- Avoid persisting tester workstation identity or unnecessary system metadata.
- Prefer shared evidence/collection helpers over repeating Windows/PowerShell queries in multiple modules.
- Missing optional tools should normally result in `WARN`/`SKIPPED`, not a hard failure.

## Development setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Pull requests

A pull request should include:

- a concise problem statement;
- why the change belongs in the framework;
- tests for bug fixes or behavior changes;
- confirmation that static mode does not create non-applicable artifacts;
- confirmation that `test_cases.txt` only references applicable/generated evidence;
- confirmation that human-readable reports do not contain literal `\\n` formatting regressions;
- Windows 11 validation for changes that touch PowerShell, snapshots, services/tasks, ACLs, Procmon, or IPC.

## Versioning

Windows Client Assessment follows semantic versioning:

- `1.0.x` — compatible bug/maintenance fixes;
- `1.x.0` — backward-compatible feature additions;
- `2.0.0` — major workflow/architecture changes.
