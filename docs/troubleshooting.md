# WCA troubleshooting

## Dependency/setup problems

Run `install_dependencies.ps1`, verify Python imports, and review `docs/optional-tools.md`. Missing optional tools should produce accurate WARN/SKIPPED/UNAVAILABLE behavior rather than fabricated coverage.

## Full-mode baseline failure

Do not continue with target activity/system-state analysis if the Baseline Snapshot failed. Revert the VM to the known-good snapshot and start a new assessment. A damaged critical checkpoint is not repaired automatically.

## Portable directory has multiple executables

Interactive mode prompts for the primary executable. In non-interactive mode supply `--primary-executable`. Do not select a setup/uninstaller/helper executable merely to avoid the prompt; choose the process that represents the primary assessed application.

## Guided Runtime takes several minutes after Enter

Large Procmon traces require export and filtering. WCA prints stop/export/sanitization/analysis stages and elapsed-time heartbeats. Allow processing to complete unless the bounded export limit is exceeded. A partial failure should retain capture duration/size and identify the failed stage rather than reporting misleading zero-duration success.

## Unexpected host processes or storage in target evidence

Check `runtime_targets.txt`, `application_scope.txt`, `application_profile.txt` and `local_storage_review.txt`. Target discovery requires stronger static/system-state/service/task/root/runtime association and should not promote unrelated host maintenance merely because it appeared in a broad baseline/post-activity differential.

## PoC helper path confusion

Live Guided Review shows the actual WCA tool/source path. Persisted guidance uses a privacy-safe tool-directory representation. PoC resources are **not** stored in the assessment output directory.

C helpers require manual compilation. Use the candidate-specific PoC Resource section for architecture/build/output/verification commands. PowerShell helpers show direct invocation. WCA never compiles or executes them automatically.

## Integrity failure

Run Assessment Status or `--verify-assessment`. Regenerate only derived reports when WCA explicitly determines that primary state/evidence remains intact. Do not use regeneration to hide snapshot/source-evidence corruption.

## Unexpected/stale files in a source release

```powershell
python .\scripts\package_release.py --audit-only
```

Current packages exclude historical duplicate validation files, `*.egg-info`, build/cache/venv artifacts, old release ZIP/checksum files and temporary assessment outputs.

## Privacy

Original imported evidence and extracted third-party payloads can contain sensitive data outside WCA's recognized sanitization patterns. Keep complete assessment folders access-controlled and do not treat them as client-ready exports.

## Procmon active but GUI statistics unavailable (corrected v2.1.0)

Windows antivirus or another local process may transiently prevent replacement of temporary GUI-only `telemetry.json`. The corrected worker issues a sanitized warning and keeps Procmon capture running; use the Stop Guided Runtime Observation button when the capture checkpoint is active. Do not equate a momentary missing statistics card with a failed capture. After processing, verify that the Guided Runtime report records capture PASS and target-scoped Procmon events, with integrity PASS. If capture itself fails, preserve the assessment and logs; do not force a finding or recertify damaged evidence.

## GUI action rejected

Open **Notifications** in the top bar. The error displays the attempted operation, code, outcome (`NOT CONFIRMED` for rejected or uncertain writes), and a safe next step. Verify the authoritative assessment state before repeating review saves or exports. Notifications do not include arbitrary filesystem paths or tester notes in diagnostics, and they are not stored with assessment evidence.

## Recent Assessments contains `case` test entries

Prior v2.1.0 regression tests could register temporary test cases. The corrected package isolates its GUI test catalogs. Entries from an older run remain until removed manually: back up `%LOCALAPPDATA%\WCA\gui_recent.json` and remove only that tester-local index while the GUI is stopped; this does not remove assessment evidence. Reopen valid assessment directories to re-register them.
