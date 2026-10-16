# WCA v2.2.0 — Backend Service and Local GUI

## Scope and non-goals

`utils/backend_service.py` provides the **in-process** backend facade (`BackendService.execute`) for state, integrity, Guided Review, and Client Appendix. It does not open a socket or launch applications itself. The separate `utils/gui_server.py` runs the **loopback-only** HTTP GUI and enforces browser-session authorization, same-origin checks and explicit mutation transport. `utils/web_worker.py` uses a private, noninteractive Python worker for assessment and Guided Runtime jobs, delivering manual tester checkpoints through the browser **without opening a second PowerShell console**. The original CLI remains fully usable. The GUI does not automatically install, launch, authenticate to or exploit target software; the tester must explicitly perform those activities. Windows GUI and native Procmon acceptance are required for new releases.
## Stable JSON-safe responses

All service actions return one dictionary:

```json
{"schema":"1.0","ok":true,"code":"OK","message":"Capabilities available.","data":{},"errors":[]}
```

`ok=false` uses a stable code and sanitized message. Unknown failures return `OPERATION_FAILED` without surfacing operating-system paths, private usernames, secrets or exception traceback. Consumers should handle unrecognized future `code` values. `schema` is the backend API contract, **not** the legacy assessment state/manifest schema. Paths, live tool locations, tester notes and raw manifest records are not returned.

Read-only JSON command-line interface (one object on stdout; exit status 9 for failed operation):

```powershell
python .\wca.py --backend-action capabilities
python .\wca.py --backend-action tool_readiness
python .\wca.py --backend-action status --backend-assessment C:\Assessments\Case
python .\wca.py --backend-action verify --backend-assessment C:\Assessments\Case
python .\wca.py --backend-action review --backend-assessment C:\Assessments\Case
python .\wca.py --backend-action appendix_readiness --backend-assessment C:\Assessments\Case
```

## Optional human-readable output (v2.1.0)

The CLI defaults to a **single-line JSON object** so the GUI and automation remain compatible. Add `--backend-format text` to show a compact human-readable view without changing the backend response schema:

```powershell
python .\wca.py --backend-action capabilities --backend-format text
python .\wca.py --backend-action tool_readiness --backend-format text
python .\wca.py --backend-action status --backend-assessment 'C:\Assessments\CompletedCase' --backend-format text
python .\wca.py --backend-action verify --backend-assessment 'C:\Assessments\CompletedCase' --backend-format text
python .\wca.py --backend-action review --backend-assessment 'C:\Assessments\CompletedCase' --backend-format text
python .\wca.py --backend-action appendix_readiness --backend-assessment 'C:\Assessments\CompletedCase' --backend-format text
```

The text renderer displays only already-sanitized fields returned by the service. It does not include raw evidence, tester notes, raw process/manifest paths or secret values. `--backend-format json` is equivalent to omitting the flag. `--backend-format` without `--backend-action` is invalid. Errors remain nonzero-exit and use a concise code/message. Text is a presentation format, not the programmatic API.

## Operations

| Name | Read/write | Requirements and guarantees |
|---|---|---|
| `capabilities` | Read | Supported target types, modes, dispositions, operation metadata and policy |
| `tool_readiness` | Read | Tool found/level/usage only; **no machine-specific paths** |
| `status` | Read | Lifecycle, coverage, checkpoints, recovery guidance, integrity and eligible actions |
| `verify` | Read | Manifest integrity checks summarized without internal manifest material |
| `review` | Read | Requires integrity PASS; stable IDs, fingerprint tokens, titles, categories, dispositions; **no tester notes** |
| `appendix_readiness` | Read | Existing strict export readiness checks; never creates an appendix |
| `save_review` | Write | `confirmed=True`, `candidate_id`, `disposition`, and current `fingerprint` required; rechecks integrity; re-renders derived reports and re-manifests |
| `export_appendix` | Write | `confirmed=True`, external `output` ZIP path; existing finalized/reviewed/integrity/allowlist gates; source unchanged |
| `regenerate_reports` | Write | `confirmed=True`; only when original verified authoritative evidence makes repair safe |
| `run_assessment`, `guided_runtime`, `resume_assessment` | GUI worker or CLI | Interactive workflows remain tester-controlled. The GUI uses a separate local job/controller protocol, not a direct mutating `--backend-action` CLI command. |

Example trusted in-process usage:

```python
from utils.backend_service import BackendService
service = BackendService()
result = service.execute("status", r"C:\Assessments\Case")
if result["ok"]:
    print(result["data"]["integrity"]["status"])
```

Mutation calls are **not** exposed on the JSON CLI. The local GUI transport enforces local authentication/authorization and explicit user intent before calling them; the `confirmed=True` flag is an in-process assertion, not an authentication token.

## State transitions and compatibility

Existing structured assessment manifests retain schema 1, review state retains its established IDs/schema, and artifact catalog/methodology remain 1.9. v2.1.0 **does not rewrite old state on read**. Completed, intact v1.9.2 and completed v1.9.3 assessments can be inspected, verified and exported without migration. Unfinished prior-version checkpoints remain readable but **cross-version resume is blocked**; use the original version on an unchanged snapshot VM or begin a fresh assessment. Legacy flat assessments are identified but not silently converted.

Status reports the saved stage transitions (`PENDING`, `STARTED`, `COMPLETED`) and recovery action; it does not invent additional persistent lifecycle states. Allowed actions are derived from integrity/status, not trusted from stored user-supplied values. `VALIDATED` is a tester decision, not independent evidence of exploitation. The service requires an exact fingerprint on review changes to refuse decisions against changed evidence.

## Concurrency and failure policy

Each WCA mutation obtains an exclusive per-assessment OS file lock **beside** the assessment directory, preserving source tree/manifest contents. Concurrent actions fail closed with `ASSESSMENT_BUSY`; a failed operation releases its lock normally. A killed process can leave a stale lock: check the process and authoritative state/integrity before **manually** removing it. Locks are advisory, not a security boundary against arbitrary other processes or a malicious local administrator. Atomic individual file writes and post-write integrity checks remain authoritative. If a write fails partway through multi-file re-rendering, refuse further mutations until integrity/status and safe recovery have been examined.

## Testing contract

Regression tests cover JSON safety, absence of tester paths, existing assessment version read-compatibility, pending review fingerprint refusal, output confirmation, review integrity, lock contention, safe export and preservation of source bytes. Install opt-in test dependencies first (`.\install_dependencies.ps1 -TestDependencies`), then run `python -m pytest -q` and `scripts/validate_windows.ps1`, then compare CLI vs JSON status on an intact completed v1.9.2 assessment. GUI HTTP access-control tests are additional, but they do not replace native Windows acceptance or a deployment security review.

## v2.1.0 local GUI transport

Use `python .\wca.py --gui` (default `127.0.0.1:9001`), or `--port 9002`. The stdlib HTTP adapter is described in [`gui-guide.md`](gui-guide.md). JSON backend schema remains `1.0`. Explicit GUI mutations require a session token, same-origin local request, tester confirmation, per-assessment lock and backend integrity gates. GUI collection now redirects the original engine through an in-browser checkpoint protocol; the separate CLI remains available for terminal use.
