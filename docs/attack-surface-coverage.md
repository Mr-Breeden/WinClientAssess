# Windows Thick Client Attack Surface Coverage

WCA uses a **vendor-neutral, extensible attack-surface methodology** for Windows thick-client testing. The categories in `attack_surface_test_plan.txt` are a structured checklist and guidance system, not a claim that every weakness can be automatically detected or that the current taxonomy is exhaustive.

## Coverage states

WCA separates evidence collection from security conclusions. Depending on the surface, the plan/report can represent:

- **AUTOMATIC INDICATOR - MANUAL VALIDATION REQUIRED** — collected evidence matched a conservative indicator; tester validation is still required.
- **GUIDED / MANUAL VALIDATION** — the surface is relevant to thick-client testing but requires tester-directed discovery or proof rather than an automatic detector.
- **NOT OBSERVED IN COLLECTED EVIDENCE** — applicable telemetry was collected but the condition was not observed.
- **NOT COLLECTED / SKIPPED** — an optional phase was not run.
- **COLLECTION UNAVAILABLE** — the required telemetry/tooling/evidence was unavailable or failed.

None of these states alone proves that a vulnerability exists or does not exist.

## Current methodology areas

The generated attack-surface plan currently addresses:

1. DLL search-order hijacking.
2. Executable/helper search-path hijacking.
3. Reparse point / symlink / junction abuse.
4. IFEO / SilentProcessExit injection.
5. Service path and configuration abuse.
6. Scheduled-task privilege boundaries.
7. Driver and kernel-facing attack surface.
8. COM registration and activation hijacking.
9. Registry persistence and execution abuse.
10. Process creation and command construction.
11. Process injection and cross-process memory access.
12. Named-pipe and local IPC authorization.
13. Localhost service / local API authorization.
14. Network transport and remote trust.
15. Local storage, embedded secrets and information disclosure.
16. Update mechanism integrity, staging and rollback.
17. Digital signing and provenance.
18. PE exploit mitigations and memory hardening.
19. Stack memory corruption.
20. Heap memory corruption.
21. Cryptography and key management.
22. Installer and custom-action privilege boundaries.
23. .NET / managed runtime dynamic behavior.
24. Electron / WebView / embedded-browser surface.
25. Authentication, authorization and client-side trust.
26. Input handling and local data-access flaws.

Future releases may add, split or refine surfaces as the framework expands. Testers should still apply application-specific threat modeling and professional judgment.

## Automation boundaries

WCA may correlate a missing DLL/EXE lookup, risky ACL, service/task/driver context, network/IPC surface, PE hardening state, storage indicator or other evidence into a review candidate. It does not silently turn that observation into a finding.

Memory corruption, process injection, COM activation abuse, protocol trust, authorization flaws and similar areas often require manual validation. WCA provides read-only starting checks and controlled proof guidance where practical, but the tester performs any invasive action explicitly.

## Proof guidance

When a proof resource applies, WCA can provide:

- candidate-specific path/process/service/pipe/port context;
- prerequisites and read-only checks;
- PoC source/script location;
- build or invocation instructions;
- architecture information when reliably available;
- expected proof marker/evidence;
- secure/vulnerable interpretation;
- conditions under which the observation should **not** be reported.

WCA never compiles or executes proof resources automatically.
