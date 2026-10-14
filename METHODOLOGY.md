# WCA — Windows thick-client assessment methodology

WCA is an evidence collector and manual-validation assistant for **authorized** Windows thick-client testing. Assessment state, automated review candidates, tester dispositions and eventual penetration-test findings are separate concepts. It does not automatically declare a vulnerability from a pattern match, observed event, misconfiguration indicator, or tester-selected `VALIDATED` disposition.

## 1. Define target scope

Identify the intended Windows application and approved workflows. Select **installable** (MSI/installer EXE) or **portable** (standalone EXE or directory with an explicit primary executable), then choose **static** or **full** mode. The primary target binary is identity-pinned by SHA-256; unrelated host/application activity is not promoted without corroborating target identity.

## 2. Static evidence

Collect metadata, package structure and signature status, PE mitigations, managed .NET binaries/first-party decompiled-source review, Electron indicators where applicable, configuration and potential-secret **locations**, component life cycles and updater surfaces. Installer-specific extraction/MSI checks do not run for portable-only targets. Pattern matches are bounded code-navigation leads and include appropriate coverage limitations.

## 3. Full-mode lifecycle

Capture the baseline Windows state, pause while the **tester** installs or exercises the target, collect the post-activity state, and correlate target-associated changes: services, tasks, drivers, startup/persistence, filesystem/registry differential, permission boundaries, updater behavior and local storage. A recorded temporal difference without target attribution is not a confirmed application issue. Snapshot/checkpoint safety is enforced before resume.

## 4. Optional runtime and attack surfaces

Target-scoped Procmon and current-system-state observations may cover processes and verified helpers, DLL/EXE search activity, registry/file I/O, named pipes/IPC, listening network endpoints, native/.NET behavior, and applicable memory/cryptographic/input-handling validation guidance. External editors launched by the app can be recorded as **direct launches** without promoting their independent descendant activity. `attack_surface_test_plan.txt` describes the 26 current vendor-neutral surfaces and remains extensible; it does not claim exhaustive vulnerability detection.

## 5. Tester validation

A tester uses the evidence guide and source reports to assess reachability, lower-trust control, authorization, affected identity, actual operation, and security impact. Explicitly distinguish observed condition, validation steps, observed result, and reportable vulnerability. PoC scripts/build instructions are provided only as tester-initiated resources; WCA never launches exploits, compiles/runs PoCs, restarts services, or changes the assessed host to trigger vulnerabilities.

## 6. Integrity, completion and deliverables

Only valid, completed evidence produces a final manifest. Guided Review saves one of `PENDING`, `VALIDATED`, `NOT APPLICABLE`, `INFORMATIONAL` with optional notes. The offline tester HTML is derived from the assessment. Client Appendix export is an explicit, integrity-verified and review-gated copy of a **strictly approved** sanitized evidence set; source snapshots, tester notes, raw procmon data, decompiled sources and unapproved reports are excluded.

## 7. Methodology quality boundaries

`COMPLETE` means requested collection stages completed, not that all possible weaknesses have been assessed. Missing optional tools, bounded decompilation budgets, unobserved runtime workflows, and incomplete access can create gaps. Retain accurate coverage labels. Normalize tester-specific paths and keep potential secrets redacted. Use the separate penetration-test report for independently validated vulnerabilities and evidence-based risk ratings.

See [the detailed methodology](docs/methodology.md), [attack-surface coverage](docs/attack-surface-coverage.md), [assessment lifecycle](docs/assessment-lifecycle.md) and [backend service contract](docs/backend-service.md).
