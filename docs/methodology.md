# WCA methodology

WCA provides repeatable evidence collection and triage for authorized Windows thick-client assessments. It separates **collection**, **automated review points**, **tester validation**, and eventual **client reporting**.

## Target models

WCA supports two first-class target types:

- **Installable** — MSI or installer EXE.
- **Portable** — standalone executable or application directory with a selected primary executable.

The selected target type controls applicability. Portable applications are not forced through installer/MSI logic; installable targets retain package/install analysis.

## Static analysis

Shared static analysis can include target/signature identity, application scope, PE mitigations, .NET/Electron/configuration/secrets/component-lifecycle review and updater candidate discovery without executing the target.

Installable targets additionally support installer metadata/technology, extraction and MSI table/custom-action analysis when applicable.

Portable targets add `target_analysis.txt` and directly scope the selected executable/application directory. A multi-EXE directory requires explicit primary-executable selection.

### Sensitive-string handling

Secrets Review inspects relevant text/config sources and also performs bounded printable ASCII/UTF-16LE triage on PE files. Reports retain indicator type/location/encoding and a redacted value marker, not the secret value itself. Binary-string hits are points of interest requiring tester context.

## Full-mode system-state analysis

Full mode captures a verified **Baseline Snapshot**, pauses for tester-controlled target activity, then captures a **Post-Activity Snapshot** and analyzes the differential.

For installable targets, the activity is installation. For portable targets, it is launch/exercise of representative application workflows. WCA does not perform those actions automatically.

System-state analysis covers target-associated filesystem/registry changes, services, scheduled tasks, drivers, persistence, permissions, privilege boundaries, local application storage and updater/maintenance components. Broad snapshot changes are temporal observations; target attribution requires stronger correlation.

## Runtime analysis

Optional Procmon/runtime evidence is sanitized and target-scoped before retention. Runtime analysis covers process activity, image loads, DLL/EXE search behavior, file/registry/network activity, process relationships, named pipes/network surfaces and selected native/.NET context.

Guided Runtime is tester-driven. The tester exercises the target; WCA observes and correlates. Supplemental runtime evidence refreshes local-storage review, application profile, test cases, review candidates and integrity state.

## Application profiling and local storage

`application_profile.txt` summarizes already-collected identity, technology, system footprint, runtime ownership and selected storage evidence for scoping. It is not a second raw source of truth.

`local_storage_review.txt` focuses on target-associated AppData/LocalAppData/ProgramData and registry locations. Text/config analysis records indicator locations without values; SQLite review inspects schema only. Generic Windows registry writes are not promoted merely because a target process touched them; target/product path association is required.

## Windows Thick Client Attack Surface Coverage

`attack_surface_test_plan.txt` is a vendor-neutral, extensible methodology spanning binary loading/execution, privilege boundaries, services/tasks/drivers, filesystem/reparse behavior, registry/COM, process behavior, IPC/network trust, local storage/secrets, updater integrity, signing, memory hardening/corruption, cryptography, frameworks, authentication/authorization and input/data-access risks.

The plan distinguishes automatic indicators from guided/manual validation and from unavailable/not-observed collection. It does not claim automatic exploit completeness.

## Review semantics

Automated review candidates use stable IDs and remain observations until the tester assigns a disposition. `VALIDATED` is a tester-selected status, not independent proof of exploitation. Notes are optional.

## Manual proof guidance

Candidate validation begins with evidence-specific read-only checks. When a bundled proof resource applies, WCA can provide source/script paths, compilation or invocation instructions, architecture guidance, expected evidence and interpretation. WCA does not compile or execute proof actions automatically.

## Coverage language

A `COMPLETE` collection grade means requested collection phases completed successfully. It does **not** mean every possible vulnerability was detected, disproved or exploited.

## Privacy and evidence hygiene

Portable reports normalize tester identity, hostname/personal source paths and secret values where they are not security-relevant. Service/task run-as identities are preserved when they define the security boundary. Raw PML/full-host temporary CSV is discarded after target-scoped sanitization.

## Integrity and regeneration

Assessment state and retained evidence are integrity-tracked. Derived reports can be regenerated only from verified authoritative inputs; source evidence and snapshots are never silently repaired.
