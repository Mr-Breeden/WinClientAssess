# WCA artifact policy

**Current artifact catalog:** 2.0 (framework v2.2.0; historical 1.8 changes documented below)

WCA keeps an artifact only when it has a distinct tester, evidence, correlation, integrity, recovery or reproducibility purpose.

## Tester-facing interpretation

When analysis is already represented by an authoritative readable `.txt` report, WCA generally does not keep a duplicate interpreted JSON/CSV copy. Examples include network surface, installation/system differential and PE security review.

## Structured evidence that remains

Structured/raw forms are retained when they have a distinct operational purpose, including:

- assessment/review/integrity state;
- baseline/post-activity snapshots;
- static file inventory used for target correlation;
- extracted payloads needed for verification/analysis;
- target-scoped sanitized Procmon evidence needed for runtime reproducibility/correlation.

Raw/full-host Procmon capture is temporary and discarded after successful target-scoped sanitization.

## v1.8.2 catalog changes

- Added `target_analysis.txt` for portable target identity.
- Renamed fixed known-vulnerability outputs to `attack_surface_correlations.txt` and `attack_surface_test_plan.txt`.
- Retained compatibility filenames such as `install_changes.txt`, `installed_files.txt`, `snapshot_pre.json` and `snapshot_post.json`; their tester-facing meaning is generalized to baseline/post-activity system-state analysis for portable targets.
- `secrets_review.txt` now supports PE printable-string indicator locations while continuing to redact matched values.

## Privacy boundary

Portable assessment artifacts should not persist tester username/hostname, personal source/package paths, raw environment data or actual secret values unless a field is security-relevant and explicitly required. Service/task security identities can remain when they define the trust boundary.

## Source release package

The GitHub source ZIP contains current source, canonical documentation, current regression tests, the current Windows validation script and operational `scripts/poc/` resources. It excludes generated/cache/build metadata, historical duplicate validation docs/scripts, prior release ZIP/checksum artifacts and temporary assessment output.

`scripts/package_release.py` enforces an explicit allowlist and fails closed on unexpected carryover. The separate minimal tester ZIP excludes tests, development/packaging tools, machine-specific configuration and generated assessment evidence while retaining assessment functionality and tester PoC helpers.

### v2.1.0 collection provenance exception

`reports/collection_provenance.txt` is the single authoritative human-readable provenance report. `working/collection_provenance_state.json` is **not** a duplicate report: it preserves append-only stable execution identifiers through later Guided Runtime sessions and derived-report regeneration. It is operational working state, integrity verified, and never included in the client export. Raw binary, CSV and JSON evidence must not have embedded provenance headers.

## M2-p3 audit / consolidation boundary

A report-by-report audit against the M2-p2 DarkRelay Full Assessment inventories 70 distinct report files and maps consolidation options. No report is removed or combined until producer/consumer mappings, tester procedure links, integrity manifests, provenance references and legacy assessment compatibility are migrated and regression-tested. Keep the separate client allowlist and only one working JSON/CSV per distinct correlation or recovery need. This is a deliberate compatibility safeguard, not a requirement to generate more reports.
