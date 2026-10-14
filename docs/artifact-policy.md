# WCA artifact policy

**Current artifact catalog:** 1.8

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

The distributed source ZIP contains current source, canonical documentation, current regression tests, the current Windows validation script and operational `scripts/poc/` resources. It excludes generated/cache/build metadata, historical duplicate validation docs/scripts, prior release ZIP/checksum artifacts and temporary assessment output.

`scripts/package_release.py` enforces an explicit allowlist and fails closed on unexpected carryover.
