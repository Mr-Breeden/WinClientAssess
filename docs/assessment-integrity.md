# WCA assessment integrity and safe regeneration

Completed structured assessments use `working/assessment_manifest.json` to record SHA-256/size information for retained reports, authoritative supporting state/evidence and extracted/decompiled payloads where applicable.

## Verification

```powershell
python .\wca.py --verify-assessment C:\Path\To\Assessment
```

Assessment Status also performs integrity verification automatically.

Verification checks report artifacts, supporting state/evidence, payload inventory, mode/catalog consistency and stale atomic-write temporary files.

## Safe regeneration

Derived TXT/HTML may be regenerated only when authoritative state, snapshots, source-backed evidence and retained payloads verify intact. WCA does not fabricate or repair corrupt snapshots, missing source evidence or damaged review-state JSON.

Regeneration is explicit and confirmed; it is never a silent repair action.

## Snapshot recovery

Successful pre/post snapshots are pinned for recovery. An incomplete or modified critical snapshot blocks resume. Cross-version resume is conservative and never silently migrates checkpoint evidence.

## Trust boundary

The manifest protects against accidental or ordinary tampering but is not a cryptographic signature held outside the assessment. Where independent non-repudiation is required, retain an external signed/checksummed copy according to engagement policy.
