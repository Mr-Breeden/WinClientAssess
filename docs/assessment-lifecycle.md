# WCA assessment lifecycle and recovery

Structured assessments separate tester-facing `reports/` from authoritative/supporting `working/` data.

## Target-aware lifecycle

Both installable and portable full assessments use the same conceptual lifecycle:

1. target/static analysis;
2. **Baseline Snapshot**;
3. tester-controlled target activity;
4. **Post-Activity Snapshot**;
5. **System Change Analysis**;
6. optional runtime/surface work;
7. reporting/integrity;
8. completion.

For an installable application, target activity is installation. For a portable application, target activity is launch/exercise of representative workflows. WCA never performs that activity silently.

Internal checkpoint identifiers retain some historical names so existing structured assessments remain readable; tester-facing status/guidance uses the generalized terminology.

## Recovery rules

State is written atomically. Resume is allowed only from checkpoints supported by verified evidence. WCA never reconstructs a baseline after target activity may already have occurred.

Use:

```powershell
python .\wca.py --status C:\Path\To\Assessment
python .\wca.py --resume C:\Path\To\Assessment
```

Examples:

- incomplete baseline → halt/revert to clean VM;
- valid baseline + confirmed target activity but no post-activity snapshot → resume post-activity capture on the unchanged VM;
- verified baseline/post-activity state → system-state and optional runtime/report work may be regenerated where supported;
- corrupted primary snapshot/source evidence → no unsafe automatic repair.

Completed assessments report no recovery action unless safe derived-report regeneration is available.

Legacy flat assessments remain readable where supported but are not silently overwritten or converted.

## v2.0.5 state contract for CLI and local GUI

`BackendService.execute("status", assessment_dir)` exposes the existing checkpoint state and derived eligible actions without persisting a second state format. Read-only status/integrity calls do not mutate assessment evidence. Interrupted assessments from a different framework version are **not** resumed silently; use the original version on the unchanged VM. Mutations acquire an advisory per-assessment exclusive lock and recheck integrity when applicable. See `docs/backend-service.md`.
