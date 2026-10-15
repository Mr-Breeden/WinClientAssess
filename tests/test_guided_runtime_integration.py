from __future__ import annotations

import csv
from pathlib import Path

from modules.guided_runtime_observation import run_guided_collectors
from modules.procmon_analysis import analyze_procmon_csv
from utils.artifacts import generated_files
from utils.privacy import current_user_sid, sanitize_report_text


def _write_procmon(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_current_tester_sid_is_normalized_but_other_sid_is_preserved(monkeypatch):
    tester_sid = "S-1-5-21-111-222-333-1001"
    service_sid = "S-1-5-18"
    monkeypatch.setenv("WCA_CURRENT_USER_SID", tester_sid)
    current_user_sid.cache_clear()
    try:
        text = sanitize_report_text(f"owner={tester_sid}; system={service_sid}")
    finally:
        current_user_sid.cache_clear()
    assert "CURRENT_USER_SID" in text
    assert tester_sid not in text
    assert service_sid in text


def test_named_pipe_write_is_not_counted_as_filesystem_write(tmp_path):
    source = tmp_path / "trace.csv"
    _write_procmon(source, [
        {"Time of Day": "1", "Process Name": "Client.exe", "PID": "10", "Operation": "WriteFile",
         "Path": r"\Device\NamedPipe\Acme", "Result": "SUCCESS", "Detail": ""},
        {"Time of Day": "2", "Process Name": "Client.exe", "PID": "10", "Operation": "WriteFile",
         "Path": r"C:\ProgramData\Acme\client.log", "Result": "SUCCESS", "Detail": ""},
    ])
    data = analyze_procmon_csv(source, [{"ProcessName": "Client.exe", "Path": r"C:\Program Files\Acme\Client.exe"}])
    assert len(data["ipc_writes"]) == 1
    assert data["ipc_writes"][0]["Path"] == r"\Device\NamedPipe\Acme"
    assert len(data["file_writes"]) == 1
    assert data["file_writes"][0]["Path"].endswith("client.log")


def test_guided_runtime_catalog_does_not_retain_full_host_capture():
    files = generated_files()
    assert "working/guided_runtime_capture.csv" not in files
    assert "working/guided_runtime_target_events.csv" in files


def test_guided_collectors_stage_only_target_scoped_csv(tmp_path, monkeypatch):
    root = tmp_path / "assessment"
    (root / "reports").mkdir(parents=True)
    (root / "working").mkdir()

    def fake_capture(assessment_dir, tools, *args, **kwargs):
        source = Path(assessment_dir) / "working" / "capture.csv"
        _write_procmon(source, [])
        return {
            "status": "PASS", "details": "ok", "csv_path": str(source), "sanitization": {},
            "session": {"started_at": "2026-10-05T00:00:00Z", "stopped_at": "2026-10-05T00:00:10Z",
                        "duration_seconds": 10, "controller": {"checklist": {}}},
        }

    def fake_analysis(assessment_dir, csv_path, runtime_targets, sanitation):
        target = Path(assessment_dir) / "working" / "procmon_target_events.csv"
        _write_procmon(target, [])
        report = Path(assessment_dir) / "reports" / "procmon_summary.txt"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("summary\n", encoding="utf-8")
        return {
            "status": "PASS", "details": "0 target events", "findings": [],
            "procmon_data": {"relevant_rows": 0, "observed_process_names": [], "file_writes": [],
                             "ipc_writes": [], "process_activity": [], "loaded_images": [],
                             "registry_writes": [], "network_activity": []},
            "observed_process_names": [], "target_filtered_path": str(target),
        }

    monkeypatch.setattr("modules.guided_runtime_observation.run_procmon_capture", fake_capture)
    monkeypatch.setattr("modules.guided_runtime_observation.run_procmon_analysis", fake_analysis)
    monkeypatch.setattr("modules.guided_runtime_observation.collect_runtime_processes", lambda *a, **k: [])
    monkeypatch.setattr("modules.guided_runtime_observation.run_network_surface_review",
                        lambda *a, **k: {"coverage_gap": False, "network_records": [], "network_pois": []})
    monkeypatch.setattr("modules.guided_runtime_observation.run_ipc_review",
                        lambda *a, **k: {"coverage_gap": False, "ipc_records": [], "ipc_pois": []})

    result = run_guided_collectors(
        root, {}, [{"ProcessName": "Client.exe", "Path": r"C:\Program Files\Acme\Client.exe"}], {},
        interactive=False, output_fn=lambda _: None,
    )
    try:
        assert "working/guided_runtime_target_events.csv" in result["staged_evidence"]
        assert "working/guided_runtime_capture.csv" not in result["staged_evidence"]
        assert result["summary"]["session"]["duration_seconds"] == 10
    finally:
        import shutil
        shutil.rmtree(result["staging_dir"], ignore_errors=True)


def test_guided_runtime_refreshes_effective_runtime_modules_without_full_capture(tmp_path, monkeypatch):
    from tests.test_guided_review_navigation import assessment
    from tests.test_guided_runtime_core import _runtime_target_report
    from utils.assessment_integrity import create_manifest
    from utils.guided_runtime import run_guided_runtime
    import json

    root = assessment(tmp_path, version="1.7.1")
    _runtime_target_report(root)
    create_manifest(root, framework_version="1.7.1", methodology_version="1.5", catalog_version="1.5")

    stage = tmp_path / "stage171"
    stage.mkdir()
    target_csv = stage / "guided_runtime_target_events.csv"
    _write_procmon(target_csv, [])
    procmon_data = {
        "relevant_rows": 3, "observed_process_names": ["Client.exe"],
        "file_writes": [], "ipc_writes": [], "process_activity": [], "loaded_images": [],
        "registry_writes": [], "network_activity": [], "missing_dlls": [], "access_denied": [],
        "target_filter_active": True,
    }
    fake = {
        "summary": {
            "captured_at": "2026-10-05T01:00:10Z",
            "checklist": {key: "EXERCISED" for key in ("launch_close", "login_session", "network_features", "privileged_helper", "file_config", "update_check")},
            "session": {"started_at": "2026-10-05T01:00:00Z", "stopped_at": "2026-10-05T01:00:10Z", "duration_seconds": 10},
            "capture": {"status": "PASS"},
            "surfaces": {
                "process_tree": {"status": "OBSERVED", "count": 1},
                "privileged_helpers": {"status": "NOT OBSERVED", "count": 0},
                "network": {"status": "NOT OBSERVED", "count": 0},
                "named_pipes": {"status": "NOT OBSERVED", "count": 0},
                "ipc_device_activity": {"status": "NOT OBSERVED", "count": 0},
                "file_writes": {"status": "NOT OBSERVED", "count": 0},
                "registry_writes": {"status": "NOT OBSERVED", "count": 0},
                "loaded_images": {"status": "NOT OBSERVED", "count": 0},
                "updater_activity": {"status": "NOT OBSERVED", "count": 0},
            },
            "counts": {"current_target_processes": 0, "target_processes_seen": 1, "procmon_target_events": 3},
            "processes": [], "processes_seen": ["Client.exe"], "privileged_processes": [],
            "examples": {}, "network": [], "pipes": [], "scope": {"target_only": False, "exclude_path_count": 0},
            "collection": {"procmon": "AVAILABLE", "process_snapshot": "NO TARGET PROCESS OBSERVED", "network": "AVAILABLE", "ipc": "AVAILABLE"},
        },
        "procmon": {"status": "PASS", "details": "3 target events", "findings": [], "procmon_data": procmon_data, "observed_process_names": ["Client.exe"]},
        "network": {"network_pois": []}, "ipc": {"ipc_pois": []}, "processes": [],
        "staged_evidence": {"working/guided_runtime_target_events.csv": str(target_csv)},
        "staging_dir": str(stage),
    }
    monkeypatch.setattr("utils.guided_runtime.run_guided_collectors", lambda *a, **k: fake)
    monkeypatch.setattr("utils.guided_runtime.detect_tools", lambda: {})
    monkeypatch.setattr("utils.guided_runtime.run_dll_search_review", lambda *a, **k: {"status": "PASS", "details": "0 lookup(s)", "findings": [], "dll_records": []})
    monkeypatch.setattr("utils.guided_runtime.run_runtime_process_review", lambda *a, **k: {"status": "PASS", "details": "0 active", "findings": [], "runtime_processes": []})
    monkeypatch.setattr("utils.guided_runtime.run_advanced_runtime_review", lambda *a, **k: {"status": "PASS", "details": "0 POI", "findings": [], "advanced_runtime_pois": []})
    monkeypatch.setattr("utils.guided_runtime.run_network_surface_review", lambda *a, **k: {"status": "PASS", "details": "0 network", "findings": [], "coverage_gap": False, "network_records": [], "network_pois": [], "runtime_processes": []})
    monkeypatch.setattr("utils.guided_runtime.run_ipc_review", lambda *a, **k: {"status": "PASS", "details": "0 pipes", "findings": [], "coverage_gap": False, "ipc_records": [], "ipc_pois": []})
    monkeypatch.setattr("utils.guided_runtime.run_attack_surface_correlations", lambda *a, **k: {"status": "PASS", "details": "0 indicators", "findings": [], "records": [], "coverage": {}})

    result = run_guided_runtime(
        root, version="1.7.1", methodology_version="1.5", catalog_version="1.5",
        input_fn=lambda _: "", output_fn=lambda _: None, interactive_collectors=True,
    )
    assert result["after"]["status"] == "PASS"
    assert result["summary"]["session"]["duration_seconds"] == 10
    assert not (root / "working" / "guided_runtime_capture.csv").exists()
    assert (root / "working" / "guided_runtime_target_events.csv").is_file()
    state = json.loads((root / "working" / "assessment_state.json").read_text(encoding="utf-8"))
    assert state["guided_runtime"]["schema_version"] == 3
    assert state["modules"]["Procmon Analysis"]["status"] == "PASS"
    assert state["modules"]["Procmon Runtime Capture"]["status"] == "PASS"
