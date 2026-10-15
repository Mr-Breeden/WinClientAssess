"""v1.7.2 Guided Runtime stabilization and tester-controlled evidence regressions."""
from __future__ import annotations

import csv
from pathlib import Path

from rich.console import Console

from modules.guided_runtime_observation import GuidedRuntimeLiveController
from modules.procmon_capture import _adaptive_export_timeout
from tests.test_guided_review_navigation import assessment
from utils.assessment_layout import artifact_path
from utils.sensitive_data import sanitize_procmon_csv


def _write_procmon(path: Path, rows: list[dict]) -> None:
    headers = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def test_streaming_procmon_sanitizer_filters_host_noise_and_follows_child(tmp_path):
    source = tmp_path / "raw.csv"
    destination = tmp_path / "target.csv"
    _write_procmon(source, [
        {
            "Time of Day": "12:00:00", "Process Name": "HostNoise.exe", "PID": "10",
            "Operation": "ReadFile", "Path": r"C:\\Windows\\noise.dat", "Result": "SUCCESS", "Detail": "host",
        },
        {
            "Time of Day": "12:00:01", "Process Name": "Client.exe", "PID": "20",
            "Operation": "Process Create", "Path": r"C:\\Windows\\System32\\cmd.exe", "Result": "SUCCESS", "Detail": "child",
        },
        {
            "Time of Day": "12:00:02", "Process Name": "cmd.exe", "PID": "21",
            "Operation": "WriteFile", "Path": r"C:\\ProgramData\\Target\\marker.txt", "Result": "SUCCESS", "Detail": "write",
        },
    ])

    result = sanitize_procmon_csv(source, destination, target_process_names=["Client.exe"])

    assert result["source_rows"] == 3
    assert result["rows"] == 1
    assert result["target_filter_active"] is True
    assert "cmd.exe" not in result["tracked_process_names"]
    output = destination.read_text(encoding="utf-8-sig")
    assert "Client.exe" in output
    assert "cmd.exe" in output
    assert "HostNoise.exe" not in output


def test_live_runtime_panel_is_passive_and_enter_only():
    controller = GuidedRuntimeLiveController([], refresh_seconds=1)
    panel = controller._render(elapsed=90, pml_size=768 * 1024 * 1024, growth_age=1,
                               processes=[], connections=0)
    console = Console(record=True, force_terminal=False, color_system=None, width=140)
    console.print(panel)
    rendered = console.export_text()

    assert "SUGGESTED ACTIVITIES" in rendered
    assert "No input is required while testing" in rendered
    assert "ENTER" in rendered and "Finish observation" in rendered
    assert "Press 1-6" not in rendered
    assert "NOT EXERCISED" not in rendered


def test_large_procmon_capture_gets_more_than_legacy_five_minute_export_window():
    timeout = _adaptive_export_timeout(int(1.4 * (1024 ** 3)))
    assert timeout > 300
    assert 600 <= timeout <= 3600


def test_evidence_guide_is_single_tester_controlled_path_without_cleanup(tmp_path):
    root = assessment(tmp_path, version="1.7.2")
    guide = artifact_path(root, "evidence_guide.txt").read_text(encoding="utf-8")

    for heading in (
        "1 / 10  OBSERVED EVIDENCE",
        "2 / 10  WHY VALIDATE IT",
        "3 / 10  PREREQUISITES",
        "4 / 10  STARTING CHECKS",
        "5 / 10  MANUAL VALIDATION PROCEDURE",
        "6 / 10  POC RESOURCE",
        "7 / 10  TESTER EXECUTION",
        "8 / 10  EXPECTED EVIDENCE",
        "9 / 10  INTERPRETATION",
        "10 / 10  WHEN NOT TO REPORT",
    ):
        assert heading in guide

    assert "Windows Client Assessment never compiles or executes PoC resources" in guide
    assert "Cleanup:" not in guide
    assert "CLEANUP" not in guide
    assert "Client/Controlled" not in guide
    assert "CTF/Lab" not in guide
    assert "Guidance Only" not in guide
