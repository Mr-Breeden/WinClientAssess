"""v1.7.3 field corrections: PoC resource paths and target scoping."""
from __future__ import annotations

import csv
from pathlib import Path

from modules.attack_surface_correlations import detect_indicators
from modules.runtime_targets import discover_runtime_targets
from modules.updater_review import discover_updater_candidates
from utils.poc_playbooks import candidate_validation, poc_resource_display


def _inventory():
    return [
        {
            "path": r"C:\Extract\Beeper.exe",
            "name": "Beeper.exe",
            "extension": ".exe",
            "size_bytes": 32768,
        },
        {
            "path": r"C:\Extract\AcmeWidgetService.exe",
            "name": "AcmeWidgetService.exe",
            "extension": ".exe",
            "size_bytes": 14848,
        },
        {
            "path": r"C:\Extract\ClientUpdater.exe",
            "name": "ClientUpdater.exe",
            "extension": ".exe",
            "size_bytes": 24000,
        },
    ]


def _diff_with_host_noise():
    return {
        "Services": {
            "added": [{
                "Name": "AcmeWidgetService",
                "DisplayName": "AcmeWidgetService",
                "PathName": r"C:\Program Files\AcmeWidget\AcmeWidgetService.exe",
                "StartName": "LocalSystem",
            }]
        },
        "ScheduledTasks": {"added": []},
        "RunEntries": {"added": []},
        "Filesystem": {
            "added": [
                {"Path": r"C:\Program Files\AcmeWidget\Beeper.exe", "Length": 32768, "IsDirectory": False},
                {"Path": r"C:\Program Files\AcmeWidget\AcmeWidgetService.exe", "Length": 14848, "IsDirectory": False},
                # Sibling target updater deliberately differs from static size;
                # the verified target install root should still associate it.
                {"Path": r"C:\Program Files\AcmeWidget\ClientUpdater.exe", "Length": 25000, "IsDirectory": False},
                {"Path": r"C:\Program Files (x86)\Microsoft\EdgeCore\154\msedge.exe", "Length": 5403976, "IsDirectory": False},
                {"Path": r"C:\Program Files (x86)\Microsoft\EdgeCore\154\msedge_pwa_launcher.exe", "Length": 3013448, "IsDirectory": False},
                {"Path": r"C:\Users\Tester\AppData\Local\Microsoft\OneDrive\26\OneDriveUpdaterService.exe", "Length": 4104552, "IsDirectory": False},
            ]
        },
    }


def test_runtime_targets_reject_unrelated_host_updates_when_inventory_is_available():
    targets = discover_runtime_targets(
        _diff_with_host_noise(),
        analysis_roots=[],
        file_inventory=_inventory(),
    )
    names = {item["ProcessName"] for item in targets}
    assert "Beeper.exe" in names
    assert "AcmeWidgetService.exe" in names
    assert "ClientUpdater.exe" in names
    assert "msedge.exe" not in names
    assert "msedge_pwa_launcher.exe" not in names
    assert "OneDriveUpdaterService.exe" not in names

    installed = [item for item in targets if item.get("Source") == "Filesystem added (target-associated)"]
    assert any("matches extracted/static payload" in item.get("Note", "") for item in installed)
    assert any("beneath target-associated install root" in item.get("Note", "") for item in installed)


def test_installed_updater_discovery_uses_same_target_association():
    candidates = discover_updater_candidates(
        None,
        _diff_with_host_noise(),
        seed_candidates=[],
        target_inventory=_inventory(),
    )
    names = {item["ProcessName"] for item in candidates}
    assert "ClientUpdater.exe" in names
    assert "msedge_pwa_launcher.exe" not in names
    assert "OneDriveUpdaterService.exe" not in names
    target = next(item for item in candidates if item["ProcessName"] == "ClientUpdater.exe")
    assert target.get("Association") == "beneath target-associated install root"


def test_attack_surface_target_names_do_not_repromote_filesystem_noise(tmp_path):
    root = tmp_path / "assessment"
    (root / "working").mkdir(parents=True)
    (root / "reports").mkdir()
    csv_path = root / "working" / "guided_runtime_target_events.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["Process Name", "Operation", "Path", "Result"],
        )
        writer.writeheader()
        writer.writerow({
            "Process Name": "msedge.exe",
            "Operation": "CreateFile",
            "Path": r"C:\ProgramData\Noise\helper.exe",
            "Result": "NAME NOT FOUND",
        })

    procmon = {
        "guided_runtime": True,
        "target_filter_active": True,
        "registry_writes": [],
    }
    records, coverage = detect_indicators(
        root,
        mode="full",
        diff=_diff_with_host_noise(),
        pre={},
        post={},
        procmon=procmon,
        targets=[{"ProcessName": "Beeper.exe", "Path": r"C:\Program Files\AcmeWidget\Beeper.exe"}],
    )
    assert not any(item.get("Process") == "msedge.exe" for item in records)
    assert coverage["Executable/helper search-path hijacking"] == "NOT OBSERVED"


def test_poc_resource_field_resolves_against_tool_tree():
    item = {
        "source_module": "IPC / Named Pipe Review",
        "title": r"PipeServer.exe -> \\.\pipe\AcmeWidget",
        "evidence": r"PipeServer.exe -> \\.\pipe\AcmeWidget",
    }
    live = candidate_validation(item, console_paths=True)["poc_resource"]
    portable = candidate_validation(item, console_paths=False)["poc_resource"]

    assert live.endswith(str(Path("scripts") / "poc" / "pipe_connect_probe.ps1"))
    assert Path(live).is_absolute()
    assert "pipe_connect_probe.ps1" in portable
    assert portable != "scripts/poc/pipe_connect_probe.ps1"
    assert "tool directory" in portable.lower() or "%USERPROFILE%" in portable


def test_all_bundled_resource_displays_are_not_ambiguous_relative_paths():
    for relative in (
        "scripts/poc/marker_dll.c",
        "scripts/poc/marker_exe.c",
        "scripts/poc/pipe_connect_probe.ps1",
        "scripts/poc/reparse_inventory.ps1",
        "scripts/poc/com_registration_probe.ps1",
    ):
        display = poc_resource_display(relative, console_paths=False)
        assert display != relative
        assert Path(poc_resource_display(relative, console_paths=True)).is_absolute()
