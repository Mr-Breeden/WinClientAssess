from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.assessment_layout import LAYOUT_VERSION, ensure_structured_layout, is_structured_layout, state_path

STATE_SCHEMA_VERSION = 1
ARTIFACT_SCHEMA_VERSION = 2
STAGES = (
    "static_analysis",
    "pre_install_snapshot",
    "installation_confirmation",
    "post_install_snapshot",
    "installed_state_analysis",
    "runtime_optional",
    "surface_optional",
    "reporting",
    "complete",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


class AssessmentState:
    def __init__(self, assessment_dir: Path, data: dict[str, Any]):
        self.assessment_dir = Path(assessment_dir)
        self.data = data

    @classmethod
    def create(
        cls, assessment_dir: Path, *, assessment_name: str, installer: Path,
        mode: str, framework_version: str, options: dict[str, Any], tools: dict[str, Any],
        target_type: str = "installable", target_source: Path | None = None,
    ) -> "AssessmentState":
        ensure_structured_layout(assessment_dir)
        now = _utc_now()
        installer = Path(installer)
        target_source = Path(target_source) if target_source is not None else installer
        target_type = str(target_type or "installable").lower()
        target = {
            "type": target_type,
            "source_kind": "directory" if target_source.is_dir() else "file",
            "source_name": target_source.name,
            "primary_executable": installer.name,
            "sha256": sha256_file(installer),
        }
        data = {
            "schema_version": STATE_SCHEMA_VERSION,
            "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
            "layout_version": LAYOUT_VERSION,
            "framework_version": framework_version,
            "assessment_name": assessment_name,
            "mode": mode,
            "installer": {
                "filename": installer.name,
                "sha256": sha256_file(installer),
            },
            "target": target,
            "options": dict(options),
            "tool_availability": {
                name: {
                    "found": bool(info.get("found")),
                    "level": info.get("level", ""),
                    "usage": info.get("usage", ""),
                }
                for name, info in tools.items()
            },
            "status": "IN_PROGRESS",
            "current_stage": "static_analysis",
            "stages": {stage: {"status": "PENDING"} for stage in STAGES},
            "modules": {},
            "created_at": now,
            "updated_at": now,
            "last_message": "Assessment initialized.",
        }
        state = cls(assessment_dir, data)
        state.save()
        return state

    @classmethod
    def load(cls, assessment_dir: Path) -> "AssessmentState" | None:
        root = Path(assessment_dir)
        path = root / "working" / "assessment_state.json"
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return cls(root, data)

    def save(self) -> None:
        self.data["updated_at"] = _utc_now()
        _atomic_json(state_path(self.assessment_dir), self.data)

    def record_snapshot_integrity(self, stage: str, filename: str) -> None:
        """Pin a successful checkpoint to its exact, privacy-sanitized snapshot."""
        from utils.assessment_layout import artifact_path
        if stage not in {"pre_install_snapshot", "post_install_snapshot"}:
            raise ValueError("Only snapshot checkpoints can be pinned")
        path = artifact_path(self.assessment_dir, filename)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Cannot pin an absent/untrusted snapshot")
        # Reject a partial snapshot even if it happens to be parseable JSON.
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("CollectionErrors"):
            raise ValueError("Incomplete snapshot cannot become a trusted checkpoint")
        if not isinstance(data.get("Services"), list) or not data["Services"] or not isinstance(data.get("ScheduledTasks"), list):
            raise ValueError("Snapshot is missing required populated service/scheduled-task inventories")
        self.data.setdefault("checkpoint_integrity", {})[stage] = {
            "filename": filename, "size": path.stat().st_size, "sha256": sha256_file(path)
        }
        self.save()

    def validate_snapshot_integrity(self, stage: str) -> tuple[bool, str]:
        from utils.assessment_layout import artifact_path
        record = self.data.get("checkpoint_integrity", {}).get(stage)
        if not isinstance(record, dict):
            return False, f"{stage}: missing trusted snapshot checksum; do not resume on a potentially changed VM."
        expected_name = {"pre_install_snapshot": "snapshot_pre.json", "post_install_snapshot": "snapshot_post.json"}.get(stage)
        if record.get("filename") != expected_name:
            return False, f"{stage}: unexpected checkpoint artifact identity."
        path = artifact_path(self.assessment_dir, expected_name)
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size != record["size"] or sha256_file(path) != record["sha256"]:
                return False, f"{stage}: snapshot missing or modified; revert VM rather than regenerating source evidence."
        except (OSError, KeyError, TypeError):
            return False, f"{stage}: snapshot could not be verified."
        return True, f"{stage}: checkpoint SHA-256 verified."

    def checkpoint(self, stage: str, status: str, message: str = "") -> None:
        if stage not in self.data["stages"]:
            self.data["stages"][stage] = {"status": "PENDING"}
        entry = self.data["stages"][stage]
        entry["status"] = status
        key = "completed_at" if status == "COMPLETED" else "started_at"
        entry[key] = _utc_now()
        self.data["current_stage"] = stage
        if message:
            entry["message"] = message
            self.data["last_message"] = message
        self.save()

    def module_status(self, module: str, info: dict[str, Any]) -> None:
        self.data.setdefault("modules", {})[module] = {
            "status": info.get("status", ""),
            "details": info.get("details", ""),
            "coverage_gap": bool(info.get("coverage_gap")),
        }
        self.save()

    def mark_interrupted(self, message: str) -> None:
        self.data["status"] = "INTERRUPTED"
        self.data["last_message"] = message
        self.save()

    def mark_complete(self, coverage: str) -> None:
        self.data["status"] = "COMPLETED"
        self.data["coverage"] = coverage
        self.checkpoint("complete", "COMPLETED", f"Assessment finalized with coverage {coverage}.")

    def validate_installer(self, installer: Path) -> tuple[bool, str]:
        expected = self.data.get("installer", {})
        if Path(installer).name != expected.get("filename"):
            return False, "Selected installer filename does not match the saved assessment state."
        current = sha256_file(installer)
        if current.lower() != str(expected.get("sha256") or "").lower():
            return False, "Selected installer SHA-256 does not match the saved assessment state."
        return True, "Installer identity verified."

    def validate_target(self, primary_executable: Path, *, source_path: Path | None = None,
                        target_type: str | None = None) -> tuple[bool, str]:
        """Validate the identity file for installable or portable assessments.

        Portable directory targets are pinned by the primary executable hash so
        normal runtime-created files beside the executable do not invalidate a
        resumable checkpoint.
        """
        target = self.data.get("target") or {}
        if not target:
            return self.validate_installer(primary_executable)
        expected_type = str(target.get("type") or "installable").lower()
        supplied_type = str(target_type or expected_type).lower()
        if supplied_type != expected_type:
            return False, f"Selected target type does not match saved assessment state ({expected_type})."
        primary_executable = Path(primary_executable)
        expected_name = str(target.get("primary_executable") or self.data.get("installer", {}).get("filename") or "")
        if primary_executable.name != expected_name:
            return False, "Selected primary executable filename does not match the saved assessment state."
        try:
            current = sha256_file(primary_executable)
        except OSError:
            return False, "Selected primary executable could not be read for identity verification."
        expected_hash = str(target.get("sha256") or self.data.get("installer", {}).get("sha256") or "")
        if current.lower() != expected_hash.lower():
            return False, "Selected primary executable SHA-256 does not match the saved assessment state."
        if source_path is not None:
            source_path = Path(source_path)
            expected_kind = str(target.get("source_kind") or "file")
            actual_kind = "directory" if source_path.is_dir() else "file"
            if actual_kind != expected_kind:
                return False, "Selected portable source kind does not match the saved assessment state."
        label = "Portable target" if expected_type == "portable" else "Installer"
        return True, f"{label} identity verified."

    def recovery_action(self) -> tuple[str, str]:
        stages = self.data.get("stages", {})
        if self.data.get("status") == "COMPLETED":
            return "NONE", "Assessment is already completed."
        pre = stages.get("pre_install_snapshot", {}).get("status")
        install = stages.get("installation_confirmation", {}).get("status")
        post = stages.get("post_install_snapshot", {}).get("status")
        target_type = str((self.data.get("target") or {}).get("type") or "installable").lower()
        if pre == "STARTED" and pre != "COMPLETED":
            return "HALT", "Baseline snapshot did not complete. Revert to the clean VM baseline before rerunning."
        if str(self.data.get("framework_version", "")).startswith("1.4") and pre == "COMPLETED":
            ok, message = self.validate_snapshot_integrity("pre_install_snapshot")
            if not ok:
                return "HALT", message
            if post == "COMPLETED":
                ok, message = self.validate_snapshot_integrity("post_install_snapshot")
                if not ok:
                    return "HALT", message
        if pre == "COMPLETED" and post != "COMPLETED":
            if install == "COMPLETED":
                if target_type == "portable":
                    return "POST_INSTALL", "Valid baseline exists and tester activity was confirmed; resume with the post-activity snapshot on the unchanged VM."
                return "POST_INSTALL", "Valid pre-install baseline exists and installation was confirmed; resume with post-install snapshot on the unchanged VM."
            if target_type == "portable":
                return "INSTALL", "Valid portable baseline exists; resume at tester-controlled application activity on the unchanged VM."
            return "INSTALL", "Valid pre-install baseline exists; resume at installation confirmation on the unchanged VM."
        if post == "COMPLETED":
            return "ANALYSIS", "Valid baseline/post-activity snapshots exist; system-state and optional runtime analysis can be regenerated safely."
        return "RESTART", "No trusted baseline/post-activity checkpoint exists; restart the assessment from the clean baseline."


def describe_assessment(assessment_dir: Path) -> dict[str, Any]:
    root = Path(assessment_dir)
    state = AssessmentState.load(root)
    if state:
        action, guidance = state.recovery_action()
        return {
            "kind": "structured",
            "state": state,
            "status": state.data.get("status", "UNKNOWN"),
            "stage": state.data.get("current_stage", "unknown"),
            "action": action,
            "guidance": guidance,
        }
    # Deliberately read legacy assessments without silently converting them.
    legacy_markers = [root / "module_status.txt", root / "coverage_summary.txt", root / "snapshot_pre.json"]
    if any(path.exists() for path in legacy_markers):
        return {
            "kind": "legacy",
            "status": "LEGACY_FLAT_ASSESSMENT",
            "stage": "unknown",
            "action": "CONVERT_REQUIRED",
            "guidance": "This assessment predates the v1.3.0 structured layout. It remains readable, but resume requires an explicit conversion in a future migration workflow; Windows Client Assessment will not overwrite it silently.",
        }
    return {
        "kind": "unknown", "status": "NOT_FOUND", "stage": "unknown", "action": "NONE",
        "guidance": "No Windows Client Assessment assessment state was found at this location.",
    }
