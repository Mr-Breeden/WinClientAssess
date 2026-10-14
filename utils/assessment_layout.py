from __future__ import annotations

from pathlib import Path

LAYOUT_VERSION = 2
REPORTS_DIR = "reports"
WORKING_DIR = "working"

# Raw/authoritative evidence that should not be mixed with interpreted tester reports.
_WORKING_FILES = {
    "snapshot_pre.json",
    "snapshot_post.json",
    "procmon_runtime_capture.csv",
    "procmon_runtime_sanitized.csv",
    "procmon_runtime_capture.pml",
    ".procmon_runtime_sanitized.tmp.csv",
}
_WORKING_DIRS = {"extracted_installer", "decompiled_dotnet"}


def is_structured_layout(assessment_dir: Path) -> bool:
    root = Path(assessment_dir)
    return (root / REPORTS_DIR).is_dir() and (root / WORKING_DIR).is_dir()


def ensure_structured_layout(assessment_dir: Path) -> tuple[Path, Path]:
    root = Path(assessment_dir)
    reports = root / REPORTS_DIR
    working = root / WORKING_DIR
    reports.mkdir(parents=True, exist_ok=True)
    working.mkdir(parents=True, exist_ok=True)
    return reports, working


def artifact_path(assessment_dir: Path, filename: str) -> Path:
    """Resolve a logical artifact name without breaking legacy flat assessments/tests."""
    root = Path(assessment_dir)
    raw = str(filename).replace("\\", "/")
    if raw.startswith("reports/") or raw.startswith("working/"):
        return root / Path(raw)
    if not is_structured_layout(root):
        return root / filename
    if raw in _WORKING_FILES:
        return root / WORKING_DIR / filename
    return root / REPORTS_DIR / filename


def generated_directory_path(assessment_dir: Path, dirname: str) -> Path:
    root = Path(assessment_dir)
    if not is_structured_layout(root):
        return root / dirname
    if dirname in _WORKING_DIRS:
        return root / WORKING_DIR / dirname
    return root / REPORTS_DIR / dirname


def state_path(assessment_dir: Path) -> Path:
    root = Path(assessment_dir)
    if is_structured_layout(root):
        return root / WORKING_DIR / "assessment_state.json"
    # Legacy assessments intentionally do not gain state implicitly.
    return root / "assessment_state.json"


def existing_artifact_path(assessment_dir: Path, filename: str) -> Path:
    """Read canonical v2 first, then legacy flat layout for compatibility."""
    root = Path(assessment_dir)
    canonical = artifact_path(root, filename)
    if canonical.exists():
        return canonical
    legacy = root / filename
    return legacy


def relative_href_from_reports(assessment_dir: Path, filename: str) -> str | None:
    root = Path(assessment_dir)
    path = existing_artifact_path(root, filename)
    if not path.is_file():
        return None
    base = (root / REPORTS_DIR) if is_structured_layout(root) else root
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        # working evidence is deliberately not linked from the tester report.
        return None
