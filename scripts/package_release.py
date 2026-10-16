#!/usr/bin/env python3
"""Build a clean WCA source ZIP from an explicit release allowlist.

The release package intentionally carries current source, current documentation,
current regression tests, and tester PoC helpers. Historical release-by-release
validation files and generated build/cache artifacts are excluded by policy.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TOP_LEVEL_FILES = {
    ".gitattributes", ".gitignore", "CHANGELOG.md", "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md", "LICENSE", "README.md", "METHODOLOGY.md", "RELEASE_NOTES.md",
    "SECURITY.md", "install_dependencies.ps1", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", "tool_paths.example.json", "wca.py",
}
TOP_LEVEL_DIRS = {"assets", "docs", "gui", "modules", "scripts", "tests", "utils"}
BRAND_ASSETS = {"WinClientAssess-v2.2.0.png"}
LOCAL_CONFIG_FILES = {"tool_paths.json"}  # user machine paths; never packaged
# Tester distribution omits developer-facing source control, unit tests and
# packaging/validation tooling. All runtime and authorized PoC helpers remain.
TESTER_EXCLUDED_TOP_LEVEL_FILES = {
    ".gitattributes", ".gitignore", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md",
    "requirements-dev.txt",
}
TESTER_EXCLUDED_DIRS = {"assets", "tests"}
TESTER_EXCLUDED_SCRIPTS = {"package_release.py", "validate_windows.ps1"}
CANONICAL_DOCS = {
    "artifact-policy.md", "manual-testing-workflow.md", "collection-provenance.md", "assessment-integrity.md", "assessment-lifecycle.md",
    "client-appendix.md", "backend-service.md", "gui-guide.md",
    "guided-review.md", "guided-runtime.md", "getting-started.md", "installation.md",
    "attack-surface-coverage.md", "methodology.md", "optional-tools.md",
    "outputs.md", "release-validation.md", "windows-environment-setup.md", "tester-dashboard.md",
    "troubleshooting.md", "usage.md", "windows-validation.md",
}
CANONICAL_SCRIPTS = {"package_release.py", "validate_windows.ps1"}
DISALLOWED_PARTS = {"__pycache__", ".pytest_cache", ".venv", "build", "dist"}
DISALLOWED_SUFFIXES = {".pyc", ".pyo"}


def _load_version() -> str:
    text = (ROOT / "wca.py").read_text(encoding="utf-8")
    match = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise RuntimeError("Unable to locate VERSION in wca.py")
    return match.group(1)


def audit_tree() -> list[str]:
    issues: list[str] = []
    for path in ROOT.iterdir():
        if path.name in DISALLOWED_PARTS or path.name == "__pycache__":
            continue
        if path.name.startswith(".") and path.name not in TOP_LEVEL_FILES:
            if path.name == ".github":
                issues.append(".github is not part of the distributed source package")
            continue
        if path.is_file() and path.name not in TOP_LEVEL_FILES and path.name not in LOCAL_CONFIG_FILES:
            issues.append(f"Unexpected top-level file: {path.name}")
        elif path.is_dir() and path.name not in TOP_LEVEL_DIRS and not path.name.endswith(".egg-info"):
            issues.append(f"Unexpected top-level directory: {path.name}")
        if path.is_dir() and path.name.endswith(".egg-info"):
            issues.append(f"Generated packaging metadata must not ship: {path.name}")

    docs = {p.name for p in (ROOT / "docs").glob("*") if p.is_file()}
    unexpected_docs = docs - CANONICAL_DOCS
    missing_docs = CANONICAL_DOCS - docs
    issues += [f"Unexpected/historical doc: docs/{name}" for name in sorted(unexpected_docs)]
    issues += [f"Missing canonical doc: docs/{name}" for name in sorted(missing_docs)]

    assets = {p.name for p in (ROOT / "assets").glob("*") if p.is_file()}
    issues += [f"Unexpected branding asset: assets/{name}" for name in sorted(assets - BRAND_ASSETS)]
    issues += [f"Missing versioned branding asset: assets/{name}" for name in sorted(BRAND_ASSETS - assets)]
    scripts_dir = ROOT / "scripts"
    scripts = {p.name for p in scripts_dir.iterdir() if p.is_file()}
    unexpected_scripts = scripts - CANONICAL_SCRIPTS
    issues += [f"Unexpected/historical script: scripts/{name}" for name in sorted(unexpected_scripts)]
    if not (scripts_dir / "poc").is_dir():
        issues.append("Missing scripts/poc directory")

    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        # Python/test caches may be created by validation itself. They are excluded
        # by iter_release_files(), so they cannot enter the ZIP. Egg-info and nested
        # release artifacts remain explicit audit failures because they indicate stale
        # packaging carryover rather than ordinary test execution.
        if any(part.endswith(".egg-info") for part in rel.parts):
            issues.append(f"Generated packaging metadata present: {rel.as_posix()}")
        if path.is_file() and path.name.lower().endswith((".zip", ".sha256", ".sha256.txt")):
            issues.append(f"Nested release artifact present: {rel.as_posix()}")
    return sorted(set(issues))


def iter_release_files(*, tester: bool = False):
    for name in sorted(TOP_LEVEL_FILES):
        if tester and name in TESTER_EXCLUDED_TOP_LEVEL_FILES:
            continue
        path = ROOT / name
        if not path.is_file():
            raise FileNotFoundError(f"Required release file missing: {name}")
        yield path
    for dirname in sorted(TOP_LEVEL_DIRS):
        if tester and dirname in TESTER_EXCLUDED_DIRS:
            continue
        base = ROOT / dirname
        if not base.is_dir():
            raise FileNotFoundError(f"Required release directory missing: {dirname}")
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            rel = path.relative_to(ROOT)
            if any(part in DISALLOWED_PARTS or part.endswith(".egg-info") for part in rel.parts):
                continue
            if path.suffix.lower() in DISALLOWED_SUFFIXES:
                continue
            if tester and dirname == "scripts" and path.relative_to(base).parts[0] in TESTER_EXCLUDED_SCRIPTS:
                continue
            yield path


def build(output_dir: Path, *, tester: bool = False) -> tuple[Path, Path]:
    issues = audit_tree()
    if issues:
        raise RuntimeError("Release audit failed:\n- " + "\n- ".join(issues))
    version = _load_version()
    stem = f"WCA-v{version}"
    package_stem = f"{stem}-Tester" if tester else stem
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / f"{package_stem}.zip"
    checksum_path = output_dir / f"{package_stem}.sha256.txt"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in iter_release_files(tester=tester):
            arcname = Path(stem) / path.relative_to(ROOT)
            zf.write(path, arcname.as_posix())
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")
    return zip_path, checksum_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit and package the current WCA source release")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--tester-package", action="store_true", help="Create minimal tester ZIP, preserving runtime and PoC helpers but excluding tests/build tooling")
    parser.add_argument("--output-dir", default=str(ROOT.parent))
    args = parser.parse_args()
    issues = audit_tree()
    if issues:
        print("Release audit: FAIL")
        for issue in issues:
            print(" -", issue)
        return 1
    print("Release audit: PASS")
    if args.audit_only:
        return 0
    zip_path, checksum_path = build(Path(args.output_dir).resolve(), tester=args.tester_package)
    print(zip_path)
    print(checksum_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
