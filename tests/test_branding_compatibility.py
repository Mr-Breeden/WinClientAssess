from pathlib import Path
import importlib


def test_current_branding_constants_and_version():
    wca = importlib.import_module("wca")
    assert wca.VERSION == "2.2.1"
    assert wca.PRODUCT_SHORT == "WCA"
    assert wca.PRODUCT_NAME == "Windows Client Assessment"
    assert wca.AUTHOR == "Matthew B."
    assert wca.METHODOLOGY_VERSION == "1.9"
    assert wca.ARTIFACT_CATALOG_VERSION == "2.0"


def test_primary_launcher_and_package_metadata():
    assert Path("wca.py").is_file()
    assert not Path("winclientassess.py").exists()
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "wca"' in text
    assert 'version = "2.2.1"' in text
    assert '{ name = "Matthew B." }' in text
    assert 'wca = "wca:main"' in text
    assert 'py-modules = ["wca"]' in text


def test_manifest_compatibility_identifier_is_preserved():
    text = Path("utils/assessment_integrity.py").read_text(encoding="utf-8")
    assert '"framework": "WinClientAssess"' in text
    assert 'manifest.get("framework") != "WinClientAssess"' in text


def test_banner_is_wide_and_borderless(monkeypatch):
    from rich.console import Console
    wca = importlib.import_module("wca")
    capture = Console(width=120, record=True, force_terminal=False)
    monkeypatch.setattr(wca, "console", capture)
    wca.banner()
    text = capture.export_text()
    lines = text.splitlines()
    art_lines = lines[:7]
    assert all("╭" not in line and "╰" not in line and "│" not in line for line in lines)
    assert max(len(line.rstrip()) for line in art_lines) >= 110
    assert "Windows Client Assessment" in text
    assert "Author: Matthew B." in text
    assert "Version: v2.2.1" in text


def test_banner_uses_compact_borderless_fallback_on_narrow_terminal(monkeypatch):
    from rich.console import Console
    wca = importlib.import_module("wca")
    capture = Console(width=60, record=True, force_terminal=False)
    monkeypatch.setattr(wca, "console", capture)
    wca.banner()
    text = capture.export_text()
    assert "╭" not in text and "╰" not in text and "│" not in text
    assert max((len(line) for line in text.splitlines()), default=0) <= 60
    assert "Version: v2.2.1" in text
