"""RC1 source/tester inventory regression gates (no Windows host required)."""
from __future__ import annotations

import zipfile
from pathlib import Path

from scripts import package_release as release


def test_source_and_tester_tiers_preserve_runtime_and_poc_helpers():
    source = {p.relative_to(release.ROOT).as_posix() for p in release.iter_release_files()}
    tester = {p.relative_to(release.ROOT).as_posix() for p in release.iter_release_files(tester=True)}
    assert tester < source
    required = {
        'wca.py', 'install_dependencies.ps1', 'requirements.txt',
        'gui/app.js', 'gui/index.html', 'gui/app.css',
        'utils/elevation.py', 'utils/gui_server.py', 'docs/manual-testing-workflow.md',
        'docs/windows-environment-setup.md', 'tool_paths.example.json',
        'scripts/poc/README.md',
    }
    assert required <= tester
    assert 'tests/test_rc1_release_packaging.py' in source
    assert 'tests/test_rc1_release_packaging.py' not in tester
    assert 'requirements-dev.txt' in source
    assert 'requirements-dev.txt' not in tester
    assert 'scripts/package_release.py' in source
    assert 'scripts/package_release.py' not in tester
    assert 'scripts/validate_windows.ps1' not in tester
    assert all(not n.startswith('tests/') for n in tester)
    assert all(not n.endswith(('.pyc', '.pyo')) and '__pycache__' not in n for n in source)
    assert all('/.venv/' not in '/' + n and 'tool_paths.json' != n for n in tester)


def test_rc1_packaging_archive_member_names_are_stable(tmp_path):
    source_zip, source_sha = release.build(tmp_path)
    tester_zip, tester_sha = release.build(tmp_path, tester=True)
    assert source_zip.name == 'WCA-v2.2.0.zip'
    assert tester_zip.name == 'WCA-v2.2.0-Tester.zip'
    for path, hash_file in ((source_zip, source_sha), (tester_zip, tester_sha)):
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            names = archive.namelist()
            assert names
            assert all(x.startswith('WCA-v2.2.0/') for x in names)
            assert not any('working/' in n or 'snapshot_pre.json' in n or '.venv' in n for n in names)
        assert path.name in hash_file.read_text()


def test_rc1_docs_do_not_call_attack_surface_a_second_checklist():
    readme = (release.ROOT / 'README.md').read_text(encoding='utf-8')
    guide = (release.ROOT / 'docs' / 'manual-testing-workflow.md').read_text(encoding='utf-8')
    assert 'WCA-v2.2.0-Tester.zip' in readme
    assert 'single Testing Queue' in readme or 'unified Testing Queue' in readme
    assert 'not another checklist' in guide
    assert 'ADDRESSED IN GUIDED REVIEW' in guide


def test_production_branding_asset_is_versioned_source_only():
    source = {p.relative_to(release.ROOT).as_posix() for p in release.iter_release_files()}
    tester = {p.relative_to(release.ROOT).as_posix() for p in release.iter_release_files(tester=True)}
    name = 'assets/WinClientAssess-v2.2.0.png'
    assert name in source and name not in tester
    assert (release.ROOT / name).read_bytes().startswith(bytes.fromhex('89504e470d0a1a0a'))
    assert 'v2.2.0' in (release.ROOT / 'README.md').read_text(encoding='utf-8')
