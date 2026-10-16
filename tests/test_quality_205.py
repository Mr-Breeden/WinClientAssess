"""v2.2.0 release consistency and security-focused permissions attribution."""
from __future__ import annotations

from pathlib import Path
import re

import pytest

import wca
from modules.permissions_review import _candidate_paths, run_permissions_review

ROOT = Path(__file__).resolve().parents[1]


def _mixed_update():
    product = r'C:\Program Files\Sample Client'
    noise = r'C:\Users\SampleTester\AppData\Local\Programs\Editor Update'
    diff = {
        'Services': {'added': [
            {'Name': 'SampleService', 'PathName': product + r'\service.exe', 'StartName': 'LocalSystem'}
        ]},
        'ScheduledTasks': {'added': []},
        'InstalledApplications': {'added': [
            {'DisplayName': 'Sample Client', 'InstallLocation': product},
            {'DisplayName': 'Unrelated Editor', 'InstallLocation': noise},
        ]},
        'Filesystem': {'added': [
            *({'Path': noise + fr'\modules\noise{i}.dll', 'IsDirectory': False} for i in range(800)),
            {'Path': product + r'\service.exe', 'IsDirectory': False},
            {'Path': product + r'\client.exe', 'IsDirectory': False},
            {'Path': product + r'\settings.json', 'IsDirectory': False},
        ], 'changed': []},
    }
    return product, noise, diff


def test_background_update_does_not_promote_unrelated_installation_to_target_acl():
    product, noise, diff = _mixed_update()
    counts = {}
    rows = _candidate_paths({}, {}, diff, stats=counts)
    paths = [x['Path'] for x in rows]
    assert any(product.lower() in x.lower() for x in paths)
    assert not any(noise.lower() in x.lower() for x in paths)
    assert len(rows) <= 7  # service, installation files/directories, no unrelated bulk
    assert counts['out_of_scope_filesystem'] >= 800
    assert not counts['unattributed_filesystem']
    # Snapshot differential is evidence and must not be altered by ACL triage.
    assert len(diff['Filesystem']['added']) == 803


def test_runtime_dll_outside_install_root_kept_even_with_unrelated_background_update(tmp_path):
    product, noise, diff = _mixed_update()
    high_value = r'C:\ProgramData\Sample Client'
    runtime = [{'SearchDirectory': high_value, 'Process': 'client.exe',
                'MissingDLL': 'helper.dll', 'DirectoryExists': True,
                'BroadWriteACEs': [{'Identity': 'Users', 'Rights': 'Modify'}],
                'ID': 'DLL-001', 'PrivilegedContext': True}]
    rows = _candidate_paths({}, {}, diff, runtime_dll_records=runtime)
    assert any(r['Path'].lower() == high_value.lower() and r['DLLCorrelations'] for r in rows)
    class Acl:
        def get_many(self, paths):
            return {p.lower(): {'Path':p, 'Exists':True, 'Access': [], 'Owner':'SYSTEM'} for p in paths}
    result = run_permissions_review(tmp_path, pre={}, post={}, diff=diff,
                                    acl_cache=Acl(), runtime_dll_records=runtime)
    assert len(result['permission_results']) < 12
    report = (tmp_path/'permissions_review.txt').read_text()
    assert 'Out-of-scope filesystem entries' in report
    assert '800' in report
    assert noise not in report
    assert high_value in report


def test_installed_application_location_still_scopes_clients_without_services():
    product = r'C:\Program Files\Standalone Product'
    diff = {'Services': {'added':[]}, 'ScheduledTasks':{'added': []},
            'InstalledApplications': {'added':[{'InstallLocation':product}]},
            'Filesystem':{'added':[{'Path':product+r'\client.exe','IsDirectory':False},
                                  {'Path':r'C:\Other\noise.dll','IsDirectory':False}], 'changed':[]}}
    paths = {row['Path'].lower() for row in _candidate_paths({}, {}, diff)}
    assert (product + r'\client.exe').lower() in paths
    assert r'c:\other\noise.dll' not in paths


def test_powershell_validation_version_is_current_and_normalized():
    script = (ROOT/'scripts/validate_windows.ps1').read_text(encoding='utf-8')
    assert 'Out-String).Trim()' in script
    assert 'Invoke-CheckedPython' in script
    patterns = re.findall(r"\$version\s+-notmatch\s+'([^']+)'", script)
    assert patterns
    product_checks = [p for p in patterns if p.startswith('WCA ')]
    assert len(product_checks) == 1
    assert re.fullmatch(product_checks[0], 'WCA ' + wca.VERSION)
    assert re.search(r'^version\s*=\s*"'+re.escape(wca.VERSION)+r'"',
                     (ROOT/'pyproject.toml').read_text(encoding='utf-8'), re.M)
    assert 'WCA v'+wca.VERSION+' Windows validation' in script
    assert 'WCA '+wca.VERSION+' version string not detected' in script
    assert 'WCA '+wca.VERSION in (ROOT/'gui/index.html').read_text(encoding='utf-8')


def test_gui_assessment_checkboxes_have_fixed_width_override():
    css = (ROOT/'gui/app.css').read_text(encoding='utf-8')
    assert '.assessment-check input[type="checkbox"]' in css
    scoped = css.split('.assessment-check input[type="checkbox"]')[-1].split('}')[0]
    assert 'width:18px' in scoped and 'min-width:18px' in scoped
    assert 'flex:0 0 18px' in scoped


def test_current_documentation_links_and_release_identity():
    base = ROOT
    expected = ['README.md', 'RELEASE_NOTES.md', 'docs/getting-started.md',
                'docs/windows-environment-setup.md', 'docs/optional-tools.md',
                'docs/gui-guide.md', 'docs/windows-validation.md',
                'docs/troubleshooting.md']
    for name in expected:
        source = (base/name).read_text(encoding='utf-8')
        assert name == 'README.md' or source.strip()
        if name in {'README.md', 'RELEASE_NOTES.md', 'docs/getting-started.md',
                    'docs/windows-environment-setup.md', 'docs/gui-guide.md', 'docs/windows-validation.md'}:
            assert '2.2.0' in source, name
        for link in re.findall(r'(?<!!)\[[^]]+\]\(([^)]+)\)', source):
            if link.startswith(('http:', 'https:', '#','mailto:')):
                continue
            path = link.split('#')[0]
            if not path:
                continue
            assert (base/name).parent.joinpath(path).exists(), (name,link)
