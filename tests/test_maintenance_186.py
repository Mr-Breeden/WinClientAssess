"""Vendor-neutral v1.8.6 Windows field issue regression coverage."""
from __future__ import annotations

import os
from unittest.mock import patch

from modules.advanced_runtime_review import run_advanced_runtime_review
from modules.local_storage_review import _runtime_storage_paths, run_local_storage_review
from utils.privacy import sanitize_report_text
from utils.sensitive_data import redact_sensitive_text


def test_windows_user_in_embedded_object_name_is_redacted_but_unrelated_accounts_survive():
    with patch.dict(os.environ, {'USERNAME': 'FixtureTester',
                                'USERPROFILE': r'C:\Users\FixtureTester'}, clear=False):
        raw = (r'\Sessions\1\BaseNamedObjects\UrlZonesSM_FixtureTester'
               '\n' r'\Sessions\1\BaseNamedObjects\UrlZonesSM_FixtureTesterOther'
               '\n' r'\Sessions\1\BaseNamedObjects\Generic_FixtureTester_Component'
               '\n' r'C:\Users\FixtureTester\Desktop\test.txt')
        result = sanitize_report_text(raw)
    assert 'UrlZonesSM_CURRENT_USER' in result
    assert 'UrlZonesSM_FixtureTesterOther' in result
    assert 'Generic_FixtureTester_Component' in result  # no blanket token replacement
    assert '%USERPROFILE%\\Desktop\\test.txt' in result
    assert 'UrlZonesSM_FixtureTester\n' not in result


def test_cross_line_sensitive_registry_name_does_not_create_redaction_artifact():
    raw = ('[POI-LS-001] HKCU\\Software\\Client\\CachedPassword\n'
           '=================================================================\n'
           'Area  : Registry\n'
           'AccessToken=meaningful-secret-value\n')
    result, indicators = redact_sensitive_text(raw)
    assert 'CachedPassword\n====' in result
    assert '\n=<REDACTED>' not in result
    assert 'AccessToken=<REDACTED>' in result
    assert 'meaningful-secret-value' not in result
    assert indicators['ACCESSTOKEN'] == 1


def _target():
    return [{'ProcessName': 'Client.exe', 'Path': 'Client.exe',
             'PortablePrimary': True, 'PrimarySHA256': 'a' * 64}]


def _live_verified():
    return [{'Name': 'Client.exe', 'Exe': r'C:\Users\FixtureTester\Desktop\ClientRoot\Client.exe',
             'IdentitySource': 'Selected primary executable SHA-256'}]


def test_verified_primary_process_recovers_portable_storage_without_load_image(tmp_path):
    procmon = {
        'loaded_images': [],
        'file_writes': [
            {'Process': 'Client.exe', 'Path': r'%USERPROFILE%\Desktop\ClientRoot\logs\activity.log', 'Operation': 'WriteFile'},
            {'Process': 'Client.exe', 'Path': r'%USERPROFILE%\Desktop\ClientRoot\data\app.db-journal', 'Operation': 'WriteFile'},
            {'Process': 'Client.exe', 'Path': r'%USERPROFILE%\Desktop\ClientRoot\settings.json', 'Operation': 'WriteFile'},
            {'Process': 'Client.exe', 'Path': r'C:\Windows\Temp\unrelated.log', 'Operation': 'WriteFile'},
            {'Process': 'Other.exe', 'Path': r'%USERPROFILE%\Desktop\ClientRoot\others.txt', 'Operation': 'WriteFile'},
        ], 'registry_writes': [],
    }
    with patch.dict(os.environ, {'USERNAME': 'FixtureTester',
                                'USERPROFILE': r'C:\Users\FixtureTester'}, clear=False):
        files, _ = _runtime_storage_paths(procmon, _target(), _live_verified())
        assert len(files) == 3
        assert all('verified primary process' in row['Area'] for row in files.values())
        without_identity, _ = _runtime_storage_paths(procmon, _target(),
                                                       [{**_live_verified()[0], 'IdentitySource': 'Process-name-only'}])
        assert without_identity == {}
        # An unrelated executable with the same basename must not establish a root.
        untrusted, _ = _runtime_storage_paths(procmon, _target(),
                                               [{**_live_verified()[0], 'Exe': r'C:\Other\Client.exe'}])
        assert not untrusted
        report = run_local_storage_review(tmp_path, procmon_data=procmon,
                                          runtime_targets=_target(), runtime_processes=_live_verified(),
                                          filesystem_evidence=False)
    assert len(report['storage_records']) == 3
    output = (tmp_path / 'local_storage_review.txt').read_text()
    assert '%USERPROFILE%' in output
    assert 'FixtureTester' not in output
    assert 'app.db-journal' in output
    assert 'unrelated.log' not in output


def _managed_setup(tmp_path, *, published=True):
    (tmp_path / 'dotnet_analysis.txt').write_text(
        f'Published .NET host detected: {published}\n.NET candidates: 1\n'
        'CANDIDATES\n-----------\n%SOURCE_DIR%\\Client.dll\n\n'
        'DECOMPILATION\n----------\n', encoding='utf-8')
    return [{'ProcessName': 'Client.exe', 'Path': 'Client.exe',
             'PortablePrimary': True, 'PrimarySHA256': 'f' * 64}]


def test_managed_context_preserves_published_host_without_clr_event(tmp_path):
    targets = _managed_setup(tmp_path)
    result = run_advanced_runtime_review(
        tmp_path, {}, targets,
        {'loaded_images': [{'Process': 'Client.exe', 'Path': r'C:\Windows\System32\ntdll.dll'}]},
        [{'Name': 'Client.exe'}], {}, 'full',
    )
    rows = [row for row in result['managed_context'] if row['Process'] == 'client.exe']
    assert len(rows) == 1
    assert rows[0]['PublishedHostStaticEvidence'] is True
    assert rows[0]['ManagedRuntimeObserved'] is False
    assert 'static evidence; CLR not observed' in rows[0]['Classification']
    contents = (tmp_path / 'runtime_managed_context.txt').read_text()
    assert 'Runtime target process identities classified' in contents and ': 1' in contents
    assert 'Native / unmanaged runtime observed' not in contents.split('[MCTX-001] client.exe')[-1]


def test_managed_context_does_not_infer_host_without_published_evidence(tmp_path):
    targets = _managed_setup(tmp_path, published=False)
    result = run_advanced_runtime_review(tmp_path, {}, targets,
                                         {'loaded_images': [{'Process': 'Client.exe', 'Path': r'C:\Windows\System32\ntdll.dll'}]},
                                         [{'Name': 'Client.exe'}], {}, 'full')
    row = next(row for row in result['managed_context'] if row['Process'] == 'client.exe')
    assert row['PublishedHostStaticEvidence'] is False
    assert row['ManagedRuntimeObserved'] is False
    assert row['Classification'] == 'Native / unmanaged runtime observed'
