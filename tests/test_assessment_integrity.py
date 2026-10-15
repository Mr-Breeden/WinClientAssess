"""v1.4.0 integrity and privacy contract. No Windows installer execution required."""
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.installer_extract import run_installer_extract
from utils.assessment_integrity import (
    create_manifest, verify_assessment, regenerate_derived_reports,
    DERIVED_REPORTS,
)
from utils.assessment_layout import artifact_path, generated_directory_path
from utils.assessment_state import AssessmentState
from utils.reporting import AssessmentReporter
from utils.sensitive_data import sanitize_procmon_csv


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.installer = base / 'Fixture.msi'
        self.installer.write_bytes(b'controlled fixture')
        self.root = base / 'assessment'

    def fixture(self, mode='full', payload=True):
        state = AssessmentState.create(
            self.root, assessment_name='Fixture', installer=self.installer,
            mode=mode, framework_version='1.4.0', options={}, tools={},
        )
        reporter = AssessmentReporter(self.root, 'Fixture', self.installer, mode, '1.4.0', state_tracker=state)
        (self.root / 'reports' / 'installer_analysis.txt').write_text('Source observations\n', encoding='utf-8')
        reporter.set_status('Installer Information', 'PASS', 'Identified installer')
        if mode == 'full':
            snapshot = artifact_path(self.root, 'snapshot_pre.json')
            snapshot.write_text('{"CollectionErrors": [], "Services": [{"Name": "EventLog"}], "ScheduledTasks": []}', encoding='utf-8')
            state.record_snapshot_integrity('pre_install_snapshot', 'snapshot_pre.json')
            state.checkpoint('pre_install_snapshot', 'COMPLETED')
        if payload:
            directory = generated_directory_path(self.root, 'extracted_installer')
            directory.mkdir(exist_ok=True)
            (directory / 'payload.unknown').write_bytes(b'payload')
        reporter.add_finding(title='Potential test condition', severity='Low',
                             description='Review only', source_module='Installer Information')
        coverage = reporter.finalize()
        state.mark_complete(coverage)
        create_manifest(self.root, framework_version='1.4.0', methodology_version='1.0', catalog_version='1.0')
        return state

    def test_fresh_manifest_inventory_and_versions(self):
        self.fixture()
        result = verify_assessment(self.root)
        self.assertEqual('PASS', result['status'], result['checks'])
        manifest = result['manifest']
        self.assertEqual('1.4.0', manifest['framework_version'])
        self.assertIn('reports/assessment_report.html', manifest['files']['reports'])
        self.assertIn('working/assessment_state.json', manifest['files']['supporting'])
        self.assertIn('working/report_render_state.json', manifest['files']['supporting'])
        self.assertIn('working/extracted_installer/payload.unknown', manifest['files']['payloads'])
        self.assertEqual(1, manifest['extraction_trees']['working/extracted_installer']['files'])
        self.assertNotIn(str(self.installer.parent), json.dumps(manifest))

    def test_vendor_tmp_payload_is_not_mistaken_for_atomic_orphan(self):
        self.fixture()
        payload = self.root / 'working' / 'extracted_installer' / 'vendor.tmp'
        payload.write_text('original installer payload')
        create_manifest(self.root, framework_version='1.4.0')
        result = verify_assessment(self.root)
        self.assertEqual('PASS', result['status'], result['checks'])

    def test_report_single_byte_tampering_is_detected_and_repaired(self):
        self.fixture()
        report = self.root / 'reports' / 'assessment_report.html'
        report.write_bytes(report.read_bytes() + b'!')
        result = verify_assessment(self.root)
        self.assertEqual('FAIL', result['status'])
        self.assertTrue(result['repairable'])
        restored = regenerate_derived_reports(self.root)
        self.assertEqual('PASS', restored['status'], restored['checks'])
        self.assertIn('Automated Review Points', report.read_text(encoding='utf-8'))

    def test_missing_generated_status_can_be_restored(self):
        self.fixture()
        (self.root / 'reports' / 'module_status.txt').unlink()
        result = verify_assessment(self.root)
        self.assertTrue(result['repairable'])
        self.assertEqual('PASS', regenerate_derived_reports(self.root)['status'])

    def test_primary_report_tamper_prevents_repair(self):
        self.fixture()
        (self.root / 'reports' / 'installer_analysis.txt').write_text('edited')
        (self.root / 'reports' / 'findings.txt').write_text('edited')
        result = verify_assessment(self.root)
        self.assertFalse(result['repairable'])
        with self.assertRaises(ValueError):
            regenerate_derived_reports(self.root)

    def test_missing_snapshot_prevents_repair_even_if_html_modified(self):
        self.fixture()
        (self.root / 'working' / 'snapshot_pre.json').unlink()
        (self.root / 'reports' / 'assessment_report.html').write_text('changed')
        result = verify_assessment(self.root)
        self.assertEqual('FAIL', result['status'])
        self.assertFalse(result['repairable'])

    def test_extraction_mutation_detected_and_not_regenerated(self):
        self.fixture()
        (self.root / 'working' / 'extracted_installer' / 'payload.unknown').write_bytes(b'new payload')
        result = verify_assessment(self.root)
        self.assertEqual('FAIL', result['status'])
        self.assertFalse(result['repairable'])

    def test_orphan_temp_and_unexpected_known_report_detected(self):
        self.fixture()
        (self.root / 'reports' / 'module_status.txt.tmp').write_text('stale')
        (self.root / 'reports' / 'signature_review.txt').write_text('stale generated report')
        result = verify_assessment(self.root)
        self.assertEqual('FAIL', result['status'])
        self.assertTrue(any('Orphan' in issue for check in result['checks'] for issue in check['issues']))
        self.assertTrue(any('Unrecorded generated' in issue for check in result['checks'] for issue in check['issues']))

    def test_unknown_user_notes_attention_not_fabricated_failure(self):
        self.fixture()
        (self.root / 'reports' / 'manual_notes.md').write_text('tester notes')
        self.assertEqual('ATTN', verify_assessment(self.root)['status'])

    def test_mode_inapplicable_even_if_recorded(self):
        self.fixture(mode='static')
        (self.root / 'reports' / 'services_review.txt').write_text('stale installed report')
        create_manifest(self.root, framework_version='1.4.0')
        result = verify_assessment(self.root)
        self.assertEqual('FAIL', result['status'])
        self.assertTrue(any('Mode-inapplicable' in issue for check in result['checks'] for issue in check['issues']))

    def test_missing_optional_evidence_is_not_an_integrity_failure(self):
        self.fixture(mode='static', payload=False)
        self.assertEqual('PASS', verify_assessment(self.root)['status'])

    def test_missing_version_metadata_returns_fail_instead_of_crashing(self):
        self.fixture()
        path = self.root / 'working' / 'assessment_manifest.json'
        data = json.loads(path.read_text())
        del data['framework_version']
        path.write_text(json.dumps(data))
        self.assertEqual('FAIL', verify_assessment(self.root)['status'])

    def test_manifest_traversal_rejected(self):
        self.fixture()
        path = self.root / 'working' / 'assessment_manifest.json'
        manifest = json.loads(path.read_text())
        manifest['files']['reports']['reports/../../outside.txt'] = {'size': 1, 'sha256': '0' * 64}
        path.write_text(json.dumps(manifest))
        self.assertEqual('FAIL', verify_assessment(self.root)['status'])

    def test_checkpoint_snapshot_mutation_halts_recovery(self):
        state = self.fixture()
        state.data['status'] = 'INTERRUPTED'
        state.save()
        self.assertEqual('INSTALL', state.recovery_action()[0])
        (self.root / 'working' / 'snapshot_pre.json').write_text('{"CollectionErrors": [], "Services": [{"Name": "EventLog"}], "ScheduledTasks": [], "x": 1}')
        action, guidance = state.recovery_action()
        self.assertEqual('HALT', action)
        self.assertIn('snapshot', guidance)

    def test_checkpoint_absent_checksum_halts_in_v140(self):
        state = self.fixture()
        state.data['checkpoint_integrity'].clear()
        state.data['status'] = 'INTERRUPTED'
        self.assertEqual('HALT', state.recovery_action()[0])


class TestPrivacyAndExtraction(unittest.TestCase):
    def test_procmon_process_environment_is_omitted_in_all_retained_csvs(self):
        with tempfile.TemporaryDirectory() as td, patch.dict('os.environ', {
            'USERNAME': 'AssessmentTester', 'USERPROFILE': r'C:\Users\AssessmentTester',
            'COMPUTERNAME': 'WIN-LAB-TESTER',
        }):
            root = Path(td)
            raw, clean = root / 'input.csv', root / 'clean.csv'
            with raw.open('w', newline='', encoding='utf-8') as fh:
                writer = csv.DictWriter(fh, fieldnames=['Process Name', 'Operation', 'Path', 'Detail'])
                writer.writeheader()
                writer.writerow({'Process Name': 'client.exe', 'Operation': 'Process Create',
                                 'Path': r'C:\Users\AssessmentTester\app.exe',
                                 'Detail': 'Parent PID: 5, Command line: client.exe, Environment: CUSTOM_SECRET=super-raw-leak; NORMAL_VALUE=private-other-value; USERNAME=AssessmentTester'})
            outcome = sanitize_procmon_csv(raw, clean)
            text = clean.read_text(encoding='utf-8-sig')
            self.assertEqual(1, outcome['rows'])
            for forbidden in ('AssessmentTester', 'super-raw-leak', 'private-other-value'):
                self.assertNotIn(forbidden, text)
            self.assertIn('Parent PID: 5', text)
            self.assertIn('[PROCESS ENVIRONMENT OMITTED]', text)
            self.assertIn('CUSTOM_SECRET=<REDACTED>', text)
            again = root / 'second.csv'
            self.assertEqual(1, sanitize_procmon_csv(clean, again)['redaction_count'])
            self.assertNotIn('super-raw-leak', again.read_text(encoding='utf-8-sig'))

    def test_recovery_extraction_clears_only_generated_subtree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from utils.assessment_layout import ensure_structured_layout
            ensure_structured_layout(root)
            installer = root / 'fixture.msi'
            installer.write_bytes(b'mock')
            extract = generated_directory_path(root, 'extracted_installer')
            extract.mkdir()
            (extract / 'previous-extractor.bin').write_bytes(b'outdated')
            (root / 'working' / 'snapshot_pre.json').write_text('retain')

            def fake_run(args, timeout=0):
                (extract / 'current-extractor.bin').write_bytes(b'current')
                return {'returncode': 0, 'stdout': '', 'stderr': ''}
            with patch('modules.installer_extract.run_command', side_effect=fake_run):
                result = run_installer_extract(installer, root, {'lessmsi': {'path': 'lessmsi.exe'}}, defer_report=True)
            self.assertEqual('PASS', result['status'])
            self.assertFalse((extract / 'previous-extractor.bin').exists())
            self.assertTrue((extract / 'current-extractor.bin').exists())
            self.assertEqual('retain', (root / 'working' / 'snapshot_pre.json').read_text())


if __name__ == '__main__':
    unittest.main()
