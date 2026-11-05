"""p18 regression checks for core behavior independent of Windows-only tools."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from utils.gui_catalog import RecentAssessments
from utils.target_evidence import stored_target_evidence
from utils.pe_dumpbin_validation import PeDumpbinJobs
from modules.snapshots import _wca_temp_entry

ROOT = Path(__file__).resolve().parents[1]


class P18Tests(unittest.TestCase):
    def test_recent_removal_preserves_directory_and_suppresses_parent_discovery(self):
        with TemporaryDirectory() as temp:
            base = Path(temp)
            catalog = RecentAssessments(base / 'recents.json')
            folder = base / 'old-assessment'
            folder.mkdir()
            (folder / 'working').mkdir()
            (folder / 'working' / 'assessment_state.json').write_text('{}')
            catalog.remember(folder)
            catalog.remove(str(folder))
            self.assertTrue(folder.is_dir())
            self.assertNotIn(str(folder), [x['path'] for x in catalog.list_recent()])
            self.assertIn(str(folder), catalog._read()['removed'])
            catalog.remember(folder)
            self.assertNotIn(str(folder), catalog._read()['removed'])

    def test_removing_unknown_recent_rejected(self):
        with TemporaryDirectory() as temp:
            catalog = RecentAssessments(Path(temp) / 'recents.json')
            with self.assertRaises(ValueError):
                catalog.remove('/totally/unrelated/path')

    def test_target_acl_parses_without_running_live_commands(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'reports').mkdir()
            (root / 'reports' / 'permissions_review.txt').write_text('''[ACL-001] Service directory
Path : C:\\Program Files\\Example
Owner : BUILTIN\\Administrators
Broad Write ACEs (1)
All ACL Entries (2)
  [01]
    Identity : BUILTIN\\Users
    Rights : Modify
    Type : Allow
    Inherited: True
  [02]
    Identity : NT AUTHORITY\\SYSTEM
    Rights : FullControl
    Type : Allow
    Inherited: False
[ACL-002] Other path
Path : C:\\Other
''')
            data = stored_target_evidence(root, 'permissions_review.txt', r'C:\Program Files\Example')
            self.assertTrue(data['found'])
            self.assertEqual(data['acl']['owner'], r'BUILTIN\Administrators')
            self.assertTrue(data['acl']['broad_write_indicated'])
            self.assertEqual(len(data['acl']['entries']), 2)
            self.assertNotIn('C:\\Other', data['excerpt'])

    def test_bounded_report_rejects_traversal(self):
        with TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                stored_target_evidence(Path(temp), '../secrets.txt', 'target')
            with self.assertRaises(ValueError):
                stored_target_evidence(Path(temp), 'example.txt', '')

    def test_wca_only_snapshot_origin(self):
        self.assertTrue(_wca_temp_entry({'Path':r'C:\Users\Test\AppData\Local\Temp\wca-gui-abcd123\worker.log'}))
        self.assertFalse(_wca_temp_entry({'Path':r'C:\Program Files\Veyon\veyon-service.exe'}))
        self.assertFalse(_wca_temp_entry({'Path':r'C:\Program Files\Vendor\wca-gui.exe'}))

    def test_dumpbin_archive_wca_owned_and_nonempty(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / 'assessment'
            root.mkdir()
            manager = PeDumpbinJobs()
            jobid = 'test123'
            folder = Path(temp) / 'assessment-TC-PE-001-DUMPBIN' / 'Run-test'
            folder.mkdir(parents=True)
            (folder / 'TC-PE-001-PE-0001_test_dump.txt').write_text('PE signature found\n')
            (folder / 'TC-PE-001-CFG-Summary.txt').write_text('SUMMARY\n')
            manager.jobs[jobid] = {'id':jobid,'state':'COMPLETED','assessment':str(root), 'folder':str(folder), 'rows':[]}
            archive, name = manager.package(jobid, root)
            self.assertIn('TC-PE-001', name)
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(archive)) as z:
                self.assertEqual(len(z.namelist()), 2)
            (folder / 'TC-PE-001-PE-0001_test_dump.txt').unlink()
            with self.assertRaises(ValueError):
                manager.package(jobid, root)

    def test_gui_controls_exist(self):
        js=(ROOT/'gui/app.js').read_text()
        html=(ROOT/'gui/index.html').read_text()
        self.assertIn('addP18GuidanceExamples', js)
        self.assertIn('peAutoDownload', html)
        self.assertIn('abbreviationSearch', html)
        self.assertIn('recent-remove', js)
        self.assertNotIn('Find selected target in source report →', js)
        self.assertIn('p18-warning', js)
        self.assertIn('Optional live read-only recheck', js)
        self.assertIn('STEP ${i+1}', js)

    def test_runtime_temp_report_is_rewritten_on_staging(self):
        source=(ROOT/'modules/guided_runtime_observation.py').read_text()
        self.assertIn('elif report_name == "runtime_secrets_review.txt"',source)
        self.assertIn('no target-scoped sanitized CSV was retained',source)


if __name__ == '__main__':
    unittest.main()
