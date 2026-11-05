"""P19 regression: real p18-p3 network report formatting and review projections."""
import tempfile
import unittest
from pathlib import Path

from utils.target_evidence import stored_target_evidence


NETWORK_REPORT = """WCA - NETWORK SURFACE REVIEW
LISTENING / BOUND ENDPOINTS
[NW-001] veyon-server.exe (PID 7740)
  Protocol            : TCP
  Local Endpoint      : 127.0.0.1:11300
  State               : LISTEN
  Bind Scope          : Loopback only
  Execution User      : NT AUTHORITY\\SYSTEM

[NW-002] veyon-server.exe (PID 7740)
  Protocol            : TCP
  Local Endpoint      : 0.0.0.0:11100
  State               : LISTEN
  Bind Scope          : Wildcard / all interfaces
  Execution User      : NT AUTHORITY\\SYSTEM

[NW-003] other.exe (PID 9876)
  Protocol            : TCP
  Local Endpoint      : 0.0.0.0:22222
  State               : LISTEN
  Bind Scope          : Wildcard / all interfaces

NETWORK POINTS OF INTEREST
[POI-NW-001] veyon-server.exe - TCP 0.0.0.0:11100
"""


class P19NetworkEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'reports').mkdir()
        (self.root / 'reports' / 'network_surface_review.txt').write_text(NETWORK_REPORT, encoding='utf-8')

    def test_pid_name_pair_recovers_all_matching_endpoint_records(self):
        result = stored_target_evidence(self.root, 'network_surface_review.txt', '7740|veyon-server.exe')
        self.assertTrue(result['found'])
        self.assertTrue(result['historical'])
        self.assertEqual(result['matches'], 2)
        self.assertEqual([e['endpoint'] for e in result['network_endpoints']],
                         ['127.0.0.1:11300', '0.0.0.0:11100'])
        self.assertNotIn('22222', result['excerpt'])
        self.assertNotIn('POI-', result['excerpt'])

    def test_wrong_pid_does_not_fall_back_to_other_process(self):
        result = stored_target_evidence(self.root, 'network_surface_review.txt', '1234|veyon-server.exe')
        self.assertFalse(result['found'])

    def test_wrong_name_does_not_match_pid(self):
        self.assertFalse(stored_target_evidence(self.root, 'network_surface_review.txt', '7740|unrelated.exe')['found'])

    def test_network_path_does_not_change_regular_report_excerpts(self):
        (self.root / 'reports' / 'file_review.txt').write_text('Artifact: safe-file.txt\nStatus: REVIEW\n')
        result = stored_target_evidence(self.root, 'file_review.txt', 'safe-file.txt')
        self.assertTrue(result['found'])
        self.assertNotIn('network_endpoints', result)

    def test_symlink_report_rejected(self):
        outside = self.root / 'private.txt'
        outside.write_text('test')
        try:
            (self.root / 'reports' / 'unsafe.txt').symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('Creating symlinks requires privileges or Developer Mode on some Windows hosts')
        self.assertFalse(stored_target_evidence(self.root, 'unsafe.txt', 'test')['found'])

    def test_no_arbitrary_report_identifiers(self):
        with self.assertRaises(ValueError):
            stored_target_evidence(self.root, '../private.txt', 'test')


class P19StructuralTests(unittest.TestCase):
    def test_codegen_keeps_provenance_before_coverage_interpretation(self):
        source = (Path(__file__).parents[1] / 'utils' / 'reporting.py').read_text()
        self.assertLess(source.index('finalize_provenance(self.assessment_dir'), source.index("provenance_file = self.assessment_dir"))

    def test_network_result_rendered_as_table(self):
        js = (Path(__file__).parents[1] / 'gui' / 'app.js').read_text()
        self.assertIn('response.network_endpoints.map(', js)
        self.assertIn('Historical collected socket observations', js)

    def test_historical_manual_state_never_changes_active_total(self):
        source = (Path(__file__).parents[1] / 'utils' / 'manual_test_workflow.py').read_text()
        self.assertIn("'historical_saved_decisions': len(historical_ids)", source)
        self.assertIn("'total': len(cases)", source)

    def test_stale_patch_label_removed(self):
        source = (Path(__file__).parents[1] / 'modules' / 'permissions_review.py').read_text()
        self.assertNotIn('P17 includes application-scoped', source)

    def test_runtime_candidate_wording_keeps_original_stable_identity(self):
        from utils.guided_review import _finding_candidates, _digest
        title = 'Sensitive Values Exposed in Runtime Process Evidence'
        finding = {'title': title, 'source_module': 'Procmon Analysis',
                   'evidence': '2 redacted sensitive fields', 'description': 'manual review'}
        item = _finding_candidates(self.root if hasattr(self, 'root') else Path(__file__).parents[1],
                                   [finding], set())[0]
        self.assertEqual(item['identity'],
                         'Procmon Analysis|finding|sensitive values exposed in runtime process evidence|sensitive values exposed in runtime process evidence')
        self.assertIn('Observed', item['title'])
        self.assertEqual(_digest(item['identity']).upper(), 'AFD91F00FD30D4')

    def test_runtime_candidate_wording_not_overstated(self):
        source = (Path(__file__).parents[1] / 'utils' / 'guided_review.py').read_text()
        self.assertIn('Sensitive Values Observed in Runtime Process Evidence', source)
        self.assertIn("identity': identity", source)
        # The persisted finding title is unchanged to keep stable legacy IDs.
        finding = (Path(__file__).parents[1] / 'modules' / 'procmon_analysis.py').read_text()
        self.assertIn('Sensitive Values Exposed in Runtime Process Evidence', finding)


if __name__ == '__main__':
    unittest.main()
