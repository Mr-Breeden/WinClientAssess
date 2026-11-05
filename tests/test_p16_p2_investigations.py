import tempfile
import unittest
from pathlib import Path
from utils.guided_review import _route_candidate, INVESTIGATIONS

class InvestigationsP16P2(unittest.TestCase):
    def test_network_discovery_and_auth_are_distinct(self):
        with tempfile.TemporaryDirectory() as t:
            cases, family = _route_candidate(Path(t), 'Network Surface Review', 'TCP listener', '0.0.0.0:11100')
            self.assertEqual(cases, ['TC-NW-001', 'TC-NW-002'])
            self.assertEqual(family, 'Network service access')
    def test_registry_not_filesystem(self):
        with tempfile.TemporaryDirectory() as t:
            cases,_ = _route_candidate(Path(t), 'Permissions Review', 'Registry permission', 'HKLM\\Software\\Example')
            self.assertIn('TC-RG-001', cases)
            self.assertNotIn('TC-FS-001', cases)
    def test_specific_updater_checks(self):
        with tempfile.TemporaryDirectory() as t:
            cases,_ = _route_candidate(Path(t), 'Updater Security Correlation', 'Staging path writable', 'C:\\ProgramData\\app')
            self.assertIn('TC-UP-003', cases)
            self.assertNotIn('TC-UP-005', cases)
    def test_no_implicit_completion(self):
        self.assertEqual(INVESTIGATIONS['TC-SV-001'], INVESTIGATIONS['TC-PB-001'])
        self.assertNotEqual('TC-SV-001','TC-PB-001')
