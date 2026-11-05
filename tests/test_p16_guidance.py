import unittest
from modules.test_case_catalog import TEST_CASES
from modules.test_case_explanations import EXPLANATIONS

class P16GuidanceTests(unittest.TestCase):
    def test_complete_coverage(self):
        self.assertEqual(set(EXPLANATIONS), {c['id'] for c in TEST_CASES})
        for case in TEST_CASES:
            for key in ('procedure','how','expected','look_for','vulnerable','not_report'):
                self.assertTrue(case[key], (case['id'], key))
            self.assertGreaterEqual(len(case['how']), 3)

    def test_explicit_false_positive_cautions(self):
        for case_id in ('TC-CF-001','TC-PE-001','TC-IP-002','TC-SV-001','TC-NW-001'):
            case = next(c for c in TEST_CASES if c['id']==case_id)
            self.assertGreater(len(case['not_report']), 35)

if __name__ == '__main__': unittest.main()
