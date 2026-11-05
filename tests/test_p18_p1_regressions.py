"""p18-p1: tester workspace and optional tool resource regression coverage."""
from pathlib import Path
import re
import unittest

from utils.tool_detection import TOOLS

ROOT = Path(__file__).resolve().parents[1]


class P18P1Tests(unittest.TestCase):
    def test_download_resource_for_every_detected_tool(self):
        js = (ROOT / 'gui' / 'app.js').read_text(encoding='utf-8')
        match = re.search(r'const toolVendorResources=Object\.freeze\(\{(.*?)\}\);', js, re.S)
        self.assertIsNotNone(match)
        declared = set(re.findall(r"^\s*'([^']+)':\s*\{url:", match.group(1), re.M))
        self.assertEqual(set(TOOLS), declared)
        for url in re.findall(r"url:'([^']+)'", match.group(1)):
            self.assertTrue(url.startswith('https://'))
        self.assertIn('vendorDownloadLink(t.name)', js)
        self.assertIn("'Download / Install'", js)
        self.assertIn("link.rel='noopener noreferrer'", js)

    def test_reference_key_only_in_testing_queue(self):
        html = (ROOT / 'gui' / 'index.html').read_text(encoding='utf-8')
        self.assertNotIn('id="abbreviationSearch"', html)
        self.assertNotIn('id="abbreviationTable"', html)
        self.assertIn('id="abbreviationSearchQueue"', html)
        self.assertIn('id="abbreviationTableQueue"', html)
        self.assertEqual(html.count('Reference key · What do TC'), 1)
        self.assertNotIn('Microsoft Sysinternals Suite</a>', html)

    def test_pe_mitigation_guide_is_in_step_three_not_bottom(self):
        js = (ROOT / 'gui' / 'app.js').read_text(encoding='utf-8')
        self.assertIn("const step=area?.querySelectorAll('.tc-procedure-step')[2]", js)
        self.assertIn('step.appendChild(buildPeMitigationGuide())', js)
        self.assertIn('if(target)addP18GuidanceExamples(target,item.id)', js)
        for phrase in ('Control Flow Guard (CFG)',
                       'Address Space Layout Randomization (ASLR)',
                       'Data Execution Prevention (DEP / NX)',
                       'Example: Indicators present',
                       'Example: Missing or limited metadata',
                       'not a confirmed vulnerability'):
            self.assertIn(phrase, js)
        self.assertIn('details', js)


if __name__ == '__main__':
    unittest.main()
