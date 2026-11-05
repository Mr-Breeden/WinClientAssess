"""Regression: p18-p3 official guides and up-to-date candidate documentation."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class FinalP18P3Tests(unittest.TestCase):
    def test_guides_are_in_fifth_step_only(self):
        js = (ROOT / 'gui/app.js').read_text(encoding='utf-8')
        self.assertIn("if(item.id==='TC-AR-003' && i===4)step.appendChild(buildAdvancedModuleToolGuides())", js)
        self.assertIn('function buildAdvancedModuleToolGuides()', js)
        for url in (
            'https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg',
            'https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md',
            'https://frida.re/docs/quickstart/',
        ):
            self.assertEqual(js[js.index("function buildAdvancedModuleToolGuides()"):js.index("function addP18GuidanceExamples(")].count(url), 1, url)
        self.assertNotIn("'TC-AR-003':{title:'Optional advanced module analysis tools'", js)
        self.assertIn("link.rel='noopener noreferrer'", js)

    def test_catalog_step_is_still_fifth(self):
        from modules.test_case_catalog import TEST_CASES
        case = next(case for case in TEST_CASES if case['id'] == 'TC-AR-003')
        self.assertEqual(len(case['how']), 5)
        self.assertIn('WinDbg, Ghidra, or Frida', case['how'][4])

    def test_documentation_links_resolve(self):
        for md in list(ROOT.glob('*.md')) + list((ROOT / 'docs').glob('*.md')):
            for url in re.findall(r'\[[^\]]+\]\(([^)]+)\)', md.read_text(encoding='utf-8')):
                if url.startswith(('https:', 'http:', 'mailto:', '#')): continue
                path = url.split('#', 1)[0]
                if path: self.assertTrue((md.parent / path).exists(), f'{md}: {path}')

    def test_current_docs_are_not_historical_test_instructions(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertIn('**Version:** v2.2.3', readme)
        self.assertIn('`--cli`', readme)
        self.assertFalse((ROOT / 'docs/p15-field-testing.md').exists())
        self.assertFalse((ROOT / 'docs/v2.2.3-validation.md').exists())
        self.assertFalse((ROOT / 'docs/p20-rc1-validation.md').exists())

if __name__ == '__main__': unittest.main()
