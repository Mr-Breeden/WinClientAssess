"""P18-p2 targeted regression checks: concise results, no duplicate secrets, safe links."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from utils.configuration_source_paths import resolve_configuration_artifact
from utils.test_case_checks import _raw_checks
from modules.test_case_catalog import TEST_CASES

ROOT = Path(__file__).resolve().parents[1]

class P18P2Tests(unittest.TestCase):
    def test_safe_verified_configuration_path_resolution(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'reports').mkdir()
            target = root/'working'/'extracted_installer'/'interception'/'install.bat'
            target.parent.mkdir(parents=True)
            target.write_text('@echo off\n')
            displayed = r'%SOURCE_DIR%\example-assessment\working\extracted_installer\interception\install.bat'
            (root/'reports'/'configuration_review.txt').write_text('[SCR-001] '+displayed+' | Size: 8 B\n')
            self.assertEqual(resolve_configuration_artifact(root, displayed), target)
            for bad in (r'%SOURCE_DIR%\example-assessment\working\extracted_installer\..\private.txt',
                        r'C:\Windows\System32\cmd.exe',
                        r'%SOURCE_DIR%\example-assessment\working\extracted_installer\not-listed.bat'):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    resolve_configuration_artifact(root, bad)
            target.unlink()
            with self.assertRaises(ValueError):
                resolve_configuration_artifact(root, displayed)

    def test_secret_case_does_not_offer_duplicate_recheck(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'reports').mkdir()
            (root/'reports'/'secrets_review.txt').write_text('STRUCTURED PRIVATE KEY (1)\n')
            cf = next(c for c in TEST_CASES if c['id']=='TC-CF-001')
            checks = _raw_checks(root, cf)
            self.assertFalse(any(x['kind']=='secrets' for x in checks))
            self.assertIn('Potential Secret Indicator Review', ' '.join(cf['how']))
            self.assertNotIn('Review Redacted Indicator Locations', ' '.join(cf['how']))

    def test_inline_shared_mitigation_warning_and_compact_dumpbin(self):
        js = (ROOT/'gui/app.js').read_text(encoding='utf-8')
        gui = (ROOT/'gui/index.html').read_text(encoding='utf-8')
        start = js.index('function buildPeMitigationGuide()')
        end = js.index('function addP18GuidanceExamples',start)
        guide = js[start:end]
        self.assertEqual(guide.count("el('div',undefined,'p18-warning')"),1)
        self.assertIn('sharedWarning',guide)
        start = js.index('function peAutoRender(job)')
        end = js.index("$('peAutoScope').addEventListener",start)
        render = js[start:end]
        self.assertNotIn('row.raw_file}`).join',render)
        self.assertIn('PE files analyzed',render)
        self.assertIn('require CFG applicability review',render)
        self.assertIn('peAutoDownload',render)
        self.assertIn('queueConfigSources',gui)
        self.assertIn('/api/config-open-location',js)
        self.assertIn('/api/config-source-path',js)

if __name__=='__main__':
    unittest.main()
