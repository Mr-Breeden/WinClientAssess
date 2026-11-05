"""P17 regression cases derived from the Veyon field-test observations."""
from pathlib import Path
import inspect
import unittest
from modules.secrets_review import _plain_candidates, _key_blocks
from utils.credential_classifier import credential_field
from modules.permissions_review import _candidate_paths
from modules.dll_search_review import run_dll_search_review
from utils.pe_dumpbin_validation import PeDumpbinJobs

class P17Regression(unittest.TestCase):
    def test_reject_mask_and_redaction(self):
        for value in ('****','********','[hidden]','[REDACTED]','<redacted>','[masked]','your_password_here'):
            with self.subTest(value=value):
                self.assertFalse(credential_field('SASL_PASSWD', value))

    def test_cpp_signature_fragments(self):
        for value in (':read(QString*&,', ':write(const', ':hasCredentials(Type)', ':loadPrivateKey(const'):
            with self.subTest(value=value):
                self.assertFalse(credential_field('Password',value))
        text='static bool PersistentLogonCredentials::read(QString*&, Password*)'
        self.assertEqual(list(_plain_candidates(text,format_hint='pe')), [])

    def test_keep_actual_value(self):
        self.assertTrue(credential_field('password','ExampleCredential123!'))
        self.assertTrue(credential_field('api_key','ExampleApiKeyValue1234567890'))

    def test_no_pem_marker_only(self):
        self.assertEqual(list(_key_blocks(b'-----BEGIN PRIVATE KEY-----',Path('fake.dll'),'PE file offset')),[])

    def test_directory_inventory_includes_nested_snapshot_dirs(self):
        root=r'C:\Program Files\Veyon'
        diff={'Filesystem':{'added':[
            {'Path':root+r'\plugins', 'IsDirectory':True,'Root':root},
            {'Path':root+r'\plugins\subfolder','IsDirectory':True,'Root':root}], 'changed':[]}}
        records=_candidate_paths({}, {}, diff, [root])
        self.assertIn(root.lower()+r'\plugins\subfolder', [r['Path'].lower() for r in records])

    def test_dll_report_explains_heuristics(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            row={'Process':'veyon-configurator.exe','Path':r'C:\Users\Public\AppData\Local\Programs\Microsoft VS Code\bin\thai.dll','Result':'NAME NOT FOUND'}
            result=run_dll_search_review(Path(d),procmon_data={'missing_dlls':[row]})
            report=(Path(d)/'reports'/'dll_search_review.txt')
            if not report.exists():
                report=next(Path(d).rglob('dll_search_review.txt'))
            self.assertIn('Environment PATH', report.read_text())
            self.assertIn('review-point rule', report.read_text())

    def test_wcr_candidate_guidance_is_attached(self):
        js=(Path(__file__).resolve().parents[1]/'gui'/'app.js').read_text()
        self.assertIn('function candidateNextSteps(detail)',js)
        self.assertIn('holder.appendChild(renderCandidateSteps(detail))',js)
        for phrase in ('Network endpoint validation','IPC protocol and authorization validation','DLL resolution validation','Sensitive-value validation'):
            self.assertIn(phrase,js)

if __name__=='__main__':unittest.main()
