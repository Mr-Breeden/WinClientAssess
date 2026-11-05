"""Portable focused regression suite: python -m unittest discover -s tests -v"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from collections import Counter
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from modules.secrets_review import _eligible_text,_text_matches,_pe_matches,run_secrets_review
from modules.configuration_review import _configuration_indicators
from utils.structured_secret_validator import pem_candidates
from utils.credential_classifier import credential_field
from utils.assessment_compare import _canonical_evidence_line,_records
from utils.secret_indicator_viewer import parse_indicators,indicator_context,_owned_source


class P15Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def write(self,name,content,encoding='utf-8'):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True)
        if isinstance(content,bytes):p.write_bytes(content)
        else:p.write_text(content,encoding=encoding)
        return p

    def test_env_filenames(self):
        for name in ['.env','.env.production','.env.local','.env-development','app.env']:
            with self.subTest(name=name):self.assertTrue(_eligible_text(self.root/name))

    def test_env_credential_detection(self):
        p=self.write('.env.production','GA_API_SECRET=valid_demo_credential_1234\nGA_MEASUREMENT_ID=G-12EXAMPLE\n')
        found=[];_text_matches([p],found)
        self.assertEqual(1,len(found))
        self.assertEqual('Named credential assignment',found[0]['type'])
        self.assertEqual(1,found[0]['line'])
        self.assertNotIn('valid_demo_credential',repr(found))

    def test_utf16_env(self):
        p=self.write('.env.local','Dga_api_secret=demo_credential_123456\n',encoding='utf-16')
        found=[];_text_matches([p],found)
        self.assertEqual(1,len(found))
        self.assertEqual('UTF-16LE',found[0]['encoding'])

    def test_qt_markup_suppressed(self):
        from modules.secrets_review import _plain_candidates
        source='<h3>About Qt</h3><p>This program uses Qt version %1.</p>\nqt_msgbox_buttonbox'
        self.assertEqual([],list(_plain_candidates(source,format_hint='pe')))

    def test_real_xml_credential(self):
        from modules.secrets_review import _plain_candidates
        self.assertEqual('XML credential element',next(_plain_candidates('<apiSecret>actual_demo_credential</apiSecret>',format_hint='pe'))[0])

    def test_public_ids_and_placeholders(self):
        for key,val in [('GA_MEASUREMENT_ID','G-TEST123'),('public_key','abc123'),('api_secret','changeme'),('password','${PASSWORD}')]:
            self.assertFalse(credential_field(key,val))
        self.assertTrue(credential_field('GA_API_SECRET','demo_secret_98765'))

    def _key(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())

    def test_key_validated_and_fingerprint(self):
        data=self._key()
        records=list(pem_candidates(data))
        self.assertEqual(1,len(records))
        self.assertEqual('VALID_KEY',records[0][3]['validation'])
        self.assertEqual(2048,records[0][3]['key_bits'])
        self.assertEqual(64,len(records[0][3]['public_fingerprint']))

    def test_key_marker_not_validation(self):
        records=list(pem_candidates(b'-----BEGIN PRIVATE KEY-----'))
        self.assertEqual('MARKER_ONLY',records[0][3]['validation'])

    def test_encrypted_label_not_decrypted(self):
        # Structural envelope only; never provide a password or attempt decryption.
        from utils.structured_secret_validator import inspect_pem
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        encrypted=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                    serialization.BestAvailableEncryption(b'test-only-password'))
        self.assertEqual('ENCRYPTED_NOT_DECRYPTED',inspect_pem(encrypted,'ENCRYPTED PRIVATE KEY')['validation'])
        self.assertEqual('INVALID_OR_UNSUPPORTED',inspect_pem(b'fake','ENCRYPTED PRIVATE KEY')['validation'])

    def test_key_persists_only_metadata(self):
        key=self._key();p=self.write('fixture.pem',key)
        found=[];_text_matches([p],found)
        self.assertEqual(1,len(found))
        self.assertEqual('VALID_KEY',found[0]['validation'])
        self.assertNotIn(key.decode()[:120],repr(found))

    def test_qt_like_pe_not_secret(self):
        p=self.write('Qt6Widgets.dll',b'MZ'+b'\0'*200+b'<h3>About Qt</h3>\0<p>This program uses Qt version %1.</p>')
        found=[]
        with patch('modules.secrets_review._has_pe_header',return_value=True):
            self.assertEqual(1,_pe_matches([p],found))
        self.assertEqual([],found)

    def test_pe_credential_offsets_utf16le(self):
        text='GA_API_SECRET=demotoken123456'
        p=self.write('fixture.dll',b'MZ'+b'\0'*200+text.encode('utf-16le'))
        found=[]
        with patch('modules.secrets_review._has_pe_header',return_value=True):
            _pe_matches([p],found)
        self.assertEqual(1,len(found))
        self.assertEqual('UTF-16LE',found[0]['encoding'])

    def test_comparison_extract_root_normalized(self):
        a=r'%SOURCE_DIR%\V6-Testing\wca-2.2.3-p13-veyon-static\working\extracted_installer\ddengine64.dll'
        b=r'%SOURCE_DIR%\wca-2.2.3-p14-veyon-static\working\extracted_installer\ddengine64.dll'
        self.assertEqual(_canonical_evidence_line(a,'wca-2.2.3-p13-veyon-static'),
                         _canonical_evidence_line(b,'wca-2.2.3-p14-veyon-static'))

    def test_installed_paths_preserved(self):
        self.assertNotEqual(_canonical_evidence_line(r'C:\Program Files\App\service.dll','A'),
                            _canonical_evidence_line(r'C:\Users\Public\service.dll','B'))

    def test_pe_sequence_number_not_identity(self):
        name=self.root.name
        (self.root/'reports').mkdir()
        p=self.root/'reports'/'binary_security_review.txt'
        p.write_text('[PE-002] %SOURCE_DIR%\\old\\working\\extracted_installer\\test.dll\n  ASLR : True\n')
        old=_records(self.root,'binary_security_review.txt')
        p.write_text('[PE-017] %SOURCE_DIR%\\new\\working\\extracted_installer\\test.dll\n  ASLR : True\n')
        new=_records(self.root,'binary_security_review.txt')
        self.assertEqual(old,new)

    def test_verified_manifest_payload_change(self):
        import json
        from utils.assessment_compare import _compare_payloads
        a=self.root/'baseline';b=self.root/'comparison'
        for root,h in ((a,'a'*64),(b,'b'*64)):
            (root/'working').mkdir(parents=True)
            data={'files':{'payloads':{
                'working/extracted_installer/app.dll':{'sha256':h,'size':100},
                'working/extracted_installer/same.dll':{'sha256':'c'*64,'size':10}}}}
            (root/'working'/'assessment_manifest.json').write_text(json.dumps(data))
        result=_compare_payloads(a,b)
        self.assertEqual(1,result['changed_total'])
        self.assertEqual(1,result['unchanged'])
        self.assertEqual(0,result['new_total'])
        self.assertEqual(0,result['removed_total'])

    def test_reused_key_public_fingerprint_group(self):
        key=self._key()
        one=self.write('a.pem',key);two=self.write('b.pem',key)
        found=[];_text_matches([one,two],found)
        self.assertEqual(2,len(found))
        self.assertEqual(found[0]['public_fingerprint'],found[1]['public_fingerprint'])
        self.assertNotIn(key.decode()[:100],repr(found))

    def test_old_report_compatibility(self):
        sample='PRIVATE KEY MARKER (1)\n[SECRET-040] Confidence=HIGH\n  File : %SOURCE_DIR%\\one\\working\\extracted_installer\\a.dll\n  PE file offset : 0x20\n'
        rows=parse_indicators(sample)
        self.assertEqual('SECRET-040',rows[0]['id'])
        self.assertEqual('0x20',rows[0]['offset'])

    def test_source_traversal_prohibited(self):
        self.assertIsNone(_owned_source(self.root,r'%SOURCE_DIR%\working\extracted_installer\..\escape.dll'))

    def test_symlinked_working_tree_prohibited(self):
        outside=self.root/'external';outside.mkdir()
        self.write('external/extracted_installer/demo.pem','test-data')
        try:(self.root/'working').symlink_to(outside,target_is_directory=True)
        except (OSError,NotImplementedError):self.skipTest('Symlink creation unavailable')
        self.assertIsNone(_owned_source(self.root,r'%SOURCE_DIR%\working\extracted_installer\demo.pem'))

    def test_viewer_displays_complete_key_without_report_leak(self):
        key=self._key()
        p=self.write('working/extracted_installer/demo.pem',key)
        report='STRUCTURED PRIVATE KEY (1)\n[SECRET-001] Confidence=HIGH\n  File : %SOURCE_DIR%\\test\\working\\extracted_installer\\demo.pem\n  Line : 1\n  String encoding : Text\n  Validation : VALID_KEY\n'
        self.write('reports/secrets_review.txt',report)
        with patch('utils.secret_indicator_viewer.verify_assessment',return_value={'status':'PASS'}):
            data=indicator_context(self.root,'SECRET-001')
        self.assertEqual(key.decode().rstrip('\r\n'),data['original_value'])
        self.assertEqual('OBSERVED',data['status'])
        self.assertEqual(report,(self.root/'reports'/'secrets_review.txt').read_text())

    def test_configuration_env_included(self):
        p=self.write('.env','debug=true\n')
        found=_configuration_indicators([{'path':str(p)}])
        self.assertTrue(any(x['setting']=='debug' for x in found))


if __name__=='__main__':unittest.main()
