"""P20: collected ACL precision, dual-stack WCR migration, and inline guidance."""
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from modules.local_storage_review import run_local_storage_review
from utils.target_evidence import stored_target_evidence
from utils.guided_review import (_poi_candidates, _merge_dualstack_network_candidates,
                                 sync_review, _digest, read_review)

ROOT = Path(__file__).resolve().parents[1]


class FakeAclCache:
    def get_many(self, paths):
        result = {}
        for path in paths:
            if path.lower().endswith('safe.lnk'):
                result[path.lower()] = {'Exists': True, 'Owner': 'BUILTIN\\Administrators',
                    'Access': [{'Identity': 'BUILTIN\\Users', 'Rights': 'ReadAndExecute',
                                'Type': 'Allow', 'Inherited': True}]}
            else:
                result[path.lower()] = {'Exists': True, 'Owner': 'SYSTEM',
                    'Access': [{'Identity': 'BUILTIN\\Users', 'Rights': 'Modify',
                                'Type': 'Allow', 'Inherited': True}]}
        return result


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'reports').mkdir()
        (self.root / 'working').mkdir()

    def test_storage_acl_output_is_selected_object_and_parent(self):
        from utils import target_evidence
        report = '''TARGET-ASSOCIATED STORAGE FILES (2)
[STORE-001] C:\\ProgramData\\Veyon\\Safe.lnk
  Broad read ACE count    : 2
  File Path: C:\\ProgramData\\Veyon\\Safe.lnk
  File ACL Status: COLLECTED
  File Owner: BUILTIN\\Administrators
  File Broad Write ACE Count: 0
    File ACE: BUILTIN\\Users | ReadAndExecute | Allow | True
  Parent Path: C:\\ProgramData\\Veyon
  Parent ACL Status: COLLECTED
  Parent Owner: SYSTEM
  Parent Broad Write ACE Count: 1
    Parent ACE: BUILTIN\\Users | Modify | Allow | True

[STORE-002] C:\\ProgramData\\Veyon\\Other.lnk
  File ACL Status: COLLECTED
  File Owner: unrelated

REGISTRY STORAGE (0)
'''
        (self.root/'reports'/'local_storage_review.txt').write_text(report)
        result=target_evidence.stored_target_evidence(self.root,'local_storage_review.txt','C:\\ProgramData\\Veyon\\Safe.lnk')
        self.assertTrue(result['found'])
        self.assertNotIn('Other.lnk',result['excerpt'])
        self.assertEqual(result['storage_acl']['file']['owner'],'BUILTIN\\Administrators')
        self.assertEqual(result['storage_acl']['parent']['entries'][0]['rights'],'Modify')
        self.assertTrue(result['storage_acl']['parent']['broad_write_indicated'])
        self.assertFalse(result['storage_acl']['file']['broad_write_indicated'])
        self.assertFalse(target_evidence.stored_target_evidence(self.root,'local_storage_review.txt','C:\\ProgramData\\Other\\Safe.lnk')['found'])

    def test_legacy_report_never_invents_aces(self):
        (self.root/'reports'/'local_storage_review.txt').write_text('[STORE-001] C:\\A\\File.lnk\n  Broad read ACE count : 2\n\nREGISTRY STORAGE (0)\n')
        result=stored_target_evidence(self.root,'local_storage_review.txt','C:\\A\\File.lnk')
        self.assertTrue(result['found'])
        self.assertEqual(result['storage_acl']['file']['status'],'NOT COLLECTED')
        self.assertEqual(result['storage_acl']['file']['entries'],[])

    def test_storage_collector_collects_file_and_parent_without_polluting_other_reports(self):
        # Keep the collector tests synthetic; never interrogate host ACLs.
        from modules import local_storage_review as ls
        sample = 'C:\\ProgramData\\Veyon\\Safe.lnk'
        diff={'Filesystem': {'added':[{'Path':sample,'IsDirectory':False}], 'changed':[]}}
        with patch.object(ls,'association_roots',return_value=[]),\
             patch.object(ls,'target_identity_tokens',return_value=({'veyon'},[])),\
             patch.object(ls,'path_has_target_identity',return_value=True),\
             patch.object(ls,'classify_installed_path',return_value='target identity') ,\
             patch.object(ls,'read_msi_properties',return_value={}):
            run_local_storage_review(self.root,diff=diff,filesystem_evidence=True,acl_cache=FakeAclCache())
        content=(self.root/'reports'/'local_storage_review.txt').read_text()
        self.assertIn('File ACL Status: COLLECTED',content)
        self.assertIn('Parent ACL Status: COLLECTED',content)
        self.assertIn('Parent Broad Write ACE Count: 1',content)
        self.assertIn('File ACE: BUILTIN\\Users | ReadAndExecute | Allow | True',content)


class DualStackTests(unittest.TestCase):
    NETWORK='''NETWORK POINTS OF INTEREST
[POI-NW-001] veyon-server.exe - TCP :::11100
Confidence: HIGH
Bind Scope: Wildcard / all interfaces
Executable: C:\\Program Files\\Veyon\\veyon-server.exe
[POI-NW-002] veyon-server.exe - TCP 0.0.0.0:11100
Confidence: HIGH
Bind Scope: Wildcard / all interfaces
Executable: C:\\Program Files\\Veyon\\veyon-server.exe
'''
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'reports').mkdir()
        (self.root/'working').mkdir()
        (self.root/'reports'/'network_surface_review.txt').write_text(self.NETWORK)

    def test_two_bindings_become_one_current_wcr(self):
        out=_poi_candidates(self.root)
        self.assertEqual(len(out),1)
        self.assertEqual(set(out[0]['source_records']),{'POI-NW-001','POI-NW-002'})
        self.assertEqual(out[0]['occurrence_count'],2)
        self.assertIn('IPv4 + IPv6',out[0]['title'])
        self.assertIn('0.0.0.0:11100',out[0]['evidence'])
        self.assertIn(':::11100',out[0]['evidence'])

    def test_different_executables_ports_or_loopback_not_merged(self):
        src=self.NETWORK.replace('veyon-server.exe - TCP 0.0.0.0:11100','veyon-server.exe - TCP 127.0.0.1:11100')
        (self.root/'reports'/'network_surface_review.txt').write_text(src)
        self.assertEqual(len(_poi_candidates(self.root)),2)
        src=self.NETWORK.replace('[POI-NW-002] veyon-server.exe - TCP 0.0.0.0:11100','[POI-NW-002] veyon-other.exe - TCP 0.0.0.0:11100').replace('Executable: C:\\Program Files\\Veyon\\veyon-server.exe\n', 'Executable: C:\\Program Files\\Veyon\\veyon-other.exe\n',1)
        (self.root/'reports'/'network_surface_review.txt').write_text(src)
        self.assertEqual(len(_poi_candidates(self.root)),2)


    def test_gui_review_detail_exposes_legacy_dispositions_without_legacy_notes(self):
        from utils import gui_server
        merged = _poi_candidates(self.root)[0]
        merged.update(id='WCR-DEADBEEF000000',fingerprint='same', status='PENDING', notes='', client_notes='',
                      merged_previous_decisions=[{'id':'WCR-OLD1','title':'IPv4 wildcard','status':'VALIDATED','notes':'private legacy note'}])
        with patch.object(gui_server, 'verify_assessment',return_value={'status':'PASS'}),\
             patch.object(gui_server, 'read_review',return_value={'items':{merged['id']:merged}}),\
             patch.object(gui_server, 'candidate_validation',return_value={}),\
             patch.object(gui_server, 'validation_commands',return_value=[]):
            detail=gui_server.review_condition_detail(self.root,merged['id'])
        self.assertEqual(detail['merged_previous_decisions'][0]['status'],'VALIDATED')
        self.assertNotIn('notes',detail['merged_previous_decisions'][0])
        self.assertEqual(len(detail['network_bindings']),2)

    def test_security_context_difference_remains_separate(self):
        report = self.NETWORK.replace('Executable: C:\\Program Files\\Veyon\\veyon-server.exe',
            'Privileged Context: True\nExecutable: C:\\Program Files\\Veyon\\veyon-server.exe',1)
        report = report.replace('[POI-NW-002] veyon-server.exe - TCP 0.0.0.0:11100',
            '[POI-NW-002] veyon-server.exe - TCP 0.0.0.0:11100\nPrivileged Context: False')
        (self.root/'reports'/'network_surface_review.txt').write_text(report)
        self.assertEqual(len(_poi_candidates(self.root)),2)

    def test_migration_retains_both_old_decisions_and_does_not_autovalidate(self):
        # Start from two old pre-consolidation records with different decisions.
        old={}
        for item in _poi_candidates(self.root):
            merged=item
        for title,status in [('veyon-server.exe - TCP :::11100','VALIDATED'),('veyon-server.exe - TCP 0.0.0.0:11100','PENDING')]:
            identity='Network Surface Review|poi|'+title.lower()
            key='WCR-'+_digest(identity).upper()
            old[key]={'id':key,'identity':identity,'title':title,'source_module':'Network Surface Review','status':status,
                      'notes':'old note '+status,'client_notes':'','evidence_reference':'','fingerprint':'older','source_record':'POI-NW-001'}
        state={'schema_version':1,'items':old,'retired':[]}
        (self.root/'working'/'tester_review_state.json').write_text(json.dumps(state))
        new=sync_review(self.root,[],create=True)
        self.assertEqual(len(new['items']),1)
        combined=next(iter(new['items'].values()))
        self.assertEqual(combined['status'],'PENDING')
        self.assertEqual({x['status'] for x in combined['merged_previous_decisions']},{'VALIDATED','PENDING'})
        self.assertEqual(len(new['retired']),2)
        self.assertEqual({x['notes'] for x in new['retired']},{'old note VALIDATED','old note PENDING'})
        again=sync_review(self.root,[],create=False)
        self.assertEqual(next(iter(again['items'].values()))['merged_previous_decisions'],combined['merged_previous_decisions'])


class UIRegressions(unittest.TestCase):
    def test_examples_are_inside_review_step_instead_of_bottom(self):
        js=(ROOT/'gui'/'app.js').read_text()
        self.assertIn('if(target)addP18GuidanceExamples(target,item.id)',js)
        self.assertIn("'TC-FS-001':2",js)
        self.assertIn("'TC-IP-002':2",js)
        self.assertIn('step.appendChild(buildPeMitigationGuide())',js)
        self.assertIn('if(item.id===\'TC-AR-003\' && i===4)',js)
        self.assertEqual(js.count('function addP18GuidanceExamples('),1)

    def test_existing_ui_behaviors_preserved(self):
        js=(ROOT/'gui'/'app.js').read_text()
        html=(ROOT/'gui'/'index.html').read_text()
        self.assertIn('Package & Download DUMPBIN Evidence ZIP',html)
        self.assertIn('Copy evidence folder path',html)
        for expected in ('Historical collected socket observations','Potential Secret Indicator Review',
                         'Open file location','Official getting-started guide'):
            self.assertIn(expected,js)

if __name__=='__main__':
    unittest.main()
