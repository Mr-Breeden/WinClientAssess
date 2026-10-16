"""M2 unified workspace and case-specific inline supporting evidence links."""
from __future__ import annotations

from pathlib import Path
from html.parser import HTMLParser
import json
import threading
from urllib.parse import urlencode

import pytest

from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_state import AssessmentState
from utils.manual_test_workflow import read_manual_detail, read_manual_workflow, save_manual_decision


class IDS(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.pages = []
    def handle_starttag(self, tag, attrs):
        props = dict(attrs)
        if 'id' in props:
            self.ids.append(props['id'])
            if props['id'].startswith('page-'):
                self.pages.append(props['id'])


def _fixture(tmp_path):
    source = tmp_path / 'target.msi'
    source.write_bytes(b'MSI fixture')
    root = tmp_path / 'case'
    state = AssessmentState.create(root, assessment_name='Fixture', installer=source,
                                   mode='full', framework_version='2.2.0', options={}, tools={})
    state.mark_complete('COMPLETE_WITH_OPTIONAL_GAPS')
    reports = root / 'reports'
    (reports / 'installer_analysis.txt').write_text('Verified installer evidence', encoding='utf-8')
    (reports / 'installer_technology.txt').write_text('Verified technology evidence', encoding='utf-8')
    (reports / 'test_cases.txt').write_text('''WCA - TEST CASES
[ ] TC-IN-001 - Installer Integrity and Provenance
Risk: Informational
Procedure:
  Verify the installer hash, origin and metadata.

How to Perform:
  1. Open installer_analysis.txt and inspect SHA-256.
  2. Open installer_technology.txt and verify MSI.
  3. Review not_available.txt only if produced.

Expected Secure Behavior:
  Hash matches the authorized installer.

When NOT to Report:
  Missing external hashes alone are not a security issue.

[ ] TC-SG-001 - Signature Validation
Procedure:
  Verify signature_review.txt if available.
''', encoding='utf-8')
    create_manifest(root, framework_version='2.2.0', methodology_version='1.9', catalog_version='2.0')
    assert verify_assessment(root)['status'] == 'PASS'
    return root


def test_manual_case_report_links_and_procedures_come_from_verified_checklist(tmp_path):
    root = _fixture(tmp_path)
    case = read_manual_detail(root, 'TC-IN-001')
    assert case['reports'] == ['installer_analysis.txt', 'installer_technology.txt']
    assert 'Verify the installer hash' in case['guidance']['Procedure']
    assert 'SHA-256' in case['guidance']['How to Perform']
    assert 'authorized installer' in case['guidance']['Expected Secure Behavior']
    assert 'not_available.txt' not in case['reports']
    assert read_manual_detail(root, 'TC-SG-001')['reports'] == []
    summary = read_manual_workflow(root)
    assert summary['items'][0]['reports'] == case['reports']
    assert 'guidance' not in summary['items'][0]
    assert verify_assessment(root)['status'] == 'PASS'


def test_manual_case_links_do_not_expose_symlink_or_large_report(tmp_path):
    root = _fixture(tmp_path)
    external = tmp_path / 'unrelated.txt'
    external.write_text('Private material', encoding='utf-8')
    # Changes to the checklist require a re-verified manifest before reading.
    checklist = root / 'reports/test_cases.txt'
    checklist.write_text(checklist.read_text() + '\nHow to Perform:\n  Read private_link.txt and over_limit.txt.\n')
    (root / 'reports/over_limit.txt').write_bytes(b'X' * 500_001)
    create_manifest(root, framework_version='2.2.0', methodology_version='1.9', catalog_version='2.0')
    assert verify_assessment(root)['status'] == 'PASS'
    assert 'over_limit.txt' not in read_manual_detail(root, 'TC-SG-001')['reports']
    # Assessment verification itself must reject any symlink before a report link is created.
    try:
        (root / 'reports/private_link.txt').symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip('Creating symlinks requires extra privileges on this host')
    assert verify_assessment(root)['status'] != 'PASS'
    with pytest.raises((OSError, ValueError)):
        read_manual_detail(root, 'TC-SG-001')


def test_manual_links_preserve_saved_state_and_integrity(tmp_path):
    root = _fixture(tmp_path)
    before = (root/'reports/test_cases.txt').read_bytes()
    case = read_manual_detail(root,'TC-IN-001')
    save_manual_decision(root, case_id=case['id'], fingerprint=case['fingerprint'],
                         status='IN PROGRESS', notes='Private testing note')
    after = read_manual_detail(root,'TC-IN-001')
    assert after['status'] == 'IN PROGRESS'
    assert after['reports'] == case['reports']
    assert after['notes'] == 'Private testing note'
    assert 'notes' not in read_manual_workflow(root)['items'][0]
    assert (root/'reports/test_cases.txt').read_bytes() == before
    assert verify_assessment(root)['status'] == 'PASS'


def test_workspace_nav_filters_and_inline_report_ui():
    root = Path(__file__).resolve().parents[1]
    markup = (root/'gui/index.html').read_text(encoding='utf-8')
    script = (root/'gui/app.js').read_text(encoding='utf-8')
    parser=IDS();parser.feed(markup)
    assert parser.pages.count('page-workspace') == 1
    assert 'page-review' not in parser.pages and 'page-workflow' not in parser.pages
    assert len(parser.ids) == len(set(parser.ids)), 'Each GUI ID must be unique'
    for name in ('manualSearch','manualStatusFilter','manualCategoryFilter','manualFilterCount',
                 'manualGuidance','manualReportLinks','manualReportPane','manualReportContent',
                 'workspace-pane-review','workspace-pane-manual','workspace-pane-final'):
        assert name in parser.ids
    assert 'data-tab="workspace"' in markup
    assert 'data-tab="review"' not in markup and 'data-tab="workflow"' not in markup
    assert 'function renderManualList()' in script
    assert 'function previewManualReport(name)' in script
    assert "request('/api/report?'" in script
    assert "go('reports');await loadReport(report)" not in script


def test_manual_http_links_are_authenticated_and_read_only(tmp_path):
    from tests.test_gui_200 import http_request, gui_headers
    from utils.gui_catalog import RecentAssessments
    from utils.gui_server import JobManager, make_server
    root=_fixture(tmp_path)
    jobs=JobManager(catalog=RecentAssessments(tmp_path/'catalog.json'))
    server=make_server(port=0, version='2.2.0',jobs=jobs,token='known-test-token')
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        query=urlencode({'assessment':str(root)})
        assert http_request(server,'GET','/api/manual-tests?'+query)[0] == 403
        code,_,data=http_request(server,'GET','/api/manual-tests?'+query,headers=gui_headers(server))
        assert code == 200
        listing=json.loads(data)['data']
        assert listing['items'][0]['reports'] == ['installer_analysis.txt','installer_technology.txt']
        assert 'notes' not in listing['items'][0] and 'guidance' not in listing['items'][0]
        rq='/api/report?'+urlencode({'assessment':str(root),'name':'installer_analysis.txt'})
        assert http_request(server,'GET',rq)[0] == 403
        assert http_request(server,'GET',rq,headers=gui_headers(server))[0] == 200
    finally:
        server.shutdown();server.server_close();thread.join(5);jobs.close()
