"""v1.9.1 offline HTML: dual-theme, privacy, navigation and safe report composition."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from html import unescape

from utils.html_theme import THEME_CSS, THEME_SCRIPT, csp, script_hash
from utils.client_appendix import _appendix_html, export_client_appendix
from utils.reporting import AssessmentReporter
from tests.test_client_appendix_190 import _assessment
from utils.assessment_integrity import verify_assessment


def test_dark_by_default_and_light_theme_accessibility():
    doc = _appendix_html({'assessment_name':'Example'}, [], [], {})
    assert '<html lang="en" data-theme="dark">' in doc
    assert 'Light theme' in doc and 'theme-toggle' in doc
    assert '[data-theme="light"]' in doc
    assert 'localStorage.setItem' in doc
    assert 'catch(e)' in doc  # runs with unavailable file:// storage
    assert "connect-src 'none'" in unescape(doc)
    assert script_hash(THEME_SCRIPT) in unescape(doc)
    assert 'https://' not in doc and 'http://' not in doc


def test_client_approved_technical_metrics_without_guesses_or_private_notes():
    state={'assessment_name':'Project <Important>','mode':'full','target':{'type':'installable'}}
    items=[{'status':'VALIDATED','title':'Pipe requires testing','source_module':'IPC / Named Pipe Review','notes':'PRIVATE_REVIEWER_NOTES'},
           {'status':'NOT APPLICABLE','title':'PRIVATE_NOT_APPLICABLE','source_module':'Secrets Review'}]
    evidence=['application_profile.txt','network_surface_review.txt','ipc_review.txt','services_review.txt']
    reports={'application_profile.txt':'Product name : Target <Tool>\nProduct version : 2.4\n',
             'network_surface_review.txt':'Listening/bound endpoints : 2\n',
             'ipc_review.txt':'Target-associated pipe records: 5\n',
             'services_review.txt':'New services : 1\n'}
    doc=_appendix_html(state, items, evidence, reports)
    assert 'Project &lt;Important&gt;' in doc and 'Target &lt;Tool&gt;' in doc
    assert '2.4' in doc and 'Bound network endpoints' in doc
    assert '>2</strong>' in doc
    assert 'Installation footprint' in doc and 'Privilege and writable paths' in doc
    assert 'Reviewed security observations' in doc and 'Evidence library' in doc
    assert 'PRIVATE_REVIEWER_NOTES' not in doc and 'PRIVATE_NOT_APPLICABLE' not in doc
    assert 'not independently confirmed vulnerabilities' in doc
    assert set(re.findall(r'href="evidence/([^"]+)"',doc))==set(evidence)


def test_client_appendix_integrity_copy_only_after_redesign(tmp_path):
    root=_assessment(tmp_path)
    out=export_client_appendix(root,tmp_path/'client.zip')
    with zipfile.ZipFile(out) as z:
        doc=z.read('assessment_report.html').decode('utf-8')
        assert 'data-theme="dark"' in doc
        assert 'Windows Client Assessment · Client technical appendix' in doc
        assert 'Evidence library' in doc
        assert 'TESTER_PRIVATE_NOTE' not in doc
        assert not any('working/' in p or 'secrets_review' in p for p in z.namelist())
        assert z.testzip() is None
    assert verify_assessment(root)['status']=='PASS'


def test_tester_workspace_is_read_only_and_accessible_without_javascript(tmp_path):
    root=tmp_path/'test'
    from utils.assessment_layout import ensure_structured_layout
    ensure_structured_layout(root)
    reporter=AssessmentReporter(root,'Assessment <Portal>',Path('Portal.exe'),'static','1.9.1')
    reporter.set_status('Configuration Review','WARN','Manual inspection indicated')
    reporter.add_finding(title='Observed configuration indicator',source_module='Configuration Review')
    reporter.finalize()
    doc=(root/'reports'/'assessment_report.html').read_text(encoding='utf-8')
    assert 'data-theme="dark"' in doc
    assert '<noscript' not in doc  # unenhanced markup is complete by default
    assert 'id="review-source"' in doc and 'review-workspace' in doc
    assert 'id="review-choices"' in doc and 'id="review-detail-host"' in doc
    assert 'id="review-search"' in doc and 'id="review-module"' in doc
    assert 'id="review-status"' in doc
    assert 'Review decisions are edited through the CLI' in doc
    assert 'Observed configuration indicator' in doc
    assert 'Assessment &lt;Portal&gt;' in doc
    assert 'Show automated review points' in doc and 'Open complete module status table' in doc
    assert 'script-src' in doc and 'connect-src' in doc
    assert 'src="http' not in doc
    assert 'No external scripts' in doc or 'No external' in doc


def test_script_allowlist_is_hash_restricted():
    from utils.consolidated_report import REVIEW_SCRIPT
    policy=unescape(csp((THEME_SCRIPT, REVIEW_SCRIPT)))
    assert script_hash(THEME_SCRIPT) in policy
    assert script_hash(REVIEW_SCRIPT) in policy
    assert "'unsafe-inline'" not in policy.split('script-src')[1]
    assert "connect-src 'none'" in policy
    assert 'innerHTML' not in REVIEW_SCRIPT  # preserve injection boundary
    assert 'textContent' in REVIEW_SCRIPT


def test_shared_theme_script_does_not_touch_assessment_evidence():
    assert 'fetch(' not in THEME_SCRIPT and 'sendBeacon' not in THEME_SCRIPT
    assert 'setAttribute' in THEME_SCRIPT and 'aria-pressed' in THEME_SCRIPT
    assert '.theme-toggle:focus-visible' in THEME_CSS
    assert '@media print' in THEME_CSS
