"""v1.6.0 tester dashboard and combined Assessment Status regressions."""
from __future__ import annotations

from pathlib import Path

from tests.test_guided_review_navigation import assessment, scripted
from utils.assessment_integrity import verify_assessment
from utils.assessment_layout import artifact_path
from utils.guided_review import read_review
from utils.reporting import AssessmentReporter
from wca import _status_available_actions


def test_dashboard_contains_v160_sections_and_candidate_evidence_relationships(tmp_path):
    root = assessment(tmp_path, version='1.6.0')
    html = artifact_path(root, 'assessment_report.html').read_text(encoding='utf-8')
    for heading in ('Guided Tester Review', 'Application / Technology Profile',
                    'Coverage Gaps and Limitations', 'Module Health and Evidence',
                    'Browsable Evidence Index'):
        assert heading in html
    state = read_review(root)
    for candidate in state['items'].values():
        assert candidate['id'] in html
    assert 'Manual validation guidance' in html
    assert 'Review decisions are edited through the CLI' in html


def test_dashboard_reflects_saved_review_progress_and_notes(tmp_path):
    root = assessment(tmp_path, version='1.6.0')
    scripted(root, ['1', '3', 'Reviewed in controlled fixture', '0'])
    html = artifact_path(root, 'assessment_report.html').read_text(encoding='utf-8')
    assert 'Reviewed in controlled fixture' in html
    assert 'INFORMATIONAL' in html
    assert '1 / 2' in html
    assert verify_assessment(root)['status'] == 'PASS'


def test_dashboard_escapes_reviewer_text_and_does_not_leak_installer_parent(tmp_path):
    root = assessment(tmp_path, version='1.6.0')
    scripted(root, ['1', '3', '<script>alert(1)</script>', '0'])
    html = artifact_path(root, 'assessment_report.html').read_text(encoding='utf-8')
    assert '<script>alert(1)</script>' not in html
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert str(tmp_path) not in html


def test_dashboard_shows_static_optional_gaps_without_inventing_vulnerabilities(tmp_path):
    root = tmp_path / 'static'
    reporter = AssessmentReporter(root, 'Static fixture', Path(r'C:\\Private\\setup.exe'), 'static', '1.6.0')
    reporter.set_status('Installer Information', 'PASS', 'Identified executable')
    reporter.set_status('Procmon Analysis', 'SKIPPED', 'Static mode')
    reporter.set_status('Network Surface Review', 'SKIPPED', 'Static mode')
    reporter.finalize()
    html = artifact_path(root, 'assessment_report.html').read_text(encoding='utf-8')
    assert 'Coverage Gaps and Limitations' in html
    assert 'Optional / observational' in html
    assert 'Procmon Analysis' in html
    assert 'Network Surface Review' in html
    assert r'C:\\Private' not in html
    assert 'not independently confirmed vulnerabilities' in html


def test_status_actions_offer_regeneration_only_for_safe_derived_report_damage():
    info = {'kind': 'structured', 'action': 'NONE'}
    assert _status_available_actions(info, {'repairable': True}) == [
        ('regenerate', 'Regenerate Derived Reports')
    ]
    assert _status_available_actions(info, {'repairable': False}) == []


def test_status_actions_preserve_recovery_without_offering_unsafe_regeneration():
    info = {'kind': 'structured', 'action': 'POST_INSTALL'}
    assert _status_available_actions(info, {'repairable': False}) == [
        ('resume', 'Resume Assessment')
    ]
    both = _status_available_actions(info, {'repairable': True})
    assert [name for name, _ in both] == ['regenerate', 'resume']
