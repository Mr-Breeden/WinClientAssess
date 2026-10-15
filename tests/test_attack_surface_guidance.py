"""v1.6.1 evidence-driven checks, bounded PoCs and optional-review-note regressions."""
from __future__ import annotations
from pathlib import Path
from tests.test_guided_review_navigation import assessment, scripted
from utils.assessment_layout import artifact_path
from utils.assessment_integrity import verify_assessment
from utils.guided_review import read_review, validation_commands
from utils.contextual_checks import checks
from utils.poc_playbooks import CATEGORIES
from utils.reporting import AssessmentReporter


def test_broad_attack_surface_categories_present_in_primary_report(tmp_path):
    root = assessment(tmp_path, version='1.6.1')
    plan = artifact_path(root, 'attack_surface_test_plan.txt').read_text(encoding='utf8')
    assert len(CATEGORIES) >= 20
    assert any(name == "Heap memory corruption" for name, *_ in CATEGORIES)
    assert any(name == "Local storage, embedded secrets and information disclosure" for name, *_ in CATEGORIES)
    for name, *_ in CATEGORIES:
        assert name.upper() in plan
    assert 'GUIDED ONLY - NOT AUTOMATICALLY DETECTED' in plan
    assert 'TESTER-CONTROLLED MANUAL VALIDATION' in plan
    assert verify_assessment(root)['status'] == 'PASS'


def test_html_has_poc_plan_and_no_undocumented_metric(tmp_path):
    root = assessment(tmp_path, version='1.6.1')
    scripted(root, ['2', '1', '', '0'])
    html = artifact_path(root, 'assessment_report.html').read_text(encoding='utf8')
    text = artifact_path(root, 'findings_summary.txt').read_text(encoding='utf8')
    guide = artifact_path(root, 'evidence_guide.txt').read_text(encoding='utf8')
    assert 'PoC resource' in html
    assert 'Windows Thick Client Attack Surface Coverage' in html
    assert 'attack_surface_test_plan.txt' in html
    assert 'Undocumented validated' not in html
    assert 'Documentation gap' not in html
    assert 'Validated without notes' not in text
    assert '6 / 10  POC RESOURCE' in guide
    assert verify_assessment(root)['status'] == 'PASS'


def test_contextual_dll_pipe_service_and_permissions_checks(tmp_path):
    root = tmp_path / 'test'
    (root / 'reports').mkdir(parents=True)
    (root / 'working').mkdir()
    (root / 'reports' / 'permissions_review.txt').write_text('''
[ACL-001] Service directory
Path      : C:\\Program Files\\Example
Broad Write ACEs (0)
[ACL-002] DLL search directory
Path      : C:\\ProgramData\\Example
Broad Write ACEs (1)
''', encoding='utf8')
    dll = {'source_module': 'DLL Search Review', 'title': 'Beeper.exe -> Shared.dll',
           'evidence': 'Missing DLL : C:\\ProgramData\\Example\\Shared.dll\nSearch Directory : C:\\ProgramData\\Example', 'artifacts': []}
    pipe = {'source_module': 'IPC / Named Pipe Review', 'title': r'PipeServer.exe -> \\.\pipe\Example', 'evidence': '', 'artifacts': []}
    service = {'source_module': 'Services Review', 'title': 'Unquoted service path',
               'evidence': 'ExampleService: C:\\Program Files\\Example\\ExampleService.exe\nIssue: Unquoted SYSTEM service command', 'artifacts': []}
    perm = {'source_module': 'Permissions Review', 'title': 'Review permissions', 'evidence': '', 'artifacts': []}
    boundary = {'source_module': 'Privilege Boundary Review', 'title': 'Component Type: Service',
                'evidence': 'Component: ExampleService\nPath: C:\\Program Files\\Example\\ExampleService.exe\nIssue: Unquoted service command', 'artifacts': []}
    assert "icacls 'C:\\ProgramData\\Example'" in checks(dll, root)
    assert "-a 'Example'" in checks(pipe, root)[0]
    assert "sc.exe qc 'ExampleService'" in checks(service, root)
    assert "icacls 'C:\\'" in checks(service, root)[-1]
    assert all('Program Files' not in x for x in checks(perm, root))
    assert all('ProgramData' not in x for x in checks(boundary, root))
    assert all('<' not in x for obj in (dll,pipe,service,perm,boundary) for x in checks(obj, root))


def test_ambiguous_evidence_does_not_invent_a_sensitive_path(tmp_path):
    root = tmp_path / 'root'
    (root / 'reports').mkdir(parents=True)
    (root / 'working').mkdir()
    item = {'source_module':'Permissions Review', 'title':'generic', 'evidence':'none', 'artifacts':[]}
    commands = validation_commands(item, root)
    assert 'permissions_review.txt' in commands[0]
    assert not any('icacls ' in x for x in commands)


def test_updater_not_applicable_is_distinguished_from_skipped(tmp_path):
    root = tmp_path / 'static'
    reporter = AssessmentReporter(root, 'Fixture', Path('sample.msi'), 'full', '1.6.1')
    reporter.set_status('Updater Security Correlation', 'NOT APPLICABLE',
                        'Full-mode system-state differential completed; no updater/launcher candidates were identified')
    reporter.finalize()
    html = artifact_path(root,'assessment_report.html').read_text(encoding='utf8')
    module_status = artifact_path(root,'module_status.txt').read_text(encoding='utf8')
    assert 'NOT APPLICABLE' in html
    assert 'NOT APPLICABLE' in module_status
    assert 'no updater/launcher candidates' in module_status
    assert 'Updater Security Correlation' not in artifact_path(root,'coverage_summary.txt').read_text(encoding='utf8').split('Optional phases skipped:')[1].split('Not applicable modules')[0]
