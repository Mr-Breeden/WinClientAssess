"""v1.9 dashboard and runtime-accounting regressions, with synthetic inputs."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from modules.advanced_runtime_review import _write_managed_context
from utils.reporting import AssessmentReporter


def test_runtime_managed_context_counts_process_and_static_candidates_separately(tmp_path):
    rows = [
        {'Process': 'application.exe', 'Classification':'Published .NET application host',
         'StaticManagedCandidate':True, 'ManagedRuntimeObserved':False,
         'ManagedRuntimeModules':[], 'NativeRuntimeModules':[], 'LoadedImageCount':0},
        *({'Process':f'library_{n}.dll', 'Classification':'Managed candidate from static analysis',
            'StaticManagedCandidate':True, 'ManagedRuntimeObserved':False,
            'ManagedRuntimeModules':[], 'NativeRuntimeModules':[], 'LoadedImageCount':0}
           for n in range(244)),
    ]
    _write_managed_context(tmp_path, rows, [{'Name':'application.exe', 'PID':100}])
    text = (tmp_path/'runtime_managed_context.txt').read_text()
    assert 'Runtime target process identities classified' in text
    assert 'Static-only assembly/host identities' in text
    assert '245' in text  # still displays evidence inventory, not runtime PID count
    lines = text.splitlines()
    runtime_line = next(line for line in lines if 'Runtime target process identities classified' in line)
    static_line = next(line for line in lines if 'Static-only assembly/host identities' in line)
    assert runtime_line.rstrip().endswith('1')
    assert static_line.rstrip().endswith('244')
    assert 'Processes classified' not in text


def test_offline_tester_dashboard_has_action_center_and_non_green_validation(tmp_path):
    from utils.assessment_layout import ensure_structured_layout
    ensure_structured_layout(tmp_path)
    reporter = AssessmentReporter(tmp_path,'Synthetic <Client>',Path('Client.exe'), 'static', '1.9.1')
    reporter.set_status('Configuration Review','WARN','Needs manual validation',coverage_gap=True)
    reporter.add_finding(title='Source pattern',severity='Informational',source_module='Configuration Review')
    reporter.finalize()
    html = (tmp_path/'reports'/'assessment_report.html').read_text()
    assert 'Tester Action Center' in html
    assert 'Coverage follow-up' in html
    assert 'review-group-pending' in html.lower()
    assert 'action-columns' in html
    assert '.decision-validated { background:#a7c3f8;' in html
    assert '.decision-validated { background:var(--pass)' not in html
    assert 'Synthetic &lt;Client&gt;' in html
    assert 'External scripts' not in html
