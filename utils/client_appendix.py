"""Copy-only, integrity-gated client appendix export.

This is intentionally not a finding generator or a vulnerability confirmation engine.
Reviewer decisions are workflow state, and notes/raw evidence are never exported.
The source assessment and its SHA-256 manifest are never modified.
"""
from __future__ import annotations

import hashlib
import html
import os
import re
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

from utils.assessment_integrity import verify_assessment
from utils.assessment_state import AssessmentState
from utils.guided_review import read_review
from utils.privacy import sanitize_report_text
from utils.html_theme import THEME_CSS, THEME_SCRIPT, csp, toggle


class ClientAppendixError(ValueError):
    """Fail-closed appendix validation or export error."""


# Deliberately short allowlist. No secrets, raw Procmon, paths from snapshots,
# tester notes, executable payloads, source code, or JSON internal state.
APPROVED_REPORTS = (
    'application_profile.txt', 'coverage_summary.txt', 'signature_review.txt',
    'binary_security_review.txt', 'configuration_review.txt',
    'services_review.txt', 'permissions_review.txt',
    'network_surface_review.txt', 'ipc_review.txt',
)
CRITICAL_STAGES = ('static_analysis', 'reporting', 'complete')
FULL_CRITICAL_STAGES = ('pre_install_snapshot', 'post_install_snapshot', 'installed_state_analysis')


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _esc(text: object) -> str:
    return html.escape(sanitize_report_text(text), quote=True)


def export_readiness(root: Path) -> tuple[dict, dict, list[dict]]:
    """Return an immutable readiness view or raise before exporting anything."""
    root = Path(root).resolve()
    integrity = verify_assessment(root)
    if integrity.get('status') != 'PASS':
        raise ClientAppendixError('Assessment integrity is not PASS; do not export altered or incomplete evidence.')
    state = AssessmentState.load(root)
    if state is None or state.data.get('status') != 'COMPLETED':
        raise ClientAppendixError('Assessment is not finalized.')
    # The v1.8.x finalized schema remains compatible. Preserve existing,
    # verified assessments without forcing another Windows test; unknown
    # manifest/reviewer schemas are rejected by the source readers.
    stages = state.data.get('stages') or {}
    critical = CRITICAL_STAGES + (FULL_CRITICAL_STAGES if state.data.get('mode') == 'full' else ())
    incomplete = [name for name in critical if (stages.get(name) or {}).get('status') != 'COMPLETED']
    if incomplete:
        raise ClientAppendixError('Critical assessment stages are incomplete: ' + ', '.join(incomplete))
    modules = state.data.get('modules') or {}
    blockers = [name for name, value in modules.items() if str(value.get('status') or '').upper() == 'ERROR']
    if blockers:
        raise ClientAppendixError('Critical module collection errors must be resolved: ' + ', '.join(blockers[:8]))
    review = read_review(root)
    if not review or not review.get('items'):
        raise ClientAppendixError('No completed Guided Tester Review state is available.')
    items = list(review['items'].values())
    pending = [item for item in items if item.get('status') not in ('VALIDATED', 'NOT APPLICABLE', 'INFORMATIONAL')
               or item.get('changed_evidence')]
    if pending:
        raise ClientAppendixError(f'{len(pending)} review condition(s) remain pending or require evidence revalidation.')
    return state.data, integrity['manifest'], items


def _field(text: str, key: str, default: str = "Not recorded") -> str:
    """Extract one factual scalar from an already approved sanitized report."""
    found = re.search(r"^\s*" + re.escape(key) + r"\s*:\s*(.+?)\s*$", text, re.I | re.M)
    return found.group(1).strip() if found else default


def _appendix_html(state: dict, items: list[dict], evidence: list[str], reports: dict[str, str] | None = None) -> str:
    """Render a client-facing technical overview using only allowlisted report text.

    This is an evidence navigation and context summary, not a finding engine.
    No tester notes, raw observations, executable content or unapproved records enter HTML.
    """
    reports = reports or {}
    profile = reports.get('application_profile.txt', '')
    coverage = reports.get('coverage_summary.txt', '')
    services = reports.get('services_review.txt', '')
    network = reports.get('network_surface_review.txt', '')
    ipc = reports.get('ipc_review.txt', '')
    permissions = reports.get('permissions_review.txt', '')
    relevant = [item for item in items if item.get('status') in ('VALIDATED', 'INFORMATIONAL')]
    relevant.sort(key=lambda i: (str(i.get('source_module') or ''), str(i.get('title') or '')))

    # Generic module-family grouping; no vulnerability confirmation is inferred.
    families = (
        ('Installation and privilege boundaries', ('MSI', 'Installer', 'Service', 'Privilege', 'Permissions', 'Persistence', 'Updater', 'Attack Surface')),
        ('Runtime, communication and storage', ('Runtime', 'Network', 'IPC', 'Pipe', 'DLL', 'Storage')),
        ('Binary, configuration and trust', ('PE Security', 'Signature', 'Configuration', 'Component', 'Electron', '.NET', 'Secrets')),
    )
    buckets: dict[str, list[dict]] = {name: [] for name, _ in families}
    buckets['Other reviewed observations'] = []
    for item in relevant:
        mod = str(item.get('source_module') or '')
        category = next((name for name, tokens in families if any(token.casefold() in mod.casefold() for token in tokens)), 'Other reviewed observations')
        buckets[category].append(item)

    def elink(name: str, label: str | None = None) -> str:
        if name not in evidence:
            return ''
        return '<a class="evidence-link" href="evidence/' + quote(name, safe='._-') + '">' + _esc(label or name) + '</a>'

    def panel(title: str, body: str, filenames: tuple[str, ...] = ()) -> str:
        links = ' '.join(elink(name) for name in filenames if name in evidence)
        return ('<article class="panel surface-panel"><h3>' + _esc(title) + '</h3><p>' + body + '</p>'
                + ('<div class="support-links">' + links + '</div>' if links else '') + '</article>')

    table_blocks = []
    for group, group_items in buckets.items():
        if not group_items:
            continue
        rows = ''.join('<tr><td>' + _esc(item.get('source_module') or 'Unspecified area') + '</td><td>'
                       + _esc(item.get('title') or 'Observation') + '</td><td>'
                       + _esc('Reviewed' if item.get('status') == 'VALIDATED' else 'Informational')
                       + '</td></tr>' for item in group_items)
        table_blocks.append('<details class="review-area"><summary>' + _esc(group) + ' <span class="count">' + str(len(group_items))
                            + '</span></summary><div class="table-scroll"><table><thead><tr><th>Source area</th><th>Observation</th><th>Review status</th></tr></thead><tbody>'
                            + rows + '</tbody></table></div></details>')
    docs = ''.join('<li>' + elink(name) + '</li>' for name in evidence)
    title = _esc(state.get('assessment_name') or 'Assessment')
    product = _field(profile, 'Product name')
    version = _field(profile, 'Product version')
    grade = _field(coverage, 'Coverage grade')
    service_count = _field(services, 'New services')
    listener_count = _field(network, 'Listening/bound endpoints')
    pipe_count = _field(ipc, 'Target-associated pipe records')
    write_count = _field(permissions, 'Broad-write review matches')
    storage_count = _field(profile, 'Target storage files')
    note = ('<div class="safety-note"><strong>How to interpret this appendix</strong><p>These are selected, '
            'reviewed technical observations—not independently confirmed vulnerabilities. A VALIDATED tester '
            'disposition does not prove exploitability, impact or a reportable finding. Consult the independent '
            'penetration-test report for substantiated issues. Missing or unobserved evidence is not proof of security.</p></div>')
    feature_panels = (
        panel('Installation footprint', 'New services: <strong>' + _esc(service_count) + '</strong>. '
              'Assessment technology: <strong>' + _esc(_field(profile, 'Technologies')) + '</strong>.',
              ('application_profile.txt', 'services_review.txt'))
        + panel('Privilege and writable paths', 'Privileged services: <strong>' + _esc(_field(services, 'Privileged services'))
              + '</strong>. Broad-write ACL matches: <strong>' + _esc(write_count) + '</strong>. '
              'Potential trust boundaries require manual effective-permission checks.',
              ('permissions_review.txt', 'services_review.txt'))
        + panel('Network footprint', 'Listening or bound endpoints: <strong>' + _esc(listener_count)
              + '</strong>. Active connections: <strong>' + _esc(_field(network, 'Active connections')) + '</strong>. '
              'Listener presence does not establish unauthorized access.', ('network_surface_review.txt',))
        + panel('Named pipes and IPC', 'Target-associated pipe records: <strong>' + _esc(pipe_count)
              + '</strong>. Pipe permission review points: <strong>' + _esc(_field(ipc, 'Pipe permission POIs'))
              + '</strong>. Authorization testing remains manual.', ('ipc_review.txt',))
        + panel('Application storage', 'Target-associated storage files: <strong>' + _esc(storage_count)
              + '</strong>. Only paths and artifacts in the approved profile are summarized.', ('application_profile.txt',))
        + panel('Binary and configuration', 'PE mitigations, signing, configuration and component lifecycle are '
              'documented in the approved security-analysis reports; review context before interpreting indicators.',
              ('binary_security_review.txt', 'signature_review.txt', 'configuration_review.txt'))
    )
    css = THEME_CSS + r"""
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font:14px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}a{text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:1190px;margin:auto;padding:0 24px}.masthead{padding:36px 0 30px}.masthead h1{font-size:clamp(27px,3vw,39px);line-height:1.13;margin:10px 0}.masthead p{max-width:780px;color:#d0dcea}.masthead .subline{color:#bad4e0;font-size:13px}.topline{display:flex;align-items:center;gap:16px}.eyebrow{letter-spacing:.14em;text-transform:uppercase;font-size:11px;font-weight:800;color:#a4dcea}
nav{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line)}nav .container{display:flex;align-items:center;gap:24px;padding-top:12px;padding-bottom:12px;overflow-x:auto;white-space:nowrap;font-size:12px;font-weight:750}
main{padding-top:26px;padding-bottom:55px}h2{font-size:20px;margin:0 0 10px}h3{font-size:15px;margin:0 0 10px}p{margin:0 0 12px}.section{margin-top:32px}.section-intro{max-width:760px}
.summary-strip .metric{background:var(--panel);border:1px solid var(--line)}.summary-strip .metric strong{font-size:clamp(15px,2vw,24px);max-width:100%;overflow-wrap:anywhere;word-break:break-word}.grid{display:grid;gap:14px}.two{grid-template-columns:repeat(2,minmax(0,1fr))}.three{grid-template-columns:repeat(3,minmax(0,1fr))}.surface-panel{border-top:3px solid var(--accent)!important}.support-links{display:flex;gap:6px;flex-wrap:wrap;margin-top:15px}
.evidence-link{display:inline-block;border:1px solid var(--line);background:var(--panel2);padding:5px 9px;border-radius:7px;font-size:12px;overflow-wrap:anywhere}.review-area{padding:12px 16px;margin:10px 0;background:var(--panel);border:1px solid var(--line);border-radius:10px}.review-area summary{cursor:pointer;font-weight:800;list-style-position:inside}.count{float:right;padding:0 9px;background:var(--panel2);border-radius:18px;color:var(--muted)}.table-scroll{overflow-x:auto;margin-top:12px}table{width:100%;border-collapse:collapse;min-width:610px}th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--panel2)}td{overflow-wrap:anywhere}
.evidence-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:0;list-style:none}.evidence-list li a{display:block}.footer{border-top:1px solid var(--line);font-size:12px;color:var(--muted);padding:20px 0 40px}.safety-note p{margin:6px 0 0}.metadata{display:flex;flex-wrap:wrap;gap:8px;margin-top:15px}.metadata span{padding:4px 10px;border:1px solid #53667f;border-radius:99px;font-size:12px;color:#d6e3f1}
@media(max-width:780px){.two,.three,.evidence-list{grid-template-columns:1fr}.container{padding:0 16px}nav .container{gap:14px}}
@media print{nav{display:none}.masthead p,.masthead .subline,.metadata span{color:#222!important}a{color:#222!important}.review-area{break-inside:avoid}}
"""
    return f"""<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp()}"><title>{title} — WCA Technical Appendix</title><style>{css}</style></head><body>
<header class="masthead"><div class="container"><div class="topline"><span class="eyebrow">Windows Client Assessment · Client technical appendix · v{_esc(state.get('framework_version') or 'unknown')}</span>{toggle()}</div><h1>{title}</h1>
<p>Reviewed technical context, observed system footprint and approved supporting evidence, organized by security area.</p><div class="subline">{_esc(product)} · {_esc(version)}</div>
<div class="metadata"><span>{_esc(state.get('mode') or 'Unknown mode')}</span><span>{_esc((state.get('target') or {}).get('type') or 'Unknown target type')}</span><span>Offline technical appendix</span></div></div></header>
<nav><div class="container"><a href="#overview">Overview</a><a href="#footprint">Technical footprint</a><a href="#observations">Reviewed observations</a><a href="#evidence">Evidence library</a></div></nav>
<main class="container"><section id="overview"><div class="summary-strip">
<div class="metric"><span>Collection coverage</span><strong>{_esc(grade)}</strong></div><div class="metric"><span>Reviewed observations</span><strong>{len(relevant)}</strong></div><div class="metric"><span>Installed services</span><strong>{_esc(service_count)}</strong></div><div class="metric"><span>Bound network endpoints</span><strong>{_esc(listener_count)}</strong></div>
</div><div style="margin-top:18px">{note}</div></section>
<section id="footprint" class="section"><h2>Observed technical footprint</h2><p class="section-intro">Information below comes from approved, sanitized technical reports. Counts reflect what was observed, not a full security verdict.</p><div class="grid three">{feature_panels}</div></section>
<section id="observations" class="section"><h2>Reviewed security observations</h2><p class="section-intro">Grouped by affected review area. These are review records; refer to supporting evidence for the underlying observation and independently verify any impact.</p>
{''.join(table_blocks) or '<div class="panel">No reviewed observations eligible for export.</div>'}</section>
<section id="evidence" class="section"><h2>Supporting technical reports</h2><p class="section-intro">Only approved, sanitized text artifacts are included. Each link opens an offline file shipped inside this ZIP.</p>
<ul class="evidence-list">{docs}</ul><p class="section-intro">Verify file integrity with SHA256SUMS.txt. No network, external fonts or JavaScript libraries are required.</p></section></main>
<footer class="container footer">WCA client technical appendix · Offline and copy-only · Findings require independent substantiation.</footer><script>{THEME_SCRIPT}</script></body></html>"""


def export_client_appendix(root: Path, output_zip: Path) -> Path:
    """Export a portable ZIP without changing the assessment or its manifest.

    A preflight validates every inventory hash. Every linked artifact must exist
    and be included. The export is staged beside the destination then atomically
    committed, so interruption cannot yield a partial final archive.
    """
    root = Path(root).resolve()
    output_zip = Path(output_zip).expanduser().resolve()
    if output_zip.suffix.lower() != '.zip':
        raise ClientAppendixError('Export destination must end in .zip')
    if output_zip == root or root in output_zip.parents:
        raise ClientAppendixError('Client Appendix destination must be outside the assessment tree.')
    state, manifest, items = export_readiness(root)
    allowed = manifest.get('files', {}).get('reports', {})
    included: dict[str, bytes] = {}
    for name in APPROVED_REPORTS:
        rel = 'reports/' + name
        if rel not in allowed:
            continue
        path = root / 'reports' / name
        if path.is_symlink() or not path.is_file():
            raise ClientAppendixError('Approved source report missing or untrusted: ' + name)
        data = path.read_text(encoding='utf-8', errors='replace')
        # Review reports have already been sanitized by WCA, but sanitize again
        # on export. This copy is not a source mutation.
        scrubbed = sanitize_report_text(data).encode('utf-8')
        included['evidence/' + name] = scrubbed
    if not included:
        raise ClientAppendixError('No approved sanitized technical reports were available.')
    filenames = [name.partition('/')[2] for name in sorted(included)]
    included['assessment_report.html'] = _appendix_html(
        state, items, filenames, {name.partition('/')[2]: data.decode('utf-8')
                                  for name, data in included.items() if name.startswith('evidence/')}
    ).encode('utf-8')
    included['README.txt'] = (
        f"WCA v{state.get('framework_version') or 'unknown'} — CLIENT APPENDIX\n"
        '============================\n'
        'Offline copy-only reviewed technical appendix. Open assessment_report.html.\n'
        'Dispositions are not proof of vulnerability; consult the separate client report.\n'
        'SHA256SUMS.txt lists SHA-256 digests for every other included file.\n'
        'No source assessment files were altered by export.\n'
    ).encode('utf-8')
    included['SHA256SUMS.txt'] = ''.join(
        f'{_sha(data)}  {name}\n' for name, data in sorted(included.items())
    ).encode('utf-8')
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.wca-appendix-', suffix='.zip',
                                         dir=output_zip.parent, delete=False) as handle:
            temp_name = Path(handle.name)
        with zipfile.ZipFile(temp_name, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for name, data in sorted(included.items()):
                bundle.writestr(name, data)
        with zipfile.ZipFile(temp_name) as bundle:
            if bundle.testzip() is not None:
                raise ClientAppendixError('Client Appendix ZIP verification failed.')
            for name, data in included.items():
                if bundle.read(name) != data:
                    raise ClientAppendixError('Client Appendix member verification failed.')
            linked = re.findall(r'href="evidence/([^"]+)"', bundle.read('assessment_report.html').decode('utf-8'))
            if set('evidence/' + x for x in linked) != set(x for x in included if x.startswith('evidence/')):
                raise ClientAppendixError('Client Appendix evidence link verification failed.')
        os.replace(temp_name, output_zip)
    finally:
        if temp_name and temp_name.exists():
            temp_name.unlink()
    return output_zip
