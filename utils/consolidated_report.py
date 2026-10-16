from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
import json
import re
from urllib.parse import quote

from utils.artifacts import ARTIFACTS, module_artifacts
from utils.privacy import portable_basename, sanitize_report_text
from utils.html_theme import THEME_CSS, THEME_SCRIPT, csp, toggle
from utils.assessment_layout import artifact_path, relative_href_from_reports


SEVERITY_ORDER = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4,
}

PHASE_LABELS = {
    "reporting": "Assessment / Reporting",
    "static": "Static Analysis",
    "installed_state": "Installed State / Privilege",
    "runtime": "Runtime / Procmon",
    "surface": "Network / IPC Surface",
    "updater_security": "Updater Security",
}

CRITICAL_MODULES = {
    "Target Information", "Installer Information", "Installer Extraction", "Baseline Snapshot",
    "Post-Activity Snapshot", "System Change Analysis", "MSI Analysis",
}
OPTIONAL_MODULES = {
    "Procmon Runtime Capture", "Procmon Analysis", "DLL Search Review",
    "Runtime Process Review", "Advanced .NET / Native Runtime Review",
    "Network Surface Review", "IPC / Named Pipe Review",
}


def _text(value) -> str:
    return escape(sanitize_report_text(value), quote=True)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    return slug or "item"


def _href(filename: str) -> str:
    return quote(str(filename), safe="._-/")


def _file_link(filename: str, assessment_dir: Path, label: str | None = None) -> str:
    path = artifact_path(assessment_dir, filename)
    href = relative_href_from_reports(assessment_dir, filename)
    if not path.is_file() or href is None:
        return ""
    return f'<a class="evidence-link" href="{_href(href)}">{_text(label or filename)}</a>'


def _module_links(module: str, assessment_dir: Path) -> str:
    links = [_file_link(filename, assessment_dir) for filename in module_artifacts(module)]
    links = [link for link in links if link]
    if not links:
        return '<span class="muted">No linked evidence generated</span>'
    return '<span class="link-list">' + "".join(links) + "</span>"


def _status_rows(status: dict, module_groups: dict, assessment_dir: Path) -> str:
    rows = []
    grouped = set()
    for group, modules in module_groups.items():
        present = [module for module in modules if module in status]
        if not present:
            continue
        rows.append(f'<tr class="group-row"><th colspan="4" id="group-{_slug(group)}">{_text(group)}</th></tr>')
        for module in present:
            grouped.add(module)
            info = status[module]
            state = str(info.get("status") or "UNKNOWN").upper()
            rows.append(
                f'<tr id="module-{_slug(module)}">'
                f'<td>{_text(module)}</td>'
                f'<td><span class="badge status-{_slug(state)}">{_text(state)}</span></td>'
                f'<td>{_text(info.get("details"))}</td>'
                f'<td>{_module_links(module, assessment_dir)}</td>'
                '</tr>'
            )
    remaining = [module for module in status if module not in grouped]
    if remaining:
        rows.append('<tr class="group-row"><th colspan="4" id="group-other">Other</th></tr>')
        for module in remaining:
            info = status[module]
            state = str(info.get("status") or "UNKNOWN").upper()
            rows.append(
                f'<tr id="module-{_slug(module)}">'
                f'<td>{_text(module)}</td>'
                f'<td><span class="badge status-{_slug(state)}">{_text(state)}</span></td>'
                f'<td>{_text(info.get("details"))}</td>'
                f'<td>{_module_links(module, assessment_dir)}</td>'
                '</tr>'
            )
    return "\n".join(rows)


def _finding_cards(findings: list[dict], assessment_dir: Path) -> str:
    if not findings:
        return ('<div class="empty-state">No automated review points were generated. '
                'This does not establish that the assessed software has no vulnerabilities.</div>')
    ordered = sorted(findings, key=lambda item: (
        SEVERITY_ORDER.get(str(item.get("severity") or "Informational"), 99),
        str(item.get("title") or "").lower(),
    ))
    cards = []
    for finding in ordered:
        finding_id = str(finding.get("report_id") or "ARP")
        severity = str(finding.get("severity") or "Informational")
        module = str(finding.get("source_module") or "Unspecified module")
        filenames = []
        for filename in (*(finding.get("artifacts") or ()), *module_artifacts(module)):
            if filename not in filenames and artifact_path(assessment_dir, filename).is_file():
                filenames.append(filename)
        links = "".join(_file_link(filename, assessment_dir) for filename in filenames)
        if not links:
            links = '<span class="muted">No module-specific evidence file was generated.</span>'
        review_ids = finding.get("review_ids") or []
        review_links = " ".join(
            f'<a class="candidate-link" href="#candidate-{_slug(identifier)}">{_text(identifier)}</a>'
            for identifier in review_ids
        ) or '<span class="muted">See Guided Review</span>'
        cards.append(
            f'<article class="finding severity-{_slug(severity)}" id="finding-{_slug(finding_id)}">'
            '<div class="finding-heading">'
            f'<span class="finding-id">{_text(finding_id)}</span>'
            f'<span class="badge severity-badge severity-{_slug(severity)}">{_text(severity)}</span>'
            '</div>'
            f'<h3>{_text(finding.get("title"))}</h3><dl>'
            '<dt>Classification</dt><dd>Automated Review Point — not confirmed</dd>'
            f'<dt>Originating module</dt><dd><a href="#module-{_slug(module)}">{_text(module)}</a></dd>'
            f'<dt>Description</dt><dd>{_text(finding.get("description"))}</dd>'
            f'<dt>Evidence summary</dt><dd>{_text(finding.get("evidence"))}</dd>'
            f'<dt>Recommended validation</dt><dd>{_text(finding.get("recommendation"))}</dd>'
            f'<dt>Guided-review candidates</dt><dd>{review_links}</dd>'
            f'<dt>Supporting files</dt><dd><span class="link-list">{links}</span></dd>'
            '</dl></article>'
        )
    return "\n".join(cards)


def _read_review_state(assessment_dir: Path) -> dict | None:
    try:
        from utils.guided_review import read_review
        return read_review(assessment_dir)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _review_summary(state: dict | None) -> tuple[str, str]:
    labels = ("PENDING", "VALIDATED", "NOT APPLICABLE", "INFORMATIONAL")
    if not state:
        cards = ''.join(
            f'<div class="metric"><span>{_text(label.title())}</span><strong>0</strong></div>'
            for label in labels
        )
        return cards, '<div class="empty-state">Guided review state is not available for this assessment.</div>'
    items = list(state.get("items", {}).values())
    tally = Counter(str(item.get("status") or "PENDING") for item in items)
    cards = ''.join(
        f'<div class="metric"><span>{_text(label.title())}</span><strong>{tally[label]}</strong></div>'
        for label in labels
    )
    completed = len(items) - tally["PENDING"]
    progress = (
        '<div class="progress-wrap">'
        f'<div><strong>{completed} / {len(items)}</strong> review conditions processed</div>'
        f'<progress max="{max(len(items), 1)}" value="{completed}">{completed}/{len(items)}</progress>'
        '</div>'
    )
    return cards, progress


def _action_center(state: dict | None, assessment_dir: Path, coverage: str, status: dict) -> str:
    """Separate review observations from actual coverage gaps and collection failures."""
    items = list((state or {}).get("items", {}).values())
    pending = [item for item in items if str(item.get("status") or "PENDING") == "PENDING"]
    gaps = [(key, info) for key, info in status.items() if info.get("coverage_gap") or
            str(info.get("status") or "").upper() == "ERROR"]
    review_modules = [(key, info) for key, info in status.items()
                      if str(info.get("status") or "").upper() == "WARN" and not info.get("coverage_gap")]
    readiness = 'Review required before Client Appendix export' if pending else 'Review queue complete'
    banner = (f'<div class="action-banner"><strong>{_text(readiness)}</strong>'
              f'<span>{len(pending)} pending · {len(review_modules)} modules with review observations · '
              f'{len(gaps)} collection gaps/failures · Coverage: {_text(coverage)}</span></div>')
    if not pending and not gaps:
        return (banner + '<div class="review-complete"><strong>Review complete</strong> · '
                f'{len(items)} conditions have saved decisions. '
                'Review decisions are not proof of exploitability.</div>')
    entries = []
    for item in pending[:8]:
        target = "#candidate-" + _slug(str(item.get("id") or ""))
        entries.append(f'<li><a href="{target}">{_text(item.get("title") or "Review condition")}</a>'
                       f'<small>{_text(item.get("source_module") or "")}</small></li>')
    if len(pending) > 8:
        entries.append(f'<li><a href="#guided-review">{len(pending)-8} more pending decisions</a></li>')
    if not entries:
        entries.append('<li>All review conditions have saved decisions.</li>')
    return (banner + '<div class="action-columns"><section><h3>Next review actions</h3><ul class="action-list">'
            + ''.join(entries) + '</ul></section><section><h3>Coverage follow-up</h3>'
            + ('<ul class="action-list">' + ''.join(f'<li><a href="#module-{_slug(k)}">{_text(k)}</a>'
               f'<small>{_text(v.get("status") or "UNKNOWN")}</small></li>' for k,v in gaps[:8]) + '</ul>' if gaps
               else '<p>No collection gaps or failures in available state.</p>')
            + '<p class="muted">Module warnings may be review observations; these are counted separately above. '
            'Manual validation is required for security conclusions.</p></section></div>')


def _candidate_cards(state: dict | None, assessment_dir: Path) -> str:
    if not state or not state.get("items"):
        return '<div class="empty-state">No Guided Tester Review candidates are available.</div>'
    try:
        from utils.guided_review import validation_commands, _guide
        from utils.poc_playbooks import candidate_validation
    except ImportError:
        validation_commands = lambda item, root=None: ()
        candidate_validation = lambda item: {"prerequisites": "", "poc_resource": "", "tester_execution": "", "expected_evidence": ""}
        _guide = lambda item: (item.get("recommendation", ""), "", "", "")
    priority = {"PENDING": 0, "VALIDATED": 1, "INFORMATIONAL": 2, "NOT APPLICABLE": 3}
    items = sorted(state["items"].values(), key=lambda item: (
        priority.get(item.get("status"), 9),
        SEVERITY_ORDER.get(str(item.get("severity") or "Informational"), 99),
        str(item.get("source_module") or ""), str(item.get("title") or ""), str(item.get("id") or ""),
    ))
    result = []
    grouped_cards = {name: [] for name in ("PENDING", "VALIDATED", "INFORMATIONAL", "NOT APPLICABLE")}
    for item in items:
        identifier = str(item.get("id") or "WCR")
        status = str(item.get("status") or "PENDING")
        severity = str(item.get("severity") or "Informational")
        module = str(item.get("source_module") or "Unspecified module")
        files = []
        for filename in item.get("artifacts") or ():
            link = _file_link(filename, assessment_dir)
            if link:
                files.append(link)
        if not files:
            files = [_module_links(module, assessment_dir)]
        instruction, vulnerable, secure, not_report = _guide(item)
        commands = validation_commands(item, assessment_dir)
        checks = ''.join(f'<pre>{_text(command)}</pre>' for command in commands[:3])
        if len(commands) > 3:
            checks += f'<p class="muted">{len(commands)-3} additional check(s) are available in evidence_guide.txt.</p>'
        validation = candidate_validation(item)
        notes = str(item.get("notes") or "").strip()
        note_html = f'<div class="tester-note">{_text(notes)}</div>' if notes else '<span class="muted">No tester notes recorded</span>'
        doc_gap = ''
        changed = '<span class="badge status-warn">RE-REVIEW</span>' if item.get("changed_evidence") else ''
        card = (
            f'<details class="candidate" id="candidate-{_slug(identifier)}">'
            '<summary>'
            f'<span><span class="candidate-id">{_text(identifier)}</span> {_text(item.get("title"))}</span>'
            f'<span class="summary-badges"><span class="badge decision-{_slug(status)}">{_text(status)}</span>{changed}</span>'
            '</summary>'
            '<div class="candidate-body">'
            f'{doc_gap}<dl>'
            f'<dt>Severity label</dt><dd>{_text(severity)}</dd>'
            f'<dt>Module</dt><dd><a href="#module-{_slug(module)}">{_text(module)}</a></dd>'
            f'<dt>Affected component</dt><dd>{_text(item.get("component"))}</dd>'
            f'<dt>Matching observations</dt><dd>{_text(item.get("occurrence_count") or 1)}</dd>'
            f'<dt>Tester notes</dt><dd>{note_html}</dd>'
            f'<dt>Supporting evidence</dt><dd><span class="link-list">{"".join(files)}</span></dd>'
            f'<dt>Related test cases</dt><dd>{_text(", ".join(item.get("test_cases") or ()) or "See test_cases.txt")}</dd>'
            '</dl>'
            '<h4>Observed evidence</h4>'
            f'<div class="observation">{_text(item.get("evidence"))}</div>'
            '<h4>Manual validation guidance</h4>'
            '<p class="muted">Tester-controlled validation only; Windows Client Assessment provides evidence, checks and optional PoC resources but never executes the proof.</p>'
            '<h4>Prerequisites</h4>'
            f'<p>{_text(validation.get("prerequisites"))}</p>'
            '<h4>Starting checks</h4>'
            f'{checks}'
            '<h4>Manual validation procedure</h4>'
            f'<p>{_text(instruction)}</p>'
            '<h4>PoC resource</h4>'
            f'<p>{_text(validation.get("poc_resource") or "No bundled PoC resource is required/available for this candidate.")}</p>'
            + ('<p class="muted">Bundled with the Windows Client Assessment tool/source directory, not the assessment output folder.</p>' if validation.get("poc_resource") else '')
            + '<p class="muted">Windows Client Assessment never executes PoC resources; the tester reviews and runs them manually when applicable.</p>'
            '<h4>Tester execution</h4>'
            f'<p>{_text(validation.get("tester_execution"))}</p>'
            '<h4>Expected evidence</h4>'
            f'<p>{_text(validation.get("expected_evidence"))}</p>'
            '<div class="interpret-grid">'
            f'<div><strong>Potential impact</strong><p>{_text(vulnerable)}</p></div>'
            f'<div><strong>Expected secure behavior</strong><p>{_text(secure)}</p></div>'
            f'<div><strong>When not to report</strong><p>{_text(not_report)}</p></div>'
            '</div>'
            '</div></details>'
        )
        grouped_cards.setdefault(status, []).append(card)
    result = []
    for group, cards in grouped_cards.items():
        if not cards:
            continue
        expanded = ' open' if group == "PENDING" else ''
        result.append(f'<details class="review-group" id="review-group-{_slug(group)}"{expanded}>'
                      f'<summary>{_text(group.title())} <span class="count">{len(cards)}</span></summary>'
                      + "\n".join(cards) + '</details>')
    return "\n".join(result)


def _coverage_gaps(status: dict, coverage: str) -> str:
    critical = []
    optional = []
    for module, info in status.items():
        state = str(info.get("status") or "UNKNOWN").upper()
        detail = str(info.get("details") or "")
        if state == "ERROR" or (module in CRITICAL_MODULES and state == "WARN"):
            critical.append((module, state, detail))
        elif info.get("coverage_gap") or (module in OPTIONAL_MODULES and state == "SKIPPED"):
            optional.append((module, state, detail))
    def rows(items, empty):
        if not items:
            return f'<div class="empty-state small">{_text(empty)}</div>'
        return '<ul class="gap-list">' + ''.join(
            f'<li><strong>{_text(module)}</strong> <span class="badge status-{_slug(state)}">{_text(state)}</span><div class="muted">{_text(detail)}</div></li>'
            for module, state, detail in items
        ) + '</ul>'
    return (
        f'<div class="gap-grid"><div><h3>Required / critical</h3>{rows(critical, "No critical coverage gaps recorded.")}</div>'
        f'<div><h3>Optional / observational</h3>{rows(optional, "No optional coverage gaps recorded.")}</div></div>'
        f'<p class="muted">Overall coverage grade: <strong>{_text(coverage)}</strong>. Coverage describes collected evidence, not vulnerability absence.</p>'
    )


def _extract_profile(assessment_dir: Path, status: dict, installer: Path, mode: str) -> str:
    technology = "Not available"
    classification = "Not available"
    product_name = "Not available"
    product_version = "Not available"
    runtime_targets = "Not available"
    local_storage = "Not available"
    profile_path = artifact_path(assessment_dir, "application_profile.txt")

    def profile_value(label: str) -> str:
        if not profile_path.is_file():
            return ""
        try:
            for line in profile_path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.lower().startswith(label.lower()) and ":" in stripped:
                    return stripped.partition(":")[2].strip()
        except OSError:
            pass
        return ""

    if profile_path.is_file():
        product_name = profile_value("Product name") or product_name
        product_version = profile_value("Product version") or product_version
        technology = profile_value("Technologies") or technology
        classification = profile_value("Package classification") or classification
        runtime_targets = profile_value("Runtime target identities") or runtime_targets
        local_storage = profile_value("Local storage evidence") or local_storage
    else:
        tech_path = artifact_path(assessment_dir, "installer_technology.txt")
        scope_path = artifact_path(assessment_dir, "application_scope.txt")
        try:
            if tech_path.is_file():
                for line in tech_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("Built-in detections:"):
                        technology = line.partition(":")[2].strip() or technology
                        break
        except OSError:
            pass
        try:
            if scope_path.is_file():
                for line in scope_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip().startswith("Classification") and ":" in line:
                        classification = line.partition(":")[2].strip() or classification
                        break
        except OSError:
            pass

    sig = status.get("Digital Signature Review", {})
    app_scope = status.get("Application / Package Scope", {})
    return (
        '<div class="profile-grid">'
        f'<div><span>Selected input</span><strong>{_text(portable_basename(installer))}</strong></div>'
        f'<div><span>Assessment mode</span><strong>{_text(mode)}</strong></div>'
        f'<div><span>Product</span><strong>{_text(product_name)}</strong></div>'
        f'<div><span>Version</span><strong>{_text(product_version)}</strong></div>'
        f'<div><span>Package classification</span><strong>{_text(classification)}</strong></div>'
        f'<div><span>Technology</span><strong>{_text(technology)}</strong></div>'
        f'<div><span>Runtime targets</span><strong>{_text(runtime_targets)}</strong></div>'
        f'<div><span>Local storage</span><strong>{_text(local_storage)}</strong></div>'
        f'<div><span>Application scope</span><strong>{_text(app_scope.get("details") or app_scope.get("status") or "Not available")}</strong></div>'
        f'<div><span>Signature review</span><strong>{_text(sig.get("status") or "Not available")}</strong></div>'
        '</div>'
    )


def _evidence_sections(assessment_dir: Path) -> str:
    by_phase: dict[str, list[tuple[str, dict]]] = {}
    for spec in ARTIFACTS.values():
        filename = spec["filename"]
        if (filename == "assessment_report.html" or spec.get("cleanup_only")
                or spec.get("internal") or not artifact_path(assessment_dir, filename).is_file()):
            continue
        by_phase.setdefault(spec["phase"], []).append((filename, spec))
    sections = []
    phase_order = ("reporting", "static", "installed_state", "runtime", "surface", "updater_security")
    for phase in phase_order:
        items = sorted(by_phase.get(phase, []), key=lambda item: item[0].lower())
        if not items:
            continue
        links = []
        for filename, spec in items:
            size = artifact_path(assessment_dir, filename).stat().st_size
            kind = "Primary" if spec.get("primary") else "Supporting"
            links.append('<li>' + _file_link(filename, assessment_dir) +
                         f'<span class="file-meta">{_text(kind)} · {size:,} bytes</span></li>')
        sections.append(
            '<details class="evidence-group">'
            f'<summary>{_text(PHASE_LABELS.get(phase, phase))} <span class="count">{len(items)}</span></summary>'
            f'<ul class="evidence-list">{"".join(links)}</ul></details>'
        )
    if not sections:
        return '<div class="empty-state">No supporting evidence artifacts were present when this report was generated.</div>'
    return "\n".join(sections)



def _guided_runtime_summary(assessment_dir: Path) -> str:
    path = artifact_path(assessment_dir, "working/guided_runtime_observations.json")
    if not path.is_file():
        return '<div class="empty-state">No post-completion Guided Runtime Observation has been recorded.</div>'
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        sessions = data.get("sessions") or []
        latest = sessions[-1] if sessions else {}
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        return '<div class="empty-state">Guided runtime state could not be read.</div>'
    surfaces = latest.get("surfaces") or {}
    cards = []
    for key in ("process_tree", "privileged_helpers", "network", "named_pipes", "ipc_device_activity", "file_writes", "registry_writes", "loaded_images", "updater_activity"):
        item = surfaces.get(key) or {}
        cards.append(
            '<span class="coverage-chip"><strong>' + _text(key.replace("_", " ").title()) + '</strong>'
            '<em>' + _text(item.get("status") or "UNKNOWN") + '</em></span>'
        )
    counts = latest.get("counts") or {}
    session = latest.get("session") or {}
    capture_duration = int(session.get("capture_duration_seconds") or session.get("duration_seconds") or 0)
    processing_duration = int(session.get("processing_duration_seconds") or 0)
    total_duration = int(session.get("total_duration_seconds") or capture_duration + processing_duration)
    def _clock(value):
        h, rem = divmod(max(0, int(value or 0)), 3600); m, sec = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{sec:02d}"
    capture = latest.get("capture") or {}
    summary_cards = [
        f'<div class="metric"><span>Capture duration</span><strong>{_clock(capture_duration)}</strong></div>',
        f'<div class="metric"><span>Evidence processing</span><strong>{_clock(processing_duration)}</strong></div>',
        f'<div class="metric"><span>Observed + processing</span><strong>{_clock(total_duration)}</strong></div>',
        f'<div class="metric"><span>Procmon capture</span><strong>{_text(capture.get("status") or "UNKNOWN")}</strong></div>',
        f'<div class="metric"><span>Current processes</span><strong>{int(counts.get("current_target_processes") or 0)}</strong></div>',
        f'<div class="metric"><span>Processes seen</span><strong>{int(counts.get("target_processes_seen") or 0)}</strong></div>',
        f'<div class="metric"><span>Target events</span><strong>{int(counts.get("procmon_target_events") or 0):,}</strong></div>',
        f'<div class="metric"><span>New review candidates</span><strong>{int(latest.get("new_review_candidates") or 0)}</strong></div>',
    ]
    return (
        f'<p class="muted">Sessions retained: {len(sessions)} · Latest: {_text(latest.get("captured_at") or "Unknown")}</p>'
        f'<div class="metrics">{"".join(summary_cards)}</div>'
        f'<h3>Coverage observations</h3><div class="coverage-chips">{"".join(cards)}</div>'
        + _file_link("guided_runtime_observation.txt", assessment_dir, "Open Guided Runtime observation")
    )

REVIEW_SCRIPT = r"""(function(){'use strict';const workspace=document.getElementById('review-workspace');if(!workspace)return;const source=document.getElementById('review-source'),host=document.getElementById('review-detail-host'),list=document.getElementById('review-choices'),input=document.getElementById('review-search'),status=document.getElementById('review-status'),moduleFilter=document.getElementById('review-module'),counter=document.getElementById('review-count');if(!source||!host||!list)return;const cards=Array.from(source.querySelectorAll('details.candidate'));if(!cards.length)return;const entries=[],modules=new Set();let selected=null;cards.forEach(function(card){const heading=card.querySelector('summary'),label=heading?heading.querySelector('span'):null;const title=label?label.textContent.trim():card.id;const badge=card.querySelector('[class*="decision-"]');const disposition=badge?badge.textContent.trim():'PENDING';const definitions=Array.from(card.querySelectorAll('dt'));let module='Other',severity='Informational';definitions.forEach(function(dt){const dd=dt.nextElementSibling;if(!dd)return;if(dt.textContent.trim()==='Module')module=dd.textContent.trim();if(dt.textContent.trim()==='Severity label')severity=dd.textContent.trim()});modules.add(module);const button=document.createElement('button');button.type='button';button.className='review-choice';button.dataset.target=card.id;button.dataset.status=disposition;button.dataset.module=module;button.dataset.search=(title+' '+module+' '+severity+' '+disposition).toLowerCase();const name=document.createElement('strong');name.textContent=title;const meta=document.createElement('small');meta.textContent=module+' · '+severity+' · '+disposition;button.append(name,meta);list.appendChild(button);entries.push({card:card,button:button});host.appendChild(card);button.addEventListener('click',function(){activate(card)});});Array.from(modules).sort().forEach(function(name){const option=document.createElement('option');option.value=name;option.textContent=name;moduleFilter.appendChild(option)});
function activate(card){if(!card)return;selected=card;entries.forEach(function(entry){const active=entry.card===card;entry.card.classList.toggle('active',active);entry.button.classList.toggle('active',active);entry.button.setAttribute('aria-pressed',String(active));entry.card.open=active});}
function update(){const q=input.value.trim().toLowerCase(),st=status.value,mod=moduleFilter.value;let first=null,n=0;entries.forEach(function(entry){const match=(!q||entry.button.dataset.search.includes(q))&&(!st||entry.button.dataset.status===st)&&(!mod||entry.button.dataset.module===mod);entry.button.hidden=!match;if(match){n++;if(!first)first=entry.card}});counter.textContent=n+' of '+entries.length+' review conditions';if(!selected||!entries.some(entry=>entry.card===selected&&!entry.button.hidden)){activate(first)}if(!n){host.setAttribute('data-empty','true');host.querySelectorAll('details.candidate').forEach(c=>c.classList.remove('active'))}else{host.removeAttribute('data-empty')}}
input.addEventListener('input',update);status.addEventListener('change',update);moduleFilter.addEventListener('change',update);workspace.classList.add('js-ready');update();function followHash(){const id=decodeURIComponent(location.hash.slice(1));const match=entries.find(entry=>entry.card.id===id);if(match){input.value='';status.value='';moduleFilter.value='';update();activate(match.card);match.card.scrollIntoView({block:'nearest'})}}window.addEventListener('hashchange',followHash);followHash();})();"""


REVIEW_CSS = r"""
.review-workspace{min-width:0}.review-sidebar,.review-detail-host{display:none}.review-workspace.js-ready{display:grid;grid-template-columns:minmax(270px,335px) minmax(0,1fr);gap:15px;align-items:start}.review-workspace.js-ready .review-sidebar{display:block;position:sticky;top:76px;max-height:calc(100vh - 95px);overflow:auto}.review-workspace.js-ready .review-detail-host{display:block;min-height:300px;padding:8px;background:var(--panel);border:1px solid var(--line);border-radius:12px}.review-workspace.js-ready .review-source{display:none}.review-workspace.js-ready .candidate{display:none;margin:0;box-shadow:none}.review-workspace.js-ready .candidate.active{display:block;border:none}.review-workspace.js-ready .candidate summary{background:var(--panel2);border-radius:8px}.review-workspace.js-ready .candidate .candidate-body{padding:12px 18px 22px}.review-workspace.js-ready .candidate-body h4{margin-top:19px}.review-sidebar{padding:15px!important}.review-controls{display:grid;gap:9px;margin-bottom:10px}.review-controls input,.review-controls select{width:100%;min-width:0;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px;color:var(--text)}.review-list{max-height:65vh;overflow:auto;border:1px solid var(--line);border-radius:8px}.review-choice{display:block;text-align:left;width:100%;padding:11px 12px;background:var(--panel);border:0;border-bottom:1px solid var(--line);color:var(--text);overflow-wrap:anywhere}.review-choice strong{display:block;font-size:13px}.review-choice small{display:block;color:var(--muted);font-size:11px;margin-top:5px}.review-choice:hover,.review-choice.active{background:var(--panel2)}.review-choice.active{border-left:4px solid var(--accent);padding-left:8px}.review-choice[hidden]{display:none}.review-detail-host[data-empty='true']:before{content:'No conditions match the current filters';display:block;color:var(--muted);padding:20px}.review-detail-host .candidate-body>h4:not(:first-child){border-top:1px solid var(--line);padding-top:14px}.review-detail-host .candidate-body pre{max-height:270px;overflow:auto}.review-detail-host .candidate-body .interpret-grid{gap:8px}.workspace-hint{color:var(--muted);font-size:12px;margin:6px 0 15px}.summary-strip{margin:16px 0}.summary-strip .metric{border:1px solid var(--line)}nav div{align-items:center}nav{background:var(--panel)}.evidence-group:not([open]) .evidence-list{display:none}.evidence-group{box-shadow:none}.review-group:not([open]){box-shadow:none}.findings .finding{box-shadow:none}.section-heading{margin-top:34px}
@media(max-width:880px){.review-workspace.js-ready{grid-template-columns:1fr}.review-workspace.js-ready .review-sidebar{position:static;max-height:none}.review-list{max-height:280px}}@media print{.review-workspace.js-ready{display:block}.review-workspace.js-ready .review-sidebar{display:none}.review-workspace.js-ready .candidate{display:block!important;border:1px solid #ddd;margin:8px 0}.review-workspace.js-ready .review-source{display:none}}
"""


def _review_workspace(cards: str) -> str:
    """Accessible no-JS review cards; enhance to searchable split view offline."""
    return ('<div class="review-workspace" id="review-workspace">'
            '<aside class="review-sidebar panel" aria-label="Review condition navigator">'
            '<div class="tiny-label">Review navigator</div>'
            '<p class="workspace-hint" id="review-count">Filter by disposition, module or keyword</p>'
            '<div class="review-controls"><input id="review-search" class="review-search" type="search" '
            'placeholder="Search conditions" aria-label="Search review conditions">'
            '<select id="review-status" class="review-filter" aria-label="Review disposition">'
            '<option value="">All decisions</option><option>PENDING</option><option>VALIDATED</option>'
            '<option>INFORMATIONAL</option><option>NOT APPLICABLE</option></select>'
            '<select id="review-module" class="review-filter" aria-label="Source module">'
            '<option value="">All modules</option></select></div><div id="review-choices" class="review-list"></div>'
            '</aside><div id="review-detail-host" class="review-detail-host" aria-live="polite"></div>'
            '<div id="review-source" class="review-source">' + cards + '</div></div>')

def generate_consolidated_report(
    assessment_dir: Path,
    assessment_name: str,
    installer: Path,
    mode: str,
    version: str,
    coverage: str,
    status: dict,
    findings: list[dict],
    module_groups: dict,
    target_type: str = "installable",
) -> Path:
    """Generate the v1.9 offline tester dashboard from persisted backend state."""
    assessment_dir = Path(assessment_dir)
    output = artifact_path(assessment_dir, "assessment_report.html")
    review_state = _read_review_state(assessment_dir)
    review_cards, review_progress = _review_summary(review_state)
    status_counts = Counter(str(info.get("status") or "UNKNOWN").upper() for info in status.values())
    module_cards = "".join(
        f'<div class="metric"><span>{_text(name)}</span><strong>{status_counts.get(name, 0)}</strong></div>'
        for name in ("PASS", "WARN", "ERROR", "SKIPPED", "NOT APPLICABLE")
    )
    severity_counts = Counter(str(item.get("severity") or "Informational") for item in findings)
    severity_summary = " · ".join(
        f'{name}: {severity_counts.get(name, 0)}'
        for name in ("Critical", "High", "Medium", "Low", "Informational")
    )
    # Keep the primary navigation compact; technical shortcuts remain available
    # in the report body/evidence index instead of consuming a second nav row.
    nav = [
        '<a href="#overview">Overview</a>', '<a href="#action-center">Action center</a>',
        '<a href="#guided-review">Guided review</a>', '<a href="#manual-testing">Manual testing</a>', '<a href="#guided-runtime">Runtime</a>',
        '<a href="#coverage-gaps">Coverage</a>', '<a href="#evidence-index">Evidence library</a>',
    ]
    navigation_html = "".join(nav)

    document = f'''<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{csp((THEME_SCRIPT, REVIEW_SCRIPT))}">
  <title>{_text(assessment_name)} — Windows Client Assessment Tester Dashboard</title>
  <style>
    :root {{ color-scheme:light dark; --bg:#0a1120; --panel:#101b2e; --panel2:#17253b; --panel3:#0d1728; --text:#e9eef7; --muted:#9caec7; --line:#2b3b55; --accent:#62ccff; --pass:#3bd09a; --warn:#f0be53; --error:#ff707d; --skip:#93a3b8; }}
    * {{ box-sizing:border-box; }} html {{ scroll-behavior:smooth; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
    a {{ color:var(--accent); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
    header,main,footer {{ width:min(1220px,calc(100% - 32px)); margin:auto; }}
    header {{ padding:42px 0 24px; }} h1 {{ margin:0 0 8px; font-size:clamp(30px,5vw,46px); line-height:1.08; }}
    h2 {{ margin:42px 0 8px; font-size:26px; }} h3 {{ margin:12px 0; }} h4 {{ margin:22px 0 8px; }}
    .eyebrow {{ color:var(--accent); font-weight:800; letter-spacing:.08em; text-transform:uppercase; }}
    .meta,.muted,.file-meta {{ color:var(--muted); }} .meta {{ display:flex; flex-wrap:wrap; gap:8px 20px; margin-top:14px; }}
    nav {{ position:sticky; top:0; z-index:2; background:rgba(10,17,32,.96); border-block:1px solid var(--line); }}
    nav div {{ width:min(1220px,calc(100% - 32px)); margin:auto; display:flex; flex-wrap:wrap; gap:18px; padding:11px 0; }}
    .hero-grid,.gap-grid,.interpret-grid {{ display:grid; gap:14px; }} .hero-grid {{ grid-template-columns:1.1fr 1fr; margin-top:22px; }}
    .panel,.notice,.finding,details,.table-wrap,.profile-grid>div {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; }}
    .panel {{ padding:20px; }} .notice {{ padding:14px 17px; border-left:4px solid var(--warn); }} .notice.compact {{ margin:0 0 16px; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(125px,1fr)); gap:10px; }}
    .metric {{ background:var(--panel2); padding:11px 13px; border-radius:9px; display:flex; justify-content:space-between; align-items:center; gap:10px; }}
    .metric strong {{ font-size:21px; }} .progress-wrap {{ margin-top:14px; }} progress {{ width:100%; height:12px; margin-top:8px; }}
    .profile-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; }} .profile-grid>div {{ padding:13px; display:flex; flex-direction:column; gap:5px; }} .profile-grid span {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }} .profile-grid strong {{ overflow-wrap:anywhere; }}
    .badge {{ display:inline-block; border-radius:999px; padding:2px 9px; font-size:12px; font-weight:800; letter-spacing:.03em; white-space:nowrap; }}
    .status-pass {{ color:#052117; background:var(--pass); }} .status-warn {{ color:#2b1c00; background:var(--warn); }} .status-error {{ color:#30070c; background:var(--error); }} .status-skipped,.status-not-applicable {{ color:#111826; background:var(--skip); }}
    .decision-pending {{ background:var(--warn); color:#2b1c00; }} .decision-validated {{ background:#a7c3f8; color:#102144; }} .decision-not-applicable,.decision-informational {{ background:var(--skip); color:#111826; }}
    .action-banner {{ background:var(--panel2);border:1px solid var(--line);border-left:4px solid var(--accent);padding:16px;border-radius:10px;display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px; }}
    .action-columns {{ display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px; }}
    .action-columns section {{ background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:15px; }}
    .action-list {{ list-style:none;padding:0;margin:0; }} .action-list li {{ border-bottom:1px solid var(--line);padding:8px 0; }}
    .action-list small {{ display:block;color:var(--muted); }}
    .coverage-chips {{ display:flex;flex-wrap:wrap;gap:8px;margin-top:10px; }}
    .coverage-chip {{ display:inline-flex;flex-direction:column;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 10px;min-width:120px; }}
    .coverage-chip strong {{ font-size:12px; }} .coverage-chip em {{ font-style:normal;color:var(--muted);font-size:11px; }}
    .review-group {{ padding:10px 14px;margin:12px 0; }} .review-group>summary {{ cursor:pointer;font-weight:800;padding:5px 0; }}
    .candidate {{ margin:10px 0; scroll-margin-top:64px; }} .candidate summary {{ display:flex; justify-content:space-between; gap:12px; align-items:center; cursor:pointer; padding:14px 16px; font-weight:700; }} .candidate-id,.finding-id {{ color:var(--accent); font-weight:800; margin-right:8px; }} .summary-badges {{ display:flex; gap:6px; align-items:center; }} .candidate-body {{ padding:0 16px 18px; border-top:1px solid var(--line); }}
    dl {{ display:grid; grid-template-columns:180px 1fr; gap:8px 16px; }} dt {{ color:var(--muted); font-weight:700; }} dd {{ margin:0; overflow-wrap:anywhere; }}
    .tester-note {{ white-space:pre-wrap; overflow-wrap:anywhere; }}
    pre,.observation {{ background:var(--panel3); border:1px solid var(--line); border-radius:9px; padding:11px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; }}
    .interpret-grid {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} .interpret-grid>div {{ background:var(--panel2); border-radius:9px; padding:12px; }}
    .gap-grid {{ grid-template-columns:1fr 1fr; }} .gap-list {{ list-style:none; padding:0; margin:0; }} .gap-list li {{ background:var(--panel2); border-radius:9px; padding:10px; margin:8px 0; }} .empty-state {{ padding:24px; color:var(--muted); border:1px dashed var(--line); border-radius:12px; }} .empty-state.small {{ padding:14px; }}
    .table-wrap {{ overflow:auto; }} table {{ width:100%; border-collapse:collapse; min-width:780px; }} th,td {{ padding:11px 13px; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; }} thead th {{ background:var(--panel2); }} .group-row th {{ background:var(--panel3); color:var(--accent); text-transform:uppercase; letter-spacing:.05em; }}
    .findings {{ display:grid; gap:14px; }} .finding {{ padding:20px; scroll-margin-top:64px; }} .finding-heading {{ display:flex; justify-content:space-between; gap:12px; }} .severity-badge {{ background:var(--panel2); border:1px solid currentColor; }}
    .link-list {{ display:flex; flex-wrap:wrap; gap:6px; }} .evidence-link,.candidate-link {{ display:inline-block; background:var(--panel2); border:1px solid var(--line); border-radius:7px; padding:2px 7px; overflow-wrap:anywhere; }}
    .evidence-group {{ margin:10px 0; padding:4px 14px; }} .evidence-group summary {{ cursor:pointer; font-weight:750; padding:10px 0; }} .count {{ background:var(--panel2); border-radius:999px; padding:1px 7px; color:var(--muted); }} .evidence-list {{ list-style:none; padding:0 0 8px; margin:0; display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:8px; }} .evidence-list li {{ display:flex; align-items:center; justify-content:space-between; gap:8px; background:var(--panel2); border-radius:8px; padding:8px; }} .file-meta {{ font-size:12px; white-space:nowrap; }}
    footer {{ color:var(--muted); padding:40px 0; }}
    @media (max-width:820px) {{ .hero-grid,.gap-grid,.interpret-grid,.profile-grid,.action-columns {{ grid-template-columns:1fr; }} dl {{ grid-template-columns:1fr; }} dt {{ margin-top:8px; }} .candidate summary {{ align-items:flex-start; flex-direction:column; }} }}
    @media print {{ :root {{ color-scheme:light; --bg:#fff; --panel:#fff; --panel2:#f4f6f8; --panel3:#f7f7f7; --text:#111; --muted:#4b5563; --line:#d2d7de; --accent:#005a8d; }} nav {{ display:none; }} body {{ font-size:11px; }} details {{ break-inside:avoid; }} details > * {{ display:block; }} .candidate-body {{ display:block!important; }} a {{ color:inherit; }} }}
    {THEME_CSS}
    {REVIEW_CSS}
  </style>
</head>
<body>
  <header id="overview">
    <div class="eyebrow">Windows Client Assessment v{_text(version)} · Tester Dashboard</div>
    <h1>{_text(assessment_name)}</h1>
    <div class="meta"><span>Target: {_text(portable_basename(installer))}</span><span>Target type: {_text(target_type)}</span><span>Mode: {_text(mode)}</span><span>Coverage: {_text(coverage)}</span><span>Offline / read-only dashboard</span></div>
    <div class="hero-grid">
      <section class="panel"><h3>Guided review progress</h3><div class="metrics">{review_cards}</div>{review_progress}</section>
      <section class="panel"><h3>Module health</h3><div class="metrics">{module_cards}</div><p class="muted">Module status reflects collection/analysis health, not vulnerability confirmation.</p></section>
    </div>
  </header>
  <nav><div>{navigation_html}{toggle()}</div></nav>
  <main>
    <p class="notice"><strong>Tester interpretation required:</strong> automated observations and reviewer dispositions are not independently confirmed vulnerabilities. Use the linked evidence and validation guidance before client reporting.</p>
    <section id="action-center"><h2>Tester Action Center</h2>{_action_center(review_state, assessment_dir, coverage, status)}</section>
    <section id="manual-testing"><h2>Manual Security Test Cases</h2><p class="muted"><strong>Collection COMPLETE is not Security Testing COMPLETE.</strong> Use the local WCA v2.2.0 GUI Tester Workspace > Testing Queue to complete the applicable manual procedures and related Guided Review candidates in one place. A manual status does not close an activity while linked Guided Review candidates remain pending. Generated test cases and the attack-surface plan are supporting references, not additional checklists. This offline HTML dashboard is read-only and does not display current live testing progress.</p><div class="link-list">{_file_link("test_cases.txt", assessment_dir, "Optional offline test-case reference")}{_file_link("attack_surface_test_plan.txt", assessment_dir, "Optional full attack-surface methodology")}{_file_link("coverage_summary.txt", assessment_dir, "Open collection coverage")}</div></section>
    <section id="application-profile"><h2>Application / Technology Profile</h2>{_extract_profile(assessment_dir, status, installer, mode)}</section>
    <section id="guided-review"><h2>Guided Tester Review</h2><p class="muted">Select a condition to inspect its disposition, supporting evidence and optional validation instructions. Review decisions are edited through the CLI, not this HTML file.</p>{_review_workspace(_candidate_cards(review_state, assessment_dir))}</section>
    <section id="coverage-gaps"><h2>Coverage Gaps and Limitations</h2>{_coverage_gaps(status, coverage)}</section>
    <section id="attack-surface"><h2>Windows Thick Client Attack Surface Coverage</h2><p>The vendor-neutral attack-surface plan combines automatic indicators with tester-guided validation across Windows execution, privilege, IPC, storage, network, update, memory, framework and application-trust surfaces. Unobserved surfaces are not automatically treated as secure.</p>{_file_link("attack_surface_test_plan.txt", assessment_dir, "Open attack-surface test plan")}</section>
    <section id="review-points"><h2>Automated Review Points</h2><p class="muted">{len(findings)} total · {_text(severity_summary)}. These are source observations feeding Guided Review.</p><details class="evidence-group"><summary>Show automated review points ({len(findings)})</summary><div class="findings">{_finding_cards(findings, assessment_dir)}</div></details></section>
    <section id="module-status"><h2>Module Health and Evidence</h2><details class="evidence-group"><summary>Open complete module status table</summary><div class="table-wrap"><table><thead><tr><th>Module</th><th>Status</th><th>Details</th><th>Supporting evidence</th></tr></thead><tbody>{_status_rows(status, module_groups, assessment_dir)}</tbody></table></div></details></section>
    <section id="guided-runtime"><h2>Guided Runtime Observation</h2><p class="muted">Post-completion tester-driven runtime observation. The tester exercises approved workflows; Windows Client Assessment only observes and records target-associated evidence.</p>{_guided_runtime_summary(assessment_dir)}</section>
    <section id="evidence-index"><h2>Browsable Evidence Index</h2><p class="muted">Only artifacts present in this assessment are listed. Large inventories remain grouped by phase while individual security surfaces stay independently reviewable above.</p>{_evidence_sections(assessment_dir)}</section>
  </main>
  <footer>Generated locally from persisted Windows Client Assessment backend state. Theme preference is local to this browser; review decisions remain in the CLI. No external scripts, fonts, styles or network resources.</footer>
<script>{THEME_SCRIPT}</script><script>{REVIEW_SCRIPT}</script>
</body>
</html>'''
    from utils.assessment_integrity import _atomic_text
    _atomic_text(output, document)
    return output
