"""Safe, bounded excerpts from already collected assessment reports.

This API does not execute commands or read arbitrary browser-provided paths.
Only single-name `.txt` / `.md` reports under the verified assessment reports
folder may be displayed. It is a presentation aid, not new evidence collection.
"""
from pathlib import Path
import re

from utils.privacy import sanitize_report_text

MAX_REPORT_BYTES = 2_000_000
MAX_EXCERPT = 5400


def stored_target_evidence(root: Path, report: str, target: str) -> dict:
    if not isinstance(report, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,110}\.(?:txt|md)', report, re.I):
        raise ValueError('Invalid report identifier.')
    if not isinstance(target, str) or not target.strip() or len(target) > 1500:
        raise ValueError('Invalid target identifier.')
    path = root / 'reports' / report
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES:
        return {'found': False, 'excerpt': '', 'truncated': False}
    contents = path.read_text(encoding='utf-8', errors='replace')
    # TC-NW-001 records a machine-readable PID|name target, while the report
    # prints "name (PID N)". Match *both* identity fields, never the literal
    # separator, and return all endpoints for the selected process.
    network_target = re.fullmatch(r'(\d{1,7})\|([\w .()\-]{1,140})', target.strip())
    if report.lower() == 'network_surface_review.txt' and network_target:
        pid, name = network_target.groups()
        marker = re.compile(r'^\[NW-\d+\]\s+(.+?)\s+\(PID\s+(\d+)\)\s*$', re.I | re.M)
        records = []
        for match in marker.finditer(contents):
            if match.group(2) != pid or match.group(1).strip().casefold() != name.strip().casefold():
                continue
            following = marker.search(contents, match.end())
            # A POI block begins after the endpoint inventory; never include
            # unrelated processes or arbitrary report content.
            boundary = contents.find('NETWORK POINTS OF INTEREST', match.end())
            ends = [len(contents)] + ([following.start()] if following else []) + ([boundary] if boundary >= 0 else [])
            block = contents[match.start():min(ends)]
            def field(label):
                found = re.search(r'(?m)^\s*' + re.escape(label) + r'\s*:\s*(.*?)\s*$', block)
                return sanitize_report_text(found.group(1).strip())[:300] if found else ''
            records.append({'protocol': field('Protocol'), 'endpoint': field('Local Endpoint'),
                            'state': field('State'), 'scope': field('Bind Scope'),
                            'user': field('Execution User'), 'privileged': field('Privileged Context')})
            if len(records) >= 64:
                break
        if records:
            excerpt = '\n'.join(f"{x['protocol']} {x['endpoint']} | {x['state']} | {x['scope']} | user={x['user']}" for x in records)
            excerpt = sanitize_report_text(excerpt)
            return {'found': True, 'excerpt': excerpt[:MAX_EXCERPT],
                    'truncated': len(excerpt) > MAX_EXCERPT, 'matches': len(records),
                    'source': report, 'network_endpoints': records, 'acl': {},
                    'historical': True}
        return {'found': False, 'excerpt': '', 'truncated': False,
                'network_endpoints': [], 'historical': True}
    # TC-LS-001: select exactly one STORE record, not the nearest 18 lines
    # (which previously displayed unrelated storage objects). ACL metadata is
    # collected during full assessment; old reports without it are explicitly
    # marked as lacking an ACL rather than misrepresenting inventory counts.
    if report.lower() == 'local_storage_review.txt':
        blocks = list(re.finditer(r'(?m)^\[STORE-\d+\]\s+([^\r\n]+)', contents))
        selected = None
        for i, match in enumerate(blocks):
            observed = match.group(1).strip()
            if observed.casefold() not in (target.strip().casefold(), sanitize_report_text(target.strip()).casefold()):
                continue
            end = blocks[i+1].start() if i+1 < len(blocks) else len(contents)
            section_end = re.search(r'(?mi)^REGISTRY STORAGE(?:\s*\(\d+\))?\s*$', contents[match.end():end])
            if section_end:
                end = min(end, match.end()+section_end.start())
            selected = contents[match.start():end].strip()
            break
        if selected is None:
            return {'found': False, 'excerpt': '', 'truncated': False, 'acl': {}, 'storage_acl': {}}
        result = {}
        for label in ('File', 'Parent'):
            name = re.escape(label)
            def field(key):
                found = re.search(r'(?m)^  ' + name + r' ' + key + r':\s*(.*)$', selected)
                return sanitize_report_text(found.group(1).strip()) if found else ''
            entries=[]
            for match in re.finditer(r'(?m)^    ' + name + r' ACE:\s*(.*)$', selected):
                parts=[x.strip() for x in match.group(1).split(' | ',3)]
                if len(parts)==4:
                    entries.append(dict(zip(('principal','rights','type','inherited'), parts)))
            result[label.lower()] = {'path':field('Path'), 'status':field('ACL Status') or 'NOT COLLECTED',
                    'owner':field('Owner'), 'entries': entries,
                    'broad_write_indicated': bool(re.match(r'^[1-9]\d*$', field('Broad Write ACE Count'))),
                    'truncated': bool(field('ACE Truncated'))}
        excerpt = sanitize_report_text(selected)
        return {'found': True, 'excerpt':excerpt[:MAX_EXCERPT], 'truncated':len(excerpt)>MAX_EXCERPT,
                'matches':1, 'source': report, 'acl': {}, 'storage_acl':result, 'historical':True}
    # Target controls only text matching inside the already trusted report.
    # Prefer a full ACL section when available; otherwise bounded line context.
    needle = target.casefold().strip()
    lines = contents.splitlines()
    hits = [i for i, line in enumerate(lines) if needle in line.casefold()]
    if not hits:
        # Path display may be normalized to %USERPROFILE% in reports.
        name = re.split(r'[\\/]', target)[-1].casefold()
        if len(name) >= 5:
            hits = [i for i, line in enumerate(lines) if name in line.casefold()]
    if not hits:
        return {'found': False, 'excerpt': '', 'truncated': False}
    i = hits[0]
    start = max(0, i - 5)
    # permissions_review.txt uses an entire ACL-NNN block with ACEs below Path.
    if report.lower() == 'permissions_review.txt':
        while start > 0 and not re.search(r'^\[ACL-\d+\]', lines[start]):
            start -= 1
            if i - start > 22:  # never walk arbitrarily far
                start = max(0, i - 5)
                break
        stop = min(len(lines), i + 90)
        for j in range(i + 1, stop):
            if j > i + 3 and re.match(r'^\[ACL-\d+\]', lines[j]):
                stop = j
                break
    else:
        stop = min(len(lines), i + 18)
    raw_excerpt = '\n'.join(lines[start:stop])
    acl = {}
    if report.lower() == 'permissions_review.txt':
        for label, key in [('Path','path'), ('Owner','owner'), ('Component','component'), ('Account','account')]:
            match = re.search(r'(?m)^' + label + r'\s*:\s*(.+)$', raw_excerpt)
            if match:
                acl[key] = sanitize_report_text(match.group(1).strip())
        entries = []
        for entry in re.split(r'(?m)^\s*\[\d{2}\]\s*$', raw_excerpt)[1:]:
            vals = {}
            for field, name in [('Identity','principal'),('Rights','rights'),('Type','type'),('Inherited','inherited')]:
                match = re.search(r'(?m)^\s*' + field + r'\s*:\s*(.+)$', entry)
                if match:
                    vals[name] = sanitize_report_text(match.group(1).strip())
            if vals.get('principal'):
                entries.append(vals)
        acl['entries'] = entries[:50]
        acl['broad_write_indicated'] = bool(re.search(r'Broad Write ACEs\s*\([1-9]\d*\)', raw_excerpt))
        acl['status'] = 'REQUIRES REVIEW' if acl['broad_write_indicated'] else 'COLLECTED'
    excerpt = sanitize_report_text(raw_excerpt)
    return {'found': True, 'excerpt': excerpt[:MAX_EXCERPT], 'truncated': len(excerpt) > MAX_EXCERPT or len(hits) > 1,
            'matches': len(hits), 'source': report, 'acl': acl}
