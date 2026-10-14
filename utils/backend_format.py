"""Offline, read-only formatting for WCA's structured backend responses.

The JSON envelope remains the authoritative API contract. Text is a human
presentation of the already-sanitized response and never opens assessment files.
"""
from __future__ import annotations

from textwrap import wrap
from typing import Any


def _line(label: str, value: Any) -> str:
    return f"{label:<21} {value if value is not None else '—'}"


def _table(headers: tuple[str, ...], rows: list[tuple[Any, ...]], widths: tuple[int, ...]) -> list[str]:
    # A bounded console-friendly table; multiline values wrap without truncation.
    def cells(values: tuple[Any, ...]) -> list[list[str]]:
        result = []
        for item, width in zip(values, widths):
            lines = []
            for part in str(item if item is not None else '').splitlines() or ['']:
                lines.extend(wrap(part, width=width, break_long_words=True, break_on_hyphens=False,
                                  replace_whitespace=False, drop_whitespace=False) or [''])
            result.append(lines)
        return result

    def draw(values: tuple[Any, ...]) -> list[str]:
        wrapped = cells(values)
        height = max(map(len, wrapped), default=1)
        return ['  '.join((column[i] if i < len(column) else '').ljust(width)
                         for column, width in zip(wrapped, widths)).rstrip()
                for i in range(height)]

    output = draw(headers)
    output.append('  '.join('-' * width for width in widths))
    for row in rows:
        output.extend(draw(row))
    return output


def render_backend_text(action: str, response: dict[str, Any]) -> str:
    """Render a JSON-safe BackendService response for terminal reading only."""
    if not response.get('ok'):
        # Never echo the requested assessment path, exception details or unsanitized
        # user-supplied material. BackendService already sanitizes its messages.
        return '\n'.join((f"WCA backend — {action}",
                          f"Status: FAILED ({response.get('code', 'ERROR')})",
                          str(response.get('message') or 'Operation unavailable.')))

    data = response.get('data') or {}
    lines = [f"WCA backend — {action.replace('_', ' ').title()}", '-' * 49]
    if action == 'capabilities':
        interface = data.get('interface') or {}
        lines += [_line('Framework', f"{data.get('framework', 'WCA')} {data.get('version', '')}"),
                  _line('Schema', response.get('schema', '')),
                  _line('Target types', ', '.join(data.get('target_types') or [])),
                  _line('Assessment modes', ', '.join(data.get('assessment_modes') or [])),
                  _line('CLI', 'Available' if interface.get('cli') else 'Unavailable'),
                  _line('GUI', 'Available' if interface.get('gui') else 'Not in this release'),
                  _line('HTTP service', 'Available' if interface.get('http_server') else 'Disabled'), '',
                  'Backend operations:']
        ops = data.get('operations') or {}
        lines.extend(_table(('Operation', 'Availability'),
                            [(key, 'GUI worker / CLI' if value.get('availability') == 'cli_and_gui_worker'
                              else 'CLI only' if value.get('availability') == 'cli_only'
                              else 'Explicit write' if value.get('mutates') else 'Read only')
                             for key, value in sorted(ops.items())], (26, 20)))
    elif action == 'tool_readiness':
        tools = data.get('tools') or []
        lines += [_line('Detected', f"{sum(1 for t in tools if t.get('found'))}/{len(tools)}"), '']
        lines.extend(_table(('Tool', 'Level', 'Usage', 'Detected'),
                            [(tool.get('name',''), tool.get('level',''), tool.get('usage',''),
                              'YES' if tool.get('found') else 'NO') for tool in tools],
                            (21, 12, 20, 8)))
    elif action == 'status':
        for label, key in (('Assessment', 'name'), ('Target type', 'target_type'), ('Mode', 'mode'),
                           ('State', 'status'), ('Current stage', 'stage'), ('Coverage', 'coverage'),
                           ('Framework version', 'framework_version'), ('Recovery', 'recovery_action')):
            if key in data:
                lines.append(_line(label, data[key]))
        integrity = data.get('integrity') or {}
        if integrity:
            lines.append(_line('Integrity', integrity.get('status','UNKNOWN')))
        if data.get('available_actions'):
            lines.append(_line('Available actions', ', '.join(data['available_actions'])))
        stages = data.get('stages') or {}
        if stages:
            lines += ['', 'Lifecycle checkpoints:']
            lines.extend(_table(('Stage','Status'), sorted(stages.items()), (29, 16)))
    elif action == 'verify':
        lines += [_line('Integrity', data.get('status','UNKNOWN')),
                  _line('Repairable', 'Yes' if data.get('repairable') else 'No'), '',
                  'Verification checks:']
        checks = data.get('checks') or []
        lines.extend(_table(('Check', 'Status', 'Issues', 'Details'),
                            [(c.get('name',''), c.get('status',''), c.get('issue_count',0), c.get('details',''))
                             for c in checks], (29, 9, 6, 39)))
        if data.get('damaged_counts'):
            lines += ['', _line('Damaged files', ', '.join(f"{key}: {value}"
                          for key, value in data['damaged_counts'].items()))]
    elif action == 'review':
        items = data.get('items') or []
        disp = data.get('by_disposition') or {}
        lines += [_line('Conditions', data.get('total', len(items))),
                  _line('Pending', data.get('pending', 0)),
                  _line('Decisions', ', '.join(f"{key}: {value}" for key, value in disp.items())), '',
                  'Review conditions:']
        lines.extend(_table(('#', 'Decision', 'Severity', 'Module', 'Observation'),
                            [(i, r.get('status',''), r.get('severity',''),
                              r.get('module',''), r.get('title','')) for i, r in enumerate(items, 1)],
                            (3, 14, 13, 27, 49)))
    elif action == 'appendix_readiness':
        lines += [_line('Ready to export', 'Yes' if data.get('ready') else 'No'),
                  _line('Assessment', data.get('integrity', 'UNKNOWN')),
                  _line('Reviewed conditions', data.get('reviewed_items', 0)), '',
                  'Export remains an explicit tester-controlled operation.']
    else:
        lines += [str(response.get('message') or 'Operation complete.')]
    return '\n'.join(lines).rstrip() + '\n'
