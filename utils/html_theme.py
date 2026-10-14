"""Self-contained offline report theming. No network assets, remote code or telemetry."""
from __future__ import annotations

import base64
import hashlib
from html import escape


THEME_CSS = r"""
:root,[data-theme="dark"]{color-scheme:dark;--bg:#0a1220;--panel:#121e30;--panel2:#1b2a40;--panel3:#0d1828;--text:#ecf3fc;--muted:#a9b9ce;--line:#32445f;--accent:#79d1ef;--pass:#61ddaf;--warn:#f0c46d;--error:#ff8791;--skip:#aab9ce;--header:#101c30;--shadow:0 8px 25px #050b1440}
:root[data-theme="light"]{color-scheme:light;--bg:#f5f7fb;--panel:#fff;--panel2:#eef3f9;--panel3:#f7f9fc;--text:#142438;--muted:#53677f;--line:#d5dfea;--accent:#096484;--pass:#087b50;--warn:#94630c;--error:#b83243;--skip:#53677f;--header:#172b47;--shadow:0 7px 22px #172b4711}
body{background:var(--bg)!important;color:var(--text)!important}
button,input,select{font:inherit}button{cursor:pointer}
.theme-toggle{margin-left:auto;border:1px solid var(--line);border-radius:9px;padding:7px 12px;background:var(--panel2);color:var(--text);font-weight:750;white-space:nowrap;box-shadow:none}
.theme-toggle:focus-visible,.review-choice:focus-visible,.review-search:focus-visible,.review-filter:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.theme-toggle:hover{border-color:var(--accent)}
header{background:linear-gradient(130deg,var(--header),var(--panel3));border-bottom:1px solid var(--line);border-radius:0 0 18px 18px}
[data-theme="light"] header{color:#fff}[data-theme="light"] header .panel,[data-theme="light"] header .panel *,[data-theme="light"] header .metric,[data-theme="light"] header .metric *{color:var(--text)}[data-theme="light"] header .metric span{color:var(--muted)}[data-theme="light"] header .eyebrow,[data-theme="light"] header .meta{color:#d2e5f2}
.panel,.metric,.finding,details,.table-wrap,.profile-grid>div{box-shadow:var(--shadow)}
.panel,.finding,.table-wrap,.profile-grid>div,.review-group,.evidence-group{border:1px solid var(--line);border-radius:12px;background:var(--panel)}
.panel{padding:20px}
.muted,.file-meta{color:var(--muted)}
a{color:var(--accent)}
.notice{background:var(--panel2);border:1px solid var(--line);border-left:4px solid var(--warn);color:var(--text)}
.summary-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}
.summary-strip .metric{display:flex;flex-direction:column;align-items:flex-start;gap:8px;padding:17px;min-height:91px}
.summary-strip .metric strong{font-size:clamp(15px,2vw,27px);line-height:1.2;font-variant-numeric:tabular-nums;max-width:100%;overflow-wrap:anywhere;word-break:break-word}
.summary-strip .metric span{font-size:12px;color:var(--muted)}
.section-intro{color:var(--muted);margin:0 0 15px}
.tiny-label{font-size:11px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:var(--accent)}
.safety-note{border-left:4px solid var(--warn);background:var(--panel2);padding:15px 19px;border-radius:8px;line-height:1.6}
@media(max-width:800px){.summary-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:480px){.summary-strip{grid-template-columns:1fr}}
@media print{[data-theme="dark"],[data-theme="light"]{color-scheme:light;--bg:#fff;--panel:#fff;--panel2:#f4f6fa;--panel3:#f4f6fa;--text:#111;--muted:#46546a;--line:#ccd4dc;--accent:#125b7a;--shadow:none}.theme-toggle,.review-controls,.review-sidebar{display:none!important}header{background:white;color:#111!important}header .eyebrow,header .meta{color:#333!important}}
"""

THEME_SCRIPT = r"""(function(){'use strict';const root=document.documentElement;const button=document.getElementById('theme-toggle');const key='wca-report-color-theme';let theme='dark';try{const stored=localStorage.getItem(key);if(stored==='dark'||stored==='light')theme=stored}catch(e){}function setTheme(value){root.setAttribute('data-theme',value);if(button){button.textContent=value==='dark'?'Light theme':'Dark theme';button.setAttribute('aria-label','Switch to '+(value==='dark'?'light':'dark')+' theme');button.setAttribute('aria-pressed',String(value==='light'))}}setTheme(theme);if(button)button.addEventListener('click',function(){theme=root.getAttribute('data-theme')==='dark'?'light':'dark';setTheme(theme);try{localStorage.setItem(key,theme)}catch(e){}})})();"""


def script_hash(script: str) -> str:
    digest = hashlib.sha256(script.encode('utf-8')).digest()
    return 'sha256-' + base64.b64encode(digest).decode('ascii')


def csp(scripts: tuple[str, ...] = (THEME_SCRIPT,)) -> str:
    """Explicit inline hash allowlist; all remote resources disallowed."""
    allowed = ' '.join("'" + script_hash(code) + "'" for code in scripts)
    return escape("default-src 'none'; style-src 'unsafe-inline'; script-src " + allowed
                  + "; base-uri 'none'; form-action 'none'; connect-src 'none'; object-src 'none'", quote=True)


def toggle() -> str:
    return '<button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light theme">Light theme</button>'
