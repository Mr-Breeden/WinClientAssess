from __future__ import annotations

"""Conservative target identity correlation helpers.

These helpers intentionally separate target identity from temporal host churn.
A pre/post snapshot can contain unrelated InstalledApplications changes, so an
application record is not considered target evidence merely because it appeared
inside the assessment window.
"""

import ntpath
import re
from pathlib import Path

from utils.assessment_layout import artifact_path
from utils.component_context import normalize_path
from utils.windows_paths import extract_executable

_GENERIC_TOKENS = {
    "windows", "microsoft", "corporation", "company", "software", "systems",
    "solutions", "technology", "technologies", "program", "files", "programdata",
    "appdata", "local", "roaming", "client", "server", "service", "application",
    "installer", "install", "setup", "update", "updater", "runtime", "system32",
    "users", "current", "user", "current_user", "current_user_sid", "exe", "dll",
    "x86", "x64", "amd64", "arm64", "release", "version", "package", "packages",
    "inc", "corp", "llc", "ltd", "limited", "group", "security", "labs",
}


def _split_words(value: str) -> list[str]:
    text = str(value or "").strip()
    # Split CamelCase before the ordinary path/punctuation split. This turns
    # names such as AcmeWidgetService into useful, exact identity words.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return re.split(r"[\\/\s._()\[\]{}\-,:;+]+", text)


def identity_tokens(*values) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        for part in _split_words(str(value or "")):
            token = part.strip().lower()
            if len(token) < 4 or token in _GENERIC_TOKENS or token.isdigit():
                continue
            if re.fullmatch(r"v?\d+(?:\.\d+)*", token):
                continue
            if re.fullmatch(r"[0-9a-f]{16,}", token):
                continue
            tokens.add(token)
    return tokens


def read_msi_properties(assessment_dir: Path) -> dict[str, str]:
    """Read already-sanitized MSI Property rows from msi_analysis.txt.

    This keeps Guided Runtime regeneration independent of the original installer
    while reusing evidence WCA already persisted in the assessment.
    """
    path = artifact_path(Path(assessment_dir), "msi_analysis.txt")
    if not path.is_file():
        return {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}

    props: dict[str, str] = {}
    current = ""
    for line in lines:
        match = re.match(r"^\s*Property\s*:\s*(.*?)\s*$", line, re.I)
        if match:
            current = match.group(1).strip()
            continue
        match = re.match(r"^\s*Value\s*:\s*(.*?)\s*$", line, re.I)
        if current and match:
            props[current] = match.group(1).strip()
            current = ""
    return props


def _specific_root_token_values(roots) -> list[str]:
    values = []
    for root in roots or []:
        value = str(root or "").strip().strip('"').rstrip("\\/")
        if not value:
            continue
        base = ntpath.basename(value)
        if base:
            values.append(base)
    return values


def _under_root(path: str, root: str) -> bool:
    candidate = normalize_path(str(path or "")).rstrip("\\")
    anchor = normalize_path(str(root or "")).rstrip("\\")
    return bool(candidate and anchor and (candidate == anchor or candidate.startswith(anchor + "\\")))


def target_anchor_tokens(*, diff=None, runtime_targets=None, roots=None, installer_info=None, msi_properties=None) -> set[str]:
    diff = diff or {}
    runtime_targets = runtime_targets or []
    installer_info = installer_info or {}
    msi_properties = msi_properties or {}

    info = installer_info.get("installer_info", installer_info) if isinstance(installer_info, dict) else {}
    meta = info.get("version_info") or {}
    tokens = identity_tokens(
        meta.get("ProductName"), meta.get("OriginalFilename"), info.get("name"),
        msi_properties.get("ProductName"),
        *_specific_root_token_values(roots),
    )

    # Product/package/root identity is preferred. Runtime process/component
    # names are often generic (Server.exe, Logger.exe, helper.exe) and should
    # only become fallback anchors when stronger product identity is absent.
    if tokens:
        return tokens

    for target in runtime_targets:
        path = str(target.get("Path") or "")
        parent = ntpath.dirname(path)
        tokens.update(identity_tokens(
            target.get("ProcessName"), target.get("Component"), ntpath.basename(parent),
        ))

    for service in (diff.get("Services", {}) or {}).get("added", []) or []:
        if not isinstance(service, dict):
            continue
        executable = extract_executable(service.get("PathName")) or ""
        tokens.update(identity_tokens(
            service.get("Name"), service.get("DisplayName"), ntpath.basename(ntpath.dirname(executable)),
        ))

    return tokens


def select_target_installed_apps(*, diff=None, runtime_targets=None, roots=None, installer_info=None, msi_properties=None) -> list[dict]:
    """Return only InstalledApplications additions correlated to the target.

    ProductCode is authoritative when available. Otherwise the application must
    overlap target anchors derived from MSI/package identity, verified install
    roots, target services, or runtime targets. Unrelated temporal additions do
    not become target identity sources.
    """
    diff = diff or {}
    apps = [x for x in ((diff.get("InstalledApplications", {}) or {}).get("added", []) or []) if isinstance(x, dict)]
    if not apps:
        return []

    props = msi_properties or {}
    anchors = target_anchor_tokens(
        diff=diff, runtime_targets=runtime_targets, roots=roots,
        installer_info=installer_info, msi_properties=props,
    )
    product_code = str(props.get("ProductCode") or "").strip().lower()

    scored: list[tuple[int, dict]] = []
    for app in apps:
        score = 0
        uninstall_text = " ".join(str(app.get(k) or "") for k in ("UninstallString", "PSPath")).lower()
        if product_code and product_code in uninstall_text:
            score += 100

        install_location = str(app.get("InstallLocation") or "").strip()
        if install_location and any(_under_root(install_location, root) or _under_root(root, install_location) for root in (roots or [])):
            score += 50

        app_tokens = identity_tokens(app.get("DisplayName"), app.get("InstallLocation"))
        overlap = anchors & app_tokens
        score += len(overlap) * 10
        if score:
            scored.append((score, app))

    if not scored:
        return []
    max_score = max(score for score, _ in scored)
    # ProductCode/root matches outrank weaker token-only matches. For token-only
    # correlation retain all records tied for the strongest score; this supports
    # products that legitimately publish more than one uninstall entry.
    floor = 50 if max_score >= 50 else max_score
    return [app for score, app in scored if score >= floor]


def target_identity_tokens(*, diff=None, runtime_targets=None, roots=None, installer_info=None, msi_properties=None) -> tuple[set[str], list[dict]]:
    props = msi_properties or {}
    anchors = target_anchor_tokens(
        diff=diff, runtime_targets=runtime_targets, roots=roots,
        installer_info=installer_info, msi_properties=props,
    )
    apps = select_target_installed_apps(
        diff=diff, runtime_targets=runtime_targets, roots=roots,
        installer_info=installer_info, msi_properties=props,
    )
    tokens = set(anchors)
    for app in apps:
        # DisplayName and InstallLocation can scope product storage. Publisher is
        # deliberately excluded because vendor-wide names can pull sibling host
        # products into the target assessment.
        tokens.update(identity_tokens(app.get("DisplayName"), app.get("InstallLocation")))
    return tokens, apps


def path_has_target_identity(path: str, tokens: set[str]) -> bool:
    """Match exact path-segment identity, never arbitrary substrings.

    A camel-cased product directory such as AcmeWidget is treated as the exact
    segment tokens {acme, widget}; NotAcmeWidgetizer does not match because its
    segment also contains unrelated tokens.
    """
    target = set(tokens or ())
    if not target:
        return False
    for segment in re.split(r"[\\/]+", str(path or "")):
        segment_tokens = identity_tokens(segment)
        if segment_tokens and segment_tokens.issubset(target):
            return True
    return False
