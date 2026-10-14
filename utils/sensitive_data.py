from __future__ import annotations

import csv
import ntpath
import re
import time
from collections import Counter
from utils.procmon_scope import trusted_roots, in_target_scope
from pathlib import Path
from utils.privacy import sanitize_report_text


REDACTED = "<REDACTED>"

# Process Monitor records the complete environment for Process Start/Create
# events. Match credential-bearing variable/parameter names without treating
# generic identifiers such as ordinary "key" values as secrets.
_SECRET_VALUE = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n;,\s]+'''
_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>(?<![?&])\b(?P<name>[A-Z0-9_-]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)[A-Z0-9_-]*)[ \t]*[=:][ \t]*)"
    rf"(?P<value>{_SECRET_VALUE})"
)
_CLI_SECRET = re.compile(
    rf"(?i)(?P<prefix>--(?:password|passwd|token|client[_-]?secret|api[_-]?key|access[_-]?key)(?:=|\s+))(?P<value>{_SECRET_VALUE})"
)
_QUERY_VALUE = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^&#\s"']+'''
_QUERY_PARAMETER = re.compile(
    r"(?i)(?P<prefix>[?&](?P<name>secret|token|access_token|refresh_token|api[_-]?key)=)"
    rf"(?P<value>{_QUERY_VALUE})"
)
_BEARER = re.compile(r"(?i)(?P<prefix>\bAuthorization\s*[:=]\s*Bearer\s+)(?P<value>[^\s,;\"']+)")


def redact_sensitive_text(value) -> tuple[str, Counter]:
    """Return redacted text and counts keyed by the sensitive field name."""
    text = str(value or "")
    counts: Counter = Counter()

    def replace_assignment(match):
        name = match.group("name").upper()
        if match.group("value") == REDACTED:
            counts[name] += 1
            return match.group(0)
        counts[name] += 1
        return f"{match.group('prefix')}{REDACTED}"

    def replace_query(match):
        name = match.group("name").upper()
        if match.group("value") == REDACTED:
            counts[name] += 1
            return match.group(0)
        counts[name] += 1
        return f"{match.group('prefix')}{REDACTED}"

    def replace_bearer(match):
        counts["AUTHORIZATION_BEARER"] += 1
        return f"{match.group('prefix')}{REDACTED}"

    def replace_cli(match):
        counts["CLI_SECRET"] += 1
        return f"{match.group('prefix')}{REDACTED}"

    text = _ASSIGNMENT.sub(replace_assignment, text)
    text = _CLI_SECRET.sub(replace_cli, text)
    text = _QUERY_PARAMETER.sub(replace_query, text)
    text = _BEARER.sub(replace_bearer, text)
    return text, counts


# Procmon Process Create/Start Detail may contain the *entire* child-process
# environment. Do not try to enumerate every possible custom secret name:
# omit that section altogether, preserving prior command line/parent PID data.
_PROCESS_ENV = re.compile(r"(?i)\bEnvironment\s*:\s*")
_IDENTITY_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:USERNAME|HOMEPATH|HOMEDRIVE|USERDOMAIN|USERDNSDOMAIN|"
    r"LOGONSERVER|COMPUTERNAME)\s*[:=]\s*)(?P<value>\"[^\"\r\n]*\"|[^\s;,\r\n]+)"
)


def sanitize_procmon_field(value, *, is_detail=False, indicator_names=None) -> str:
    text = str(value or "")
    if is_detail:
        marker = _PROCESS_ENV.search(text)
        if marker and "[PROCESS ENVIRONMENT OMITTED]" not in text:
            text = text[:marker.start()].rstrip(" ,;\r\n") + " Environment: [PROCESS ENVIRONMENT OMITTED]"
            if indicator_names:
                # Names only, never the environment values. This also lets a
                # later re-import detect previously observed secret indicators.
                names = sorted(name for name in indicator_names if re.fullmatch(r"[A-Z0-9_-]{1,80}", name))
                if names:
                    text += " Indicators: " + " ".join(name + "=<REDACTED>" for name in names)
    text = _IDENTITY_ASSIGNMENT.sub(lambda m: m.group("prefix") + "[REDACTED]", text)
    return text


def _encoding_candidates(source: Path) -> tuple[str, ...]:
    """Choose likely CSV encodings without pre-reading the complete capture.

    Procmon exports are normally UTF-8/UTF-16 with a BOM. A small sample is
    enough to choose the common path; if strict decoding later fails, the
    sanitizer retries with the next candidate and replaces only a temporary
    destination.
    """
    try:
        with source.open("rb") as handle:
            sample = handle.read(1024 * 1024)
    except OSError:
        sample = b""
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return ("utf-16", "utf-8-sig", "cp1252")
    if sample.startswith(b"\xef\xbb\xbf"):
        return ("utf-8-sig", "cp1252", "utf-16")
    # UTF-16 without a BOM is uncommon, but a high NUL ratio is a useful hint.
    if sample and sample.count(b"\x00") > max(8, len(sample) // 8):
        return ("utf-16", "utf-8-sig", "cp1252")
    try:
        sample.decode("utf-8")
        return ("utf-8-sig", "cp1252", "utf-16")
    except UnicodeDecodeError:
        return ("cp1252", "utf-8-sig", "utf-16")


def sanitize_procmon_csv(
    source: Path,
    destination: Path,
    *,
    target_process_names=None,
    target_executable_paths=None,
    progress_fn=None,
    progress_interval: float = 15.0,
) -> dict:
    """Stream a Procmon CSV to a sanitized copy without retaining secret values.

    When ``target_process_names`` is supplied, unrelated host rows are discarded
    during the same sanitization pass. Direct Process Create events remain as
    evidence, but only children under VERIFIED executable directories extend
    the tracked set. Launching an external app (such as a CSV editor) does not
    authorize collection or promotion of that app's independently spawned shell
    commands. If executable identity is unavailable, remain conservative.
    """
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_destination = destination.with_name('.' + destination.name + '.tmp')

    requested = {
        str(name or '').strip().lower()
        for name in (target_process_names or [])
        if str(name or '').strip()
    }
    filter_active = bool(requested)
    roots = trusted_roots(target_executable_paths)
    last_error = None

    for encoding in _encoding_candidates(source):
        totals: Counter = Counter()
        source_rows = 0
        retained_rows = 0
        tracked = set(requested)
        started = time.monotonic()
        next_progress = started + max(1.0, float(progress_interval or 15.0))
        temp_destination.unlink(missing_ok=True)
        try:
            with source.open("r", encoding=encoding, errors="strict", newline="") as src:
                reader = csv.DictReader(src)
                headers = reader.fieldnames or []
                process_header = next(
                    (h for h in headers if str(h).strip().lower() in {"process name", "processname"}),
                    None,
                )
                operation_header = next(
                    (h for h in headers if str(h).strip().lower() == "operation"),
                    None,
                )
                path_header = next(
                    (h for h in headers if str(h).strip().lower() == "path"),
                    None,
                )
                with temp_destination.open("w", encoding="utf-8-sig", newline="") as dst:
                    writer = csv.DictWriter(dst, fieldnames=headers, extrasaction="ignore")
                    writer.writeheader()
                    for row in reader:
                        source_rows += 1
                        proc_name = str(row.get(process_header, "") if process_header else "").strip().lower()
                        keep = not filter_active or not process_header or proc_name in tracked
                        if keep:
                            # Retain the parent's direct launch event, but follow
                            # the child ONLY if its executable is inside a verified
                            # first-party directory. Do not follow external editors,
                            # browsers or their descendant shells by name.
                            operation = str(row.get(operation_header, "") if operation_header else "").strip().lower()
                            child_path = str(row.get(path_header, "") or "") if path_header else ""
                            if filter_active and operation == "process create" and in_target_scope(child_path, roots):
                                child_name = ntpath.basename(child_path).strip().lower()
                                if child_name:
                                    tracked.add(child_name)

                            clean = {}
                            for key in headers:
                                clean_value, counts = redact_sensitive_text(row.get(key, ""))
                                clean_value = sanitize_procmon_field(
                                    clean_value,
                                    is_detail=str(key).strip().lower() in {"detail", "details"},
                                    indicator_names=counts,
                                )
                                clean[key] = sanitize_report_text(clean_value)
                                totals.update(counts)
                            writer.writerow(clean)
                            retained_rows += 1

                        now = time.monotonic()
                        if callable(progress_fn) and now >= next_progress:
                            progress_fn({
                                "source_rows": source_rows,
                                "retained_rows": retained_rows,
                                "elapsed_seconds": max(0, int(now - started)),
                            })
                            next_progress = now + max(1.0, float(progress_interval or 15.0))
            temp_destination.replace(destination)
            return {
                "rows": retained_rows,
                "source_rows": source_rows,
                "source_encoding": encoding,
                "redaction_count": sum(totals.values()),
                "sensitive_names": dict(sorted(totals.items())),
                "destination": str(destination),
                "target_filter_active": filter_active,
                "target_process_names": sorted(requested),
                "tracked_process_names": sorted(tracked),
            }
        except UnicodeDecodeError as exc:
            last_error = exc
            temp_destination.unlink(missing_ok=True)
            continue
        except Exception:
            temp_destination.unlink(missing_ok=True)
            raise

    raise RuntimeError(f"Could not decode Procmon CSV for sanitization: {last_error}")

