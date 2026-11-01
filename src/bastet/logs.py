"""Log triage — the part of the shift nobody escapes.

One pass over auth.log or an nginx access log: parse it, count it, and surface the
four things that actually mean something at 03:00 — a brute force, a login that
worked after a brute force, user enumeration, and a scanner walking the usual paths.

No network, no SIEM, no query language. Point it at a file.
"""

from __future__ import annotations

import datetime as dt
import gzip
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

class LogError(Exception):
    """The file cannot be read as a log (missing, binary, unreadable)."""


# ---------------------------------------------------------------- patterns

SYSLOG_TS = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
CLF_TS = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?)\]")

SSH_FAIL = re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\w.:]+)")
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\w.:]+)")
SSH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\w.:]+)")
PAM_FAIL = re.compile(r"authentication failure;.*?user=(?P<user>\S+).*?(?:rhost=(?P<ip>[\w.:]+))?")
HTTP_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ (?P<ts>\[[^\]]+\]) "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

#: Paths that mean someone is looking for a way in, not a page.
SCAN_PATHS = {
    "/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/pma/",
    "/admin", "/admin.php", "/administrator/", "/cgi-bin/", "/actuator/env",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/xmlrpc.php",
    "/solr/admin/", "/console/", "/manager/html", "/.aws/credentials",
    "/config.json", "/backup.zip", "/db.sql", "/.ds_store", "/server-status",
    "/shell.php", "/cmd.php", "/owa/auth/logon.aspx",
}

#: Tools that announce themselves, or that no health check uses.
SUSPICIOUS_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|ffuf|wfuzz|nuclei|wpscan|"
    r"hydra|metasploit|python-requests|go-http-client|okhttp|curl/|wget/)",
    re.IGNORECASE,
)

THRESHOLDS = {
    "brute_force_failures": 5,
    "enumeration_users": 3,
    "not_found_flood": 20,
}


# ---------------------------------------------------------------- model

@dataclass
class LogEvent:
    line_no: int
    ts: dt.datetime | None
    ip: str = ""
    user: str = ""
    kind: str = "other"
    method: str = ""
    path: str = ""
    status: int | None = None
    ua: str = ""
    raw: str = ""


@dataclass
class Finding:
    kind: str
    severity: str
    title: str
    subject: str
    count: int
    detail: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "severity": self.severity, "title": self.title,
            "subject": self.subject, "count": self.count, "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class LogAnalysis:
    path: str
    fmt: str
    lines: int = 0
    parsed: int = 0
    first_ts: dt.datetime | None = None
    last_ts: dt.datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    status_counts: dict[int, int] = field(default_factory=dict)
    hourly: list[int] = field(default_factory=lambda: [0] * 24)
    failed_by_ip: dict[str, int] = field(default_factory=dict)
    ok_by_ip: dict[str, int] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def worst(self) -> str:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if not self.findings:
            return "info"
        return sorted(self.findings, key=lambda f: order.get(f.severity, 9))[0].severity

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.fmt,
            "lines": self.lines,
            "parsed": self.parsed,
            "first": self.first_ts.isoformat(sep=" ") if self.first_ts else None,
            "last": self.last_ts.isoformat(sep=" ") if self.last_ts else None,
            "worst": self.worst,
            "findings": [f.to_dict() for f in self.findings],
            "top_ips": self.top_ips,
            "top_users": self.top_users,
            "top_paths": self.top_paths,
            "status_counts": {str(k): v for k, v in self.status_counts.items()},
            "hourly": self.hourly,
            "elapsed_ms": self.elapsed_ms,
        }


# ---------------------------------------------------------------- parsing

def detect_format(lines: list[str]) -> str:
    for line in lines[:200]:
        if "'" in line or "Failed password" in line or "sshd[" in line or "Invalid user" in line:
            if "sshd" in line or "Failed password" in line or "Invalid user" in line or "session opened" in line:
                return "auth"
        if HTTP_LINE.match(line):
            return "http"
    return "unknown"


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_ts(line: str) -> dt.datetime | None:
    """Slice the fixed-width syslog stamp instead of calling strptime.

    strptime was ~40% of the runtime on a 500k-line file, and the format is fixed:
    "Nov  1 02:00:11" is 15 characters at the start of the line.
    """
    if len(line) < 15:
        return None
    month = MONTHS.get(line[0:3])
    if month is None or line[3] != " " or line[6] != " " or line[9] != ":" or line[12] != ":":
        return None
    try:
        day = int(line[4:6])
        hour = int(line[7:9])
        minute = int(line[10:12])
        second = int(line[13:15])
    except ValueError:
        return None
    if not (1 <= day <= 31 and hour < 24 and minute < 60 and second < 61):
        return None
    try:
        return dt.datetime(dt.datetime.now().year, month, day, hour, minute, second)
    except ValueError:
        return None


_LOCAL_OFFSET = dt.datetime.now().astimezone().utcoffset() or dt.timedelta(0)


def _parse_offset(text: str) -> dt.timedelta | None:
    """+0100 → timedelta(hours=1). Returns None when the field is absent."""
    if len(text) < 5:
        return None
    sign = {"+": 1, "-": -1}.get(text[0])
    if sign is None:
        return None
    try:
        hours = int(text[1:3])
        minutes = int(text[3:5])
    except ValueError:
        return None
    return sign * dt.timedelta(hours=hours, minutes=minutes)


def _parse_clf_ts(text: str) -> dt.datetime | None:
    """Parse "01/Nov/2026:14:30:11 +0100" by slicing, then correct to local time.

    strptime with %z was the single biggest cost on an access log. The offset is
    still respected: the stamp is shifted by (log offset - local offset), so a log
    written in UTC reads correctly on a machine at UTC+1.
    """
    text = text.strip().strip("[]")
    if len(text) < 20:
        return None
    try:
        day = int(text[0:2])
        year = int(text[7:11])
        hour = int(text[12:14])
        minute = int(text[15:17])
        second = int(text[18:20])
    except ValueError:
        return None
    month = MONTHS.get(text[3:6])
    if month is None:
        return None
    try:
        parsed = dt.datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None
    offset = _parse_offset(text[21:26]) if len(text) > 21 else None
    if offset is not None and offset != _LOCAL_OFFSET:
        parsed -= offset - _LOCAL_OFFSET
    return parsed


def parse_line(line: str, line_no: int) -> LogEvent | None:
    """Parse one line.

    Cheap string tests come before any regex: an access log line is recognised by its
    quotes, an auth line by one of four substrings. On 500k lines that ordering is the
    difference between one second and five.
    """
    stripped = line.rstrip("\n")
    if not stripped or stripped[0] == "#":
        return None

    if '"' in stripped:
        http = HTTP_LINE.match(stripped)
        if http:
            return LogEvent(
                line_no=line_no,
                ts=_parse_clf_ts(http.group("ts")),
                ip=http.group("ip"),
                kind="http",
                method=http.group("method"),
                path=http.group("path"),
                status=int(http.group("status")),
                ua=_ua_of(stripped),
                raw=stripped,
            )

    if (
        "Failed" in stripped
        or "Invalid user" in stripped
        or "Accepted" in stripped
        or "authentication failure" in stripped
    ):
        ts = _parse_syslog_ts(stripped)
        for pattern, kind in ((SSH_OK, "ssh-ok"), (SSH_FAIL, "ssh-fail"),
                              (SSH_INVALID, "ssh-invalid")):
            match = pattern.search(stripped)
            if match:
                return LogEvent(
                    line_no=line_no, ts=ts, ip=match.group("ip"),
                    user=match.group("user"), kind=kind, raw=stripped,
                )
        pam = PAM_FAIL.search(stripped)
        if pam:
            return LogEvent(
                line_no=line_no, ts=ts, ip=pam.group("ip") or "",
                user=pam.group("user"), kind="pam-fail", raw=stripped,
            )
        return LogEvent(line_no=line_no, ts=ts, kind="other", raw=stripped)

    return LogEvent(line_no=line_no, ts=_parse_syslog_ts(stripped), kind="other", raw=stripped)


def _ua_of(line: str) -> str:
    parts = line.split('"')
    return parts[-2] if len(parts) >= 2 else ""


# ---------------------------------------------------------------- analysis

def iter_lines(path: str | Path, max_lines: int | None = None) -> Iterator[str]:
    """Stream a log, including .gz, without holding the file in memory.

    auth.log on a busy host is 100 MB and rotated into .gz — reading it into a list
    first is how a triage tool becomes the thing that took the box down.
    """
    if str(path) == "-":
        for index, line in enumerate(sys.stdin):
            if max_lines and index >= max_lines:
                return
            yield line
        return

    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise LogError(f"no such file: {file_path}")
    if file_path.is_dir():
        raise LogError(f"{file_path} is a directory")

    opener = gzip.open if file_path.suffix == ".gz" else open
    try:
        with opener(file_path, "rt", errors="replace") as handle:
            head = handle.read(4096)
            if "\x00" in head:
                raise LogError(f"{file_path.name} looks binary — not a text log")
            handle.seek(0)
            for index, line in enumerate(handle):
                if max_lines and index >= max_lines:
                    return
                yield line
    except PermissionError:
        raise LogError(f"cannot read {file_path} — permission denied") from None
    except OSError as exc:
        raise LogError(f"cannot read {file_path}: {exc}") from None


def _matches(event: LogEvent, ip: str, since: dt.time | None, until: dt.time | None) -> bool:
    if ip and ip not in event.ip:
        return False
    if since or until:
        if event.ts is None:
            return False
        moment = event.ts.time()
        if since and moment < since:
            return False
        if until and moment > until:
            return False
    return True


def parse_clock(value: str, default: dt.time) -> dt.time:
    """Accept 14, 14:30, 1430, or 14:30:05."""
    text = value.strip()
    if not text:
        return default
    for fmt in ("%H:%M:%S", "%H:%M", "%H%M"):
        try:
            return dt.datetime.strptime(text, fmt).time()
        except ValueError:
            continue
    raise ValueError(f"not a time: {value!r} (try 14:30)")


def analyse(
    path: str | Path,
    max_lines: int | None = None,
    ip_filter: str = "",
    since: dt.time | None = None,
    until: dt.time | None = None,
) -> LogAnalysis:
    """Parse and triage in a single streaming pass.

    Nothing per-line is retained except counters and up to three evidence lines per
    finding. A 500k-line file costs a few MB instead of a few hundred: holding every
    event as an object made the triage tool the reason the box ran out of memory.
    """
    started = time.perf_counter()
    stats = _Stats()
    analysis = LogAnalysis(path=str(path), fmt="unknown")
    lines = 0
    sample: list[str] = []

    for index, line in enumerate(iter_lines(path, max_lines), start=1):
        lines += 1
        if len(sample) < 200 and line.strip():
            sample.append(line)
        event = parse_line(line, index)
        if event is None:
            continue
        if event.kind == "other" and not event.ip:
            continue
        if not _matches(event, ip_filter, since, until):
            continue
        stats.feed(event)
        if event.ts:
            analysis.first_ts = min(analysis.first_ts or event.ts, event.ts)
            analysis.last_ts = max(analysis.last_ts or event.ts, event.ts)
            analysis.hourly[event.ts.hour] += 1

    analysis.fmt = detect_format(sample)
    analysis.lines = lines
    analysis.parsed = stats.parsed
    analysis.top_ips = stats.ips.most_common(10)
    analysis.top_users = stats.users.most_common(10)
    analysis.top_paths = stats.paths.most_common(10)
    analysis.status_counts = dict(stats.status.most_common())
    analysis.failed_by_ip = dict(stats.failed)
    analysis.ok_by_ip = dict(stats.ok)
    analysis.findings = _detect(stats)
    analysis.elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    return analysis


class _Stats:
    """Counters only. This is what keeps the pass flat in memory."""

    MAX_USERS_PER_IP = 100
    MAX_PATHS_PER_IP = 12
    MAX_EVIDENCE = 3

    def __init__(self) -> None:
        self.parsed = 0
        self.ips: Counter[str] = Counter()
        self.users: Counter[str] = Counter()
        self.paths: Counter[str] = Counter()
        self.status: Counter[int] = Counter()
        self.failed: Counter[str] = Counter()
        self.ok: Counter[str] = Counter()
        self.users_by_ip: dict[str, set[str]] = defaultdict(set)
        self.scan_hits: Counter[str] = Counter()
        self.scan_paths: dict[str, set[str]] = defaultdict(set)
        self.not_found: Counter[str] = Counter()
        self.ua_hits: Counter[str] = Counter()
        self.ua_sample: dict[str, str] = {}
        self.evidence: dict[tuple[str, str], list[str]] = defaultdict(list)

    def _keep(self, ip: str, key: str, raw: str) -> None:
        bucket = self.evidence[(ip, key)]
        if len(bucket) < self.MAX_EVIDENCE:
            bucket.append(raw)

    def feed(self, event: LogEvent) -> None:
        ip = event.ip
        if ip:
            self.ips[ip] += 1
        if event.user and event.user not in ("invalid", "-"):
            self.users[event.user] += 1
        if event.path:
            self.paths[event.path] += 1
        if event.status:
            self.status[event.status] += 1

        if event.kind in ("ssh-fail", "ssh-invalid", "pam-fail"):
            self.parsed += 1
            self.failed[ip] += 1
            self._keep(ip, "fail", event.raw)
            if event.user and len(self.users_by_ip[ip]) < self.MAX_USERS_PER_IP:
                self.users_by_ip[ip].add(event.user)
        elif event.kind == "ssh-ok":
            self.parsed += 1
            self.ok[ip] += 1
            self._keep(ip, "ok", event.raw)
        elif event.kind == "http":
            self.parsed += 1
            path = event.path.split("?")[0].lower()
            if path in SCAN_PATHS:
                self.scan_hits[ip] += 1
                if len(self.scan_paths[ip]) < self.MAX_PATHS_PER_IP:
                    self.scan_paths[ip].add(path)
                self._keep(ip, "scan", event.raw)
            if event.status == 404:
                self.not_found[ip] += 1
                self._keep(ip, "404", event.raw)
            if event.ua and SUSPICIOUS_UA.search(event.ua):
                self.ua_hits[ip] += 1
                self.ua_sample.setdefault(ip, event.ua)
                self._keep(ip, "ua", event.raw)


def _detect(stats: _Stats) -> list[Finding]:
    findings: list[Finding] = []

    for ip in stats.ips:
        failures = stats.failed.get(ip, 0)
        successes = stats.ok.get(ip, 0)
        users = stats.users_by_ip.get(ip) or set()
        scans = stats.scan_hits.get(ip, 0)
        missing = stats.not_found.get(ip, 0)
        tools = stats.ua_hits.get(ip, 0)

        if failures >= THRESHOLDS["brute_force_failures"]:
            severity = "high" if failures >= 20 else "medium"
            findings.append(Finding(
                kind="brute-force", severity=severity,
                title="Repeated authentication failures", subject=ip, count=failures,
                detail=f"{failures} failed attempt(s) against {len(users) or 1} account(s)",
                evidence=stats.evidence.get((ip, "fail"), []),
            ))

        if successes and failures:
            findings.append(Finding(
                kind="success-after-failure", severity="critical",
                title="Successful login after failed attempts — check this first",
                subject=ip, count=successes,
                detail=f"{failures} failure(s) then {successes} success(es) from the same address",
                evidence=stats.evidence.get((ip, "fail"), [])[:2] + stats.evidence.get((ip, "ok"), [])[:2],
            ))

        if len(users) >= THRESHOLDS["enumeration_users"]:
            findings.append(Finding(
                kind="user-enumeration", severity="medium",
                title="Many distinct accounts tried from one address",
                subject=ip, count=len(users),
                detail=f"{len(users)} different usernames: " + ", ".join(sorted(users)[:6]),
                evidence=stats.evidence.get((ip, "fail"), []),
            ))

        if scans:
            findings.append(Finding(
                kind="scanner-paths", severity="high",
                title="Requests for paths that only scanners ask for",
                subject=ip, count=scans,
                detail=", ".join(sorted(stats.scan_paths[ip])[:6]),
                evidence=stats.evidence.get((ip, "scan"), []),
            ))

        if missing >= THRESHOLDS["not_found_flood"]:
            findings.append(Finding(
                kind="not-found-flood", severity="low",
                title="Burst of 404s — usually a directory bruteforce",
                subject=ip, count=missing,
                detail=f"{missing} responses were 404",
                evidence=stats.evidence.get((ip, "404"), []),
            ))

        if tools:
            findings.append(Finding(
                kind="suspicious-user-agent", severity="medium",
                title="Tool-like user agent", subject=ip, count=tools,
                detail=stats.ua_sample.get(ip, "")[:80],
                evidence=stats.evidence.get((ip, "ua"), []),
            ))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -f.count))
    return findings
