"""Log triage — the part of the shift nobody escapes.

One pass over auth.log or an nginx access log: parse it, count it, and surface the
four things that actually mean something at 03:00 — a brute force, a login that
worked after a brute force, user enumeration, and a scanner walking the usual paths.

No network, no SIEM, no query language. Point it at a file.
"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

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


def _parse_syslog_ts(line: str) -> dt.datetime | None:
    match = SYSLOG_TS.match(line)
    if not match:
        return None
    text = re.sub(r"\s+", " ", match.group(0))
    try:
        parsed = dt.datetime.strptime(f"{dt.datetime.now().year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return parsed


def _parse_clf_ts(match: re.Match | None) -> dt.datetime | None:
    if not match:
        return None
    text = match.group(1)
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_line(line: str, line_no: int) -> LogEvent | None:
    stripped = line.rstrip("\n")
    if not stripped or stripped.startswith("#"):
        return None

    http = HTTP_LINE.match(stripped)
    if http:
        return LogEvent(
            line_no=line_no,
            ts=_parse_clf_ts(CLF_TS.search(stripped)),
            ip=http.group("ip"),
            kind="http",
            method=http.group("method"),
            path=http.group("path"),
            status=int(http.group("status")),
            ua=_ua_of(stripped),
            raw=stripped,
        )

    ts = _parse_syslog_ts(stripped)
    for pattern, kind in ((SSH_OK, "ssh-ok"), (SSH_FAIL, "ssh-fail"), (SSH_INVALID, "ssh-invalid")):
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


def _ua_of(line: str) -> str:
    parts = line.split('"')
    return parts[-2] if len(parts) >= 2 else ""


# ---------------------------------------------------------------- analysis

def analyse(path: str | Path, max_lines: int = 500_000) -> LogAnalysis:
    file_path = Path(path).expanduser()
    text = file_path.read_text(errors="replace")
    lines = text.splitlines()[:max_lines]

    analysis = LogAnalysis(path=str(file_path), fmt=detect_format(lines), lines=len(lines))
    events: list[LogEvent] = []
    for index, line in enumerate(lines, start=1):
        event = parse_line(line, index)
        if event is None:
            continue
        events.append(event)
        if event.ts:
            analysis.first_ts = min(analysis.first_ts or event.ts, event.ts)
            analysis.last_ts = max(analysis.last_ts or event.ts, event.ts)
            analysis.hourly[event.ts.hour] += 1

    analysis.parsed = len([e for e in events if e.kind != "other"])
    _aggregate(analysis, events)
    analysis.findings = _detect(analysis, events)
    return analysis


def _aggregate(analysis: LogAnalysis, events: list[LogEvent]) -> None:
    ips: Counter[str] = Counter()
    users: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    statuses: Counter[int] = Counter()
    failed: Counter[str] = Counter()
    ok: Counter[str] = Counter()

    for event in events:
        if event.ip:
            ips[event.ip] += 1
        if event.user and event.user not in ("invalid", "-"):
            users[event.user] += 1
        if event.path:
            paths[event.path] += 1
        if event.status:
            statuses[event.status] += 1
        if event.kind in ("ssh-fail", "ssh-invalid", "pam-fail"):
            failed[event.ip] += 1
        if event.kind == "ssh-ok":
            ok[event.ip] += 1

    analysis.top_ips = ips.most_common(10)
    analysis.top_users = users.most_common(10)
    analysis.top_paths = paths.most_common(10)
    analysis.status_counts = dict(statuses.most_common())
    analysis.failed_by_ip = dict(failed)
    analysis.ok_by_ip = dict(ok)


def _detect(analysis: LogAnalysis, events: list[LogEvent]) -> list[Finding]:
    findings: list[Finding] = []
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.ip:
            by_ip[event.ip].append(event)

    for ip, items in by_ip.items():
        failures = [e for e in items if e.kind in ("ssh-fail", "ssh-invalid", "pam-fail")]
        successes = [e for e in items if e.kind == "ssh-ok"]
        users = {e.user for e in failures if e.user not in ("invalid", "", "-")}
        scanner_hits = [e for e in items if e.path.split("?")[0].lower() in SCAN_PATHS]
        not_found = [e for e in items if e.status == 404]
        bad_ua = [e for e in items if e.ua and SUSPICIOUS_UA.search(e.ua)]

        if len(failures) >= THRESHOLDS["brute_force_failures"]:
            severity = "high" if len(failures) >= 20 else "medium"
            findings.append(Finding(
                kind="brute-force", severity=severity,
                title="Repeated authentication failures",
                subject=ip, count=len(failures),
                detail=f"{len(failures)} failed attempt(s) against "
                       f"{len(users) or 1} account(s)",
                evidence=[f.raw for f in failures[:3]],
            ))

        if successes and failures:
            findings.append(Finding(
                kind="success-after-failure", severity="critical",
                title="Successful login after failed attempts — check this first",
                subject=ip, count=len(successes),
                detail=f"{len(failures)} failure(s) then {len(successes)} success(es) "
                       f"from the same address",
                evidence=[e.raw for e in (failures[:2] + successes[:2])],
            ))

        if len(users) >= THRESHOLDS["enumeration_users"]:
            findings.append(Finding(
                kind="user-enumeration", severity="medium",
                title="Many distinct accounts tried from one address",
                subject=ip, count=len(users),
                detail=f"{len(users)} different usernames: "
                       + ", ".join(sorted(users)[:6]),
                evidence=[e.raw for e in failures[:2]],
            ))

        if scanner_hits:
            findings.append(Finding(
                kind="scanner-paths", severity="high",
                title="Requests for paths that only scanners ask for",
                subject=ip, count=len(scanner_hits),
                detail=", ".join(sorted({e.path.split("?")[0] for e in scanner_hits})[:6]),
                evidence=[e.raw for e in scanner_hits[:3]],
            ))

        if len(not_found) >= THRESHOLDS["not_found_flood"]:
            findings.append(Finding(
                kind="not-found-flood", severity="low",
                title="Burst of 404s — usually a directory bruteforce",
                subject=ip, count=len(not_found),
                detail=f"{len(not_found)} responses were 404",
                evidence=[e.raw for e in not_found[:3]],
            ))

        if bad_ua:
            findings.append(Finding(
                kind="suspicious-user-agent", severity="medium",
                title="Tool-like user agent",
                subject=ip, count=len(bad_ua),
                detail=bad_ua[0].ua[:80],
                evidence=[e.raw for e in bad_ua[:3]],
            ))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -f.count))
    return findings
