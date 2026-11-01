"""Bastet command line.

    bastet                     the shift: what is open, what is cached, what time it is
    bastet ioc <indicator>     what is this thing, is it dangerous, where to look
    bastet logs <file>         brute force, enumeration, scanners, 404 floods
    bastet cve <id>            NVD lookup, cached for offline
    bastet attack <id|word>    ATT&CK technique and how to detect it
    bastet port <n|word>       what that open port actually means
    bastet ip <cidr>           subnet maths
    bastet decode/encode       peel or apply base64, hex, url, html, rot13
    bastet hash                digests, and identify an unknown hash
    bastet case ...            incident notes with a timeline
    bastet triage <playbook>   the checklist for this kind of alert
    bastet cat                 the cat

Exit codes: 0 ok · 1 error · 2 not found / bad usage · 3 network unavailable
            · 4 findings at or above --fail-on (for cron and CI)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import sys
from pathlib import Path

from . import __version__
from . import attack as attackmod
from . import cases
from . import cat as catmod
from . import codec
from . import cve as cvemod
from . import ioc as iocmod
from . import logs as logsmod
from . import netcalc
from . import ports as portsmod
from . import triage
from . import ui
from .config import SEVERITIES, SEVERITY_ORDER, data_dir

ACCENT = "#c9f24d"

#: Short labels for the table. The full kind goes to --json; a screen has room
#: for sixteen characters, not "success-after-failure".
KIND_LABEL = {
    "success-after-failure": "success→ok",
    "brute-force": "brute-force",
    "user-enumeration": "enumeration",
    "scanner-paths": "scanner",
    "not-found-flood": "404 flood",
    "suspicious-user-agent": "tool UA",
}


# ---------------------------------------------------------------- helpers

def grid(columns, rows, title: str = "") -> None:
    """Render a table, or tab-separated lines when rich is missing."""
    table = ui.table(columns)
    if table is None:
        for row in rows:
            print("  ".join(str(cell) for cell in row))
        return
    for row in rows:
        table.add_row(*row)
    ui.console.print(table)
    ui.console.print()


def _short(text: str, limit: int = 70) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------- dashboard

def cmd_dashboard(args: argparse.Namespace) -> int:
    ui.big_cat()
    now = dt.datetime.now()
    utc = dt.datetime.now(dt.timezone.utc)

    try:
        open_cases = cases.open_count()
        case_line = f"{open_cases} open" if open_cases else "none open"
    except Exception:  # noqa: BLE001 - a broken db must not hide the dashboard
        case_line = "unavailable"

    ui.kv(
        [
            ("local", now.strftime("%Y-%m-%d %H:%M:%S")),
            ("utc", utc.strftime("%Y-%m-%d %H:%M:%S")),
            ("cases", case_line),
            ("cve cache", f"{cvemod.cache_count()} record(s)"),
            ("data", str(data_dir())),
        ],
        title="shift",
    )

    ui.console.print()
    ui.rule("start here")
    for line in (
        "bastet ioc 45.155.205.233 evil-login.top    what is this, and how bad",
        "bastet logs /var/log/auth.log              who is trying to get in",
        "bastet cve CVE-2021-44228                  what it is, what to do",
        "bastet case new --title \"...\"              start the write-up now, not later",
        "bastet triage phishing --case IR-2026-0001 attach the checklist",
    ):
        ui.console.print(f"  [dim]{line}[/]" if ui.RICH else f"  {line}")
    ui.console.print()
    return 0


def cmd_cat(args: argparse.Namespace) -> int:
    ui.big_cat(mood="sleepy" if getattr(args, "sleepy", False) else "awake")
    return 0


# ---------------------------------------------------------------- ioc

def cmd_ioc(args: argparse.Namespace) -> int:
    indicators = iocmod.triage(args.values)

    if args.json:
        ui.emit_json([i.to_dict() for i in indicators])
        return 0

    ui.header("indicator triage", f"{len(indicators)} value(s)")

    rows = []
    for indicator in indicators:
        note = indicator.notes[0] if indicator.notes else "no heuristic fired"
        rows.append([indicator.kind.upper(), ui.severity(indicator.risk),
                     indicator.raw, _short(note, 60)])
    grid([("TYPE", 10), ("RISK", 11), ("INDICATOR", 34), ("FIRST READ", None)], rows)

    for indicator in indicators:
        ui.console.print(f"  [bold]{indicator.value}[/]" if ui.RICH else f"  {indicator.value}")
        ui.console.print(f"    defanged  {iocmod.defang(indicator.value)}")
        for note in indicator.notes:
            ui.console.print(f"    · {note}")
        for name, link in indicator.links.items():
            ui.console.print(f"    {name:<12} {link}")
        ui.console.print()

    worst = iocmod.worst_risk(indicators)
    if SEVERITY_ORDER.get(worst, 0) <= SEVERITY_ORDER["medium"]:
        ui.warn(f"worst reading across these values: {worst.upper()}")
    return 0


# ---------------------------------------------------------------- codec

def cmd_decode(args: argparse.Namespace) -> int:
    chain = codec.decode_chain(args.text, include_rot13=args.rot13)

    if args.json:
        ui.emit_json([step.to_dict() for step in chain])
        return 0

    ui.header("decode", f"{len(chain) - 1} layer(s) peeled")
    for index, step in enumerate(chain):
        label = "input" if index == 0 else step.kind
        style = "dim" if index == 0 else ACCENT
        if ui.RICH:
            ui.console.print(f"  [{style}]{index}[/] [bold]{label}[/]")
        else:
            ui.console.print(f"  {index} {label}")
        ui.console.print(f"      {step.value}")
        ui.console.print()

    if len(chain) == 1:
        ui.warn("nothing decoded — it may be plain text, or a format I do not peel")
    else:
        ui.console.print(f"  [dim]final:[/] [bold]{chain[-1].value}[/]" if ui.RICH
                         else f"  final: {chain[-1].value}")
        ui.console.print()
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    try:
        value = codec.encode(args.text, args.as_encoding)
    except ValueError as exc:
        ui.fail(str(exc))
        return 2
    if args.json:
        ui.emit_json({"encoding": args.as_encoding, "input": args.text, "output": value})
    else:
        ui.console.print(value)
    return 0


# ---------------------------------------------------------------- hash

def _digests(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def cmd_hash(args: argparse.Namespace) -> int:
    if args.identify:
        indicator = iocmod.classify(args.identify)
        if args.json:
            ui.emit_json(indicator.to_dict())
            return 0
        ui.header("hash identification", indicator.kind)
        ui.kv([
            ("value", indicator.raw),
            ("type", indicator.kind),
            ("known", indicator.notes[0] if indicator.notes else "not in the small table"),
        ])
        return 0

    if args.file:
        path = Path(args.file).expanduser()
        if not path.exists():
            ui.fail(f"no such file: {path}")
            return 2
        data = path.read_bytes()
        source = f"{path} ({len(data)} bytes)"
    else:
        if not args.text:
            ui.fail("give me text, --file, or --identify")
            return 2
        data = args.text.encode()
        source = f"{len(data)} byte(s) of text"

    digests = _digests(data)
    if args.json:
        ui.emit_json({"source": source, **digests})
        return 0

    ui.header("digests", source)
    ui.kv([(name, value) for name, value in digests.items()])
    return 0


# ---------------------------------------------------------------- logs

def cmd_logs(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    if not path.exists():
        ui.fail(f"no such file: {path}")
        return 2

    analysis = logsmod.analyse(path)

    if args.json:
        ui.emit_json(analysis.to_dict())
    else:
        span = ""
        if analysis.first_ts and analysis.last_ts:
            span = f" · {analysis.first_ts:%Y-%m-%d %H:%M} → {analysis.last_ts:%H:%M}"
        ui.header("log triage", f"{path.name} · {analysis.fmt}{span}")
        ui.console.print(
            f"  {analysis.lines} line(s), {analysis.parsed} parsed, "
            f"{len(analysis.findings)} finding(s)\n"
        )

        if analysis.findings:
            rows = [
                [ui.severity(f.severity), KIND_LABEL.get(f.kind, f.kind), f.subject,
                 str(f.count), _short(f.detail, 46)]
                for f in analysis.findings[: args.top]
            ]
            grid([("SEV", 9), ("KIND", 16), ("SUBJECT", 15), ("N", 4), ("WHAT", None)], rows)

            ui.rule("evidence")
            for finding in analysis.findings[:3]:
                ui.console.print(f"  [bold]{finding.title}[/]" if ui.RICH else f"  {finding.title}")
                for line in finding.evidence[:2]:
                    ui.console.print(f"    [dim]{_short(line, 88)}[/]" if ui.RICH
                                     else f"    {_short(line, 88)}")
                ui.console.print()
        else:
            ui.console.print("  [dim]nothing that looks like an attack in this file[/]"
                             if ui.RICH else "  nothing that looks like an attack in this file")
            ui.console.print()

        if analysis.hourly and any(analysis.hourly):
            ui.console.print(f"  events/hour  {ui.sparkline(analysis.hourly)}")
            ui.console.print()

        if analysis.top_ips:
            rows = [[ip, str(count), ui.bar(count, analysis.top_ips[0][1], 18)]
                    for ip, count in analysis.top_ips[:8]]
            ui.console.print("  top sources" if not ui.RICH else "  [dim]top sources[/]")
            grid([("IP", 20), ("EVENTS", 7), ("", None)], rows)

        if analysis.top_users:
            ui.console.print("  top accounts" if not ui.RICH else "  [dim]top accounts[/]")
            grid([("USER", 22), ("EVENTS", 7)], [[u, str(c)] for u, c in analysis.top_users[:8]])

        if analysis.top_paths:
            ui.console.print("  top paths" if not ui.RICH else "  [dim]top paths[/]")
            grid([("PATH", 46), ("HITS", 6)], [[p, str(c)] for p, c in analysis.top_paths[:8]])

        if analysis.status_counts:
            counts = "  ".join(f"{code}×{n}" for code, n in list(analysis.status_counts.items())[:6])
            ui.console.print(f"  [dim]status[/] {counts}" if ui.RICH else f"  status {counts}")
            ui.console.print()

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in analysis.findings):
            return 4
    return 0


# ---------------------------------------------------------------- cve

def cmd_cve(args: argparse.Namespace) -> int:
    try:
        record = cvemod.get(args.id, refresh=args.refresh)
    except ValueError as exc:
        ui.fail(str(exc))
        return 2
    except cvemod.LookupError_ as exc:
        ui.fail(f"{exc} — and nothing cached for that id")
        return 3

    if args.json:
        ui.emit_json(record.to_dict())
        return 0

    ui.header(record.id, f"source: {record.source}")
    severity = record.severity if record.severity in SEVERITIES else "info"
    ui.kv([
        ("severity", ui.severity(severity)),
        ("cvss", f"{record.cvss:.1f}" if record.cvss is not None else "not scored"),
        ("published", record.published or "unknown"),
        ("cwe", ", ".join(record.cwes) or "not assigned"),
        ("vector", _short(record.vector, 60) or "—"),
    ])

    if record.description:
        ui.console.print()
        for line in _wrap(record.description, 96):
            ui.console.print(f"  {line}")
        ui.console.print()

    if record.refs:
        ui.rule("references")
        for ref in record.refs:
            ui.console.print(f"  {ref}")
        ui.console.print()
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


# ---------------------------------------------------------------- attack

def cmd_attack(args: argparse.Namespace) -> int:
    if not args.query and not args.tactic:
        grouped = attackmod.by_tactic()
        ui.header("mitre att&ck", f"{sum(len(v) for v in grouped.values())} techniques")
        for tactic, techniques in grouped.items():
            ui.console.print(f"  [bold]{tactic}[/]" if ui.RICH else f"  {tactic}")
            for technique in techniques:
                ui.console.print(f"    {technique['id']:<11} {technique['name']}")
            ui.console.print()
        return 0

    if args.query:
        exact = attackmod.by_id(args.query)
        if exact and not args.tactic:
            if args.json:
                ui.emit_json(exact)
                return 0
            ui.header(exact["id"], exact["name"])
            ui.kv([("tactic", exact["tactic"]), ("platforms", "windows · linux · cloud")])
            ui.console.print()
            for line in _wrap(exact["description"], 96):
                ui.console.print(f"  {line}")
            ui.console.print()
            ui.rule("detection")
            for line in _wrap(exact["detection"], 96):
                ui.console.print(f"  {line}")
            ui.console.print()
            return 0

    results = attackmod.search(args.query or "", args.tactic or "")
    if not results:
        ui.fail("nothing matched — try `bastet attack` to browse by tactic")
        return 2
    if args.json:
        ui.emit_json(results)
        return 0

    ui.header("att&ck search", f"{len(results)} match(es)")
    grid([("ID", 13), ("TACTIC", 23), ("NAME", 34), ("DETECT", None)],
         [[t["id"], t["tactic"], t["name"], _short(t["detection"], 46)] for t in results])
    return 0


# ---------------------------------------------------------------- ports / net

def cmd_port(args: argparse.Namespace) -> int:
    if args.risk:
        entries = portsmod.dangerous(args.risk)
        title = f"ports at {args.risk} or worse"
    else:
        entries = portsmod.search(args.query or "")
        title = f"port reference — {args.query}"

    if not entries:
        ui.fail(f"nothing for {args.query!r}")
        return 2
    if args.json:
        ui.emit_json(entries)
        return 0

    ui.header("ports", title)
    grid([("PORT", 7), ("SERVICE", 20), ("RISK", 10), ("WHY IT MATTERS", None)],
         [[str(e["port"]), e["service"], ui.severity(e["risk"]), e["note"]] for e in entries])
    return 0


def cmd_ip(args: argparse.Namespace) -> int:
    try:
        info = netcalc.subnet(args.cidr)
    except ValueError as exc:
        ui.fail(f"not a subnet: {exc}")
        return 2

    if args.contains:
        inside = netcalc.contains(args.cidr, args.contains)
        if args.json:
            ui.emit_json({"cidr": info.cidr, "contains": args.contains, "result": inside})
        else:
            ui.console.print(f"  {args.contains} {'is' if inside else 'is not'} in {info.cidr}")
            ui.console.print()
        return 0 if inside else 4

    if args.json:
        ui.emit_json(info.to_dict())
        return 0

    ui.header("subnet", info.cidr)
    rows = [
        ("network", info.network),
        ("netmask", info.netmask),
        ("wildcard", info.wildcard),
        ("broadcast", info.broadcast or "—"),
        ("hosts", f"{info.first_host} – {info.last_host}" if info.first_host else "—"),
        ("usable", f"{info.usable_hosts:,}"),
        ("total", f"{info.total_addresses:,}"),
        ("scope", "private" if info.is_private else "public"),
    ]
    ui.kv(rows)
    return 0


# ---------------------------------------------------------------- cases

def cmd_case(args: argparse.Namespace) -> int:
    action = args.action

    if action == "new":
        if not args.title:
            ui.fail("--title is required")
            return 2
        if args.severity not in SEVERITIES:
            ui.fail(f"severity must be one of {', '.join(SEVERITIES)}")
            return 2
        case = cases.new_case(args.title, args.severity, args.summary or "", args.ttps or "")
        if args.json:
            ui.emit_json(case.to_dict())
        else:
            ui.header("case opened", case.id)
            ui.kv([("title", case.title), ("severity", case.severity), ("status", case.status)])
            ui.console.print(f"  [dim]add the first fact:[/] bastet case add {case.id} \"what you saw\""
                             if ui.RICH else f"  bastet case add {case.id} \"what you saw\"")
            ui.console.print()
        return 0

    if action == "list":
        rows = cases.list_cases(args.status or "")
        if args.json:
            ui.emit_json(rows)
            return 0
        ui.header("cases", f"{len(rows)} shown")
        if not rows:
            ui.console.print("  [dim]no cases yet — `bastet case new --title \"...\"`[/]"
                             if ui.RICH else "  no cases yet")
            ui.console.print()
            return 0
        grid([("ID", 14), ("SEV", 10), ("STATUS", 15), ("TITLE", None)],
             [[r["id"], ui.severity(r["severity"]), r["status"], _short(r["title"], 56)]
              for r in rows])
        return 0

    if action == "show":
        case = cases.get_case(args.case_id)
        if case is None:
            ui.fail(f"no case {args.case_id}")
            return 2
        if args.json:
            ui.emit_json(case.to_dict())
            return 0
        ui.header(case.id, case.title)
        ui.kv([("severity", ui.severity(case.severity)), ("status", case.status),
               ("opened", case.created), ("ttps", case.ttps or "—")])
        if case.summary:
            ui.console.print()
            for line in _wrap(case.summary, 96):
                ui.console.print(f"  {line}")
        ui.console.print()
        if case.events:
            ui.rule("timeline")
            for event in case.events:
                ui.console.print(f"  [dim]{event['ts']}[/] [bold]{event['kind']:<8}[/] {event['text']}"
                                 if ui.RICH else f"  {event['ts']} {event['kind']} {event['text']}")
            ui.console.print()
        else:
            ui.console.print("  [dim]no events yet[/]" if ui.RICH else "  no events yet")
            ui.console.print()
        return 0

    if action == "add":
        if not args.text:
            ui.fail("give the event text")
            return 2
        try:
            cases.add_event(args.case_id, args.text, args.kind, args.source or "analyst")
        except KeyError:
            ui.fail(f"no case {args.case_id}")
            return 2
        if not args.json:
            ui.console.print(f"  added to {args.case_id}")
            ui.console.print()
        return 0

    if action == "status":
        if args.status_value not in ("open", "investigating", "contained", "closed"):
            ui.fail("status must be open, investigating, contained or closed")
            return 2
        cases.set_status(args.case_id, args.status_value, args.resolution or "")
        if not args.json:
            ui.console.print(f"  {args.case_id} → {args.status_value}")
            ui.console.print()
        return 0

    if action == "export":
        try:
            markdown = cases.export_markdown(args.case_id)
        except KeyError:
            ui.fail(f"no case {args.case_id}")
            return 2
        if args.out:
            path = Path(args.out).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            ui.console.print(f"  wrote {path}")
            ui.console.print()
        else:
            ui.console.print(markdown)
        return 0

    if action == "playbook":
        if not args.playbook:
            ui.fail("name a playbook — `bastet triage --list`")
            return 2
        try:
            markdown = triage.render_markdown(args.playbook, args.case_id)
        except KeyError:
            ui.fail(f"no playbook {args.playbook!r}")
            return 2
        cases.add_event(args.case_id, f"Playbook attached: {args.playbook}", "note", "bastet")
        if args.out:
            Path(args.out).expanduser().write_text(markdown, encoding="utf-8")
            ui.console.print(f"  wrote {args.out}")
        else:
            ui.console.print(markdown)
        return 0

    ui.fail("unknown case action")
    return 2


# ---------------------------------------------------------------- triage

def cmd_triage(args: argparse.Namespace) -> int:
    if args.list or not args.playbook:
        ui.header("playbooks", "what to do, in order")
        grid([("NAME", 13), ("COVERS", 24), ("GOAL", None)],
             [[name, triage.get(name)["title"], _short(triage.get(name)["goal"], 52)]
              for name in triage.names()])
        return 0

    try:
        markdown = triage.render_markdown(args.playbook, args.case_id or "")
    except KeyError:
        ui.fail(f"no playbook {args.playbook!r} — try `bastet triage --list`")
        return 2

    if args.case_id:
        try:
            cases.add_event(args.case_id, f"Playbook attached: {args.playbook}", "note", "bastet")
        except KeyError:
            ui.fail(f"no case {args.case_id}")
            return 2

    if args.out:
        path = Path(args.out).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
        ui.console.print(f"  wrote {path}")
        ui.console.print()
        return 0
    ui.console.print(markdown)
    return 0


# ---------------------------------------------------------------- doctor

def cmd_doctor(args: argparse.Namespace) -> int:
    ui.header("doctor", "is the toolbox healthy")
    info = [
        ("bastet", __version__),
        ("python", platform.python_version()),
        ("rich", "yes" if ui.RICH else "missing — output falls back to plain text"),
        ("data dir", str(data_dir())),
        ("cases", "ok" if _db_ok() else "unavailable"),
        ("cve cache", f"{cvemod.cache_count()} record(s)"),
        ("attack db", f"{len(attackmod.load())} techniques"),
        ("port db", f"{len(portsmod.load())} ports"),
    ]
    ui.kv(info)
    ui.console.print("  [dim]no API keys needed; NVD_API_KEY only raises the rate limit[/]"
                     if ui.RICH else "  no API keys needed")
    ui.console.print()
    return 0


def _db_ok() -> bool:
    try:
        cases.open_count()
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bastet",
        description="Night-shift toolbox: IOC triage, log analysis, CVE and ATT&CK lookup, case notes.",
        epilog="Start with `bastet` — it shows what is open and what to run next.",
    )
    parser.add_argument("--version", action="version", version=f"bastet {__version__}")
    sub = parser.add_subparsers(dest="command")

    c = sub.add_parser("cat", help="the cat")
    c.add_argument("--sleepy", action="store_true", help="it is the end of the shift")
    c.set_defaults(func=cmd_cat)

    i = sub.add_parser("ioc", help="triage one or more indicators")
    i.add_argument("values", nargs="+", help="IPs, domains, URLs, hashes, emails, CVE ids")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_ioc)

    d = sub.add_parser("decode", help="peel base64/hex/url/html layers")
    d.add_argument("text")
    d.add_argument("--rot13", action="store_true", help="also try rot13 (noisy on normal text)")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_decode)

    e = sub.add_parser("encode", help="apply an encoding")
    e.add_argument("text")
    e.add_argument("--as", dest="as_encoding", default="base64", choices=codec.ENCODINGS)
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_encode)

    h = sub.add_parser("hash", help="digest text or a file, or identify a hash")
    h.add_argument("text", nargs="?", help="text to hash")
    h.add_argument("--file", help="hash a file instead")
    h.add_argument("--identify", help="work out what kind of hash this is")
    h.add_argument("--json", action="store_true")
    h.set_defaults(func=cmd_hash)

    lg = sub.add_parser("logs", help="triage an auth or web access log")
    lg.add_argument("file")
    lg.add_argument("--top", type=int, default=12, help="findings to show (default 12)")
    lg.add_argument("--fail-on", choices=SEVERITIES,
                    help="exit 4 if a finding at this severity exists")
    lg.add_argument("--json", action="store_true")
    lg.set_defaults(func=cmd_logs)

    cv = sub.add_parser("cve", help="look up a CVE (cached for offline)")
    cv.add_argument("id")
    cv.add_argument("--refresh", action="store_true", help="ignore the cache")
    cv.add_argument("--json", action="store_true")
    cv.set_defaults(func=cmd_cve)

    a = sub.add_parser("attack", help="MITRE ATT&CK technique lookup")
    a.add_argument("query", nargs="?", help="T1059, powershell, ransomware, ...")
    a.add_argument("--tactic", help="filter by tactic, e.g. exfiltration")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_attack)

    p = sub.add_parser("port", help="what an open port means")
    p.add_argument("query", nargs="?", help="port number or service name")
    p.add_argument("--risk", choices=("critical", "high", "medium", "low"),
                   help="list everything at this risk or worse")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_port)

    n = sub.add_parser("ip", help="subnet maths")
    n.add_argument("cidr")
    n.add_argument("--contains", help="is this address inside the range?")
    n.add_argument("--json", action="store_true")
    n.set_defaults(func=cmd_ip)

    ca = sub.add_parser("case", help="incident cases and their timeline")
    ca_sub = ca.add_subparsers(dest="action", required=True)
    ca_new = ca_sub.add_parser("new", help="open a case")
    ca_new.add_argument("--title", required=True)
    ca_new.add_argument("--severity", default="medium", choices=SEVERITIES)
    ca_new.add_argument("--summary", default="")
    ca_new.add_argument("--ttps", default="")
    ca_new.add_argument("--json", action="store_true")
    ca_list = ca_sub.add_parser("list", help="open cases")
    ca_list.add_argument("--status", choices=("open", "investigating", "contained", "closed"))
    ca_list.add_argument("--json", action="store_true")
    ca_show = ca_sub.add_parser("show", help="one case with its timeline")
    ca_show.add_argument("case_id")
    ca_show.add_argument("--json", action="store_true")
    ca_add = ca_sub.add_parser("add", help="append a timeline event")
    ca_add.add_argument("case_id")
    ca_add.add_argument("text")
    ca_add.add_argument("--kind", default="note", choices=cases.EVENT_KINDS)
    ca_add.add_argument("--source", default="analyst")
    ca_add.add_argument("--json", action="store_true")
    ca_status = ca_sub.add_parser("status", help="move a case along")
    ca_status.add_argument("case_id")
    ca_status.add_argument("status_value", choices=("open", "investigating", "contained", "closed"))
    ca_status.add_argument("--resolution", default="")
    ca_status.add_argument("--json", action="store_true")
    ca_export = ca_sub.add_parser("export", help="markdown for the ticket or the vault")
    ca_export.add_argument("case_id")
    ca_export.add_argument("-o", "--out")
    ca_pb = ca_sub.add_parser("playbook", help="attach a checklist to a case")
    ca_pb.add_argument("case_id")
    ca_pb.add_argument("playbook", nargs="?", default="")
    ca_pb.add_argument("-o", "--out")
    ca.set_defaults(func=cmd_case)

    t = sub.add_parser("triage", help="the checklist for this kind of alert")
    t.add_argument("playbook", nargs="?", help="phishing, host, bec, malware, exposure")
    t.add_argument("--case", dest="case_id", help="attach it to a case")
    t.add_argument("--list", action="store_true", help="list the playbooks")
    t.add_argument("-o", "--out", help="write the checklist to a file")
    t.set_defaults(func=cmd_triage)

    doc = sub.add_parser("doctor", help="check the toolbox")
    doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return cmd_dashboard(argparse.Namespace())
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0
    try:
        return func(args)
    except KeyboardInterrupt:
        ui.console.print()
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
