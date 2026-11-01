"""Pull indicators out of unstructured text.

The most common shift task with no good tool: someone forwards an alert, a phishing
mail, or a paragraph from a ticket, and you need the addresses, domains, hashes and
CVEs out of it — deduplicated, typed, and defanged before it goes anywhere.

Regexes do the extraction; `ioc.classify` does the explaining, so an indicator found
here reads exactly like one you typed in by hand.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .ioc import Indicator, classify

MAX_ITEMS = 300

#: Extensions that look like a TLD in prose but are almost always a filename.
FILE_SUFFIXES = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "txt", "log", "md", "csv", "json", "xml", "yml",
    "yaml", "conf", "ini", "cfg", "sh", "py", "js", "ts", "css", "html", "htm",
    "php", "exe", "dll", "so", "dylib", "zip", "gz", "tar", "rar", "7z", "iso",
    "bin", "dat", "db", "sql", "bak", "tmp", "swp", "lock", "service", "socket",
    "timer", "local", "internal", "lan", "arpa", "test", "invalid", "example",
}

PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("url", re.compile(r"https?://[^\s<>\"'\)\]\}]+", re.I)),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"\b(?:[0-9a-f]{1,4}:){1,7}:?(?:[0-9a-f]{1,4})?\b", re.I)),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[A-Za-z]{2,}\b")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")),
)

KINDS = tuple(name for name, _ in PATTERNS)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _valid_ipv6(value: str) -> bool:
    """A timestamp like 2026:10:00:11 matches the shape and is not an address."""
    if value.count(":") < 3:
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _plausible_domain(value: str) -> bool:
    labels = value.lower().strip(".").split(".")
    if len(labels) < 2:
        return False
    if labels[-1] in FILE_SUFFIXES:
        return False
    # a label that is all digits is an IP fragment, not a domain
    if all(label.isdigit() for label in labels):
        return False
    return True


def extract(text: str, only: tuple[str, ...] = KINDS, limit: int = MAX_ITEMS) -> list[Indicator]:
    """Every indicator in the text, deduplicated, in the order it first appeared."""
    found: dict[str, Indicator] = {}

    for kind, pattern in PATTERNS:
        if kind not in only:
            continue
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(".,;:)]}\"'")
            if value in found:
                continue
            if kind == "ipv4" and not _valid_ipv4(value):
                continue
            if kind == "ipv6" and not _valid_ipv6(value):
                continue
            if kind == "domain" and not _plausible_domain(value):
                continue
            if kind == "email":
                # the domain pattern will also match the part after the @
                pass
            found[value] = classify(value)
            if len(found) >= limit:
                return list(found.values())

    return list(found.values())


def from_file(path: str | Path, only: tuple[str, ...] = KINDS, limit: int = MAX_ITEMS) -> list[Indicator]:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise FileNotFoundError(str(file_path))
    text = file_path.read_text(errors="replace")
    return extract(text, only=only, limit=limit)


def by_kind(indicators: list[Indicator]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for indicator in indicators:
        counts[indicator.kind] = counts.get(indicator.kind, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))
