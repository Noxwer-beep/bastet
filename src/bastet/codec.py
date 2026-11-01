"""Decoding chains — the thing an analyst does forty times a shift.

Phishing payloads are usually encoded more than once: a URL-encoded base64 blob of
a PowerShell command. This peels them in order and shows the chain, so you can see
where it ends instead of guessing.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import urllib.parse
from dataclasses import dataclass

MAX_STEPS = 5

# A short payload only counts as base64 if it carries padding — otherwise every
# 8-letter word in a log decodes to noise.
BASE64_RE = re.compile(r"^(?:[A-Za-z0-9+/_-]{4,}={1,2}|[A-Za-z0-9+/_-]{12,})$")
HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{8,}$")
URLENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
HTMLENTITY_RE = re.compile(r"&(#\d{2,5}|#x[0-9a-fA-F]{2,4}|[a-zA-Z]{2,8});")


@dataclass
class Step:
    kind: str
    value: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value}


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return good / len(text)


def _looks_like_text(text: str) -> bool:
    if not text.strip():
        return False
    if _printable_ratio(text) < 0.92:
        return False
    letters = sum(1 for c in text if c.isalpha() or c.isspace())
    return letters / len(text) > 0.35


def try_base64(text: str) -> str | None:
    candidate = text.strip()
    if not BASE64_RE.match(candidate) or len(candidate) % 4 not in (0, 2, 3):
        return None
    padded = candidate.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-8", "utf-16-le"):
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_text(decoded):
            return decoded
    return None


def try_hex(text: str) -> str | None:
    candidate = text.strip()
    if not HEX_RE.match(candidate):
        return None
    body = candidate[2:] if candidate.lower().startswith("0x") else candidate
    if len(body) % 2:
        return None
    try:
        raw = bytes.fromhex(body)
    except ValueError:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        decoded = raw.decode("latin-1")
    return decoded if _looks_like_text(decoded) else None


def try_url(text: str) -> str | None:
    if not URLENCODED_RE.search(text):
        return None
    decoded = urllib.parse.unquote(text)
    return decoded if decoded != text else None


def try_html(text: str) -> str | None:
    if not HTMLENTITY_RE.search(text):
        return None
    decoded = html.unescape(text)
    return decoded if decoded != text else None


def try_rot13(text: str) -> str | None:
    decoded = codecs.decode(text, "rot13")
    return decoded if decoded != text else None


DETECTORS = (
    ("url", try_url),
    ("html", try_html),
    ("base64", try_base64),
    ("hex", try_hex),
)


def decode_chain(text: str, max_steps: int = MAX_STEPS, include_rot13: bool = False) -> list[Step]:
    """Peel encodings until nothing recognisable is left.

    The first step is always the original, so the caller can print the full chain
    without special-casing the input.
    """
    chain = [Step("input", text)]
    current = text
    detectors = list(DETECTORS)
    if include_rot13:
        detectors.append(("rot13", try_rot13))

    for _ in range(max_steps):
        for name, detector in detectors:
            result = detector(current)
            if result and result != current:
                chain.append(Step(name, result))
                current = result
                break
        else:
            break
    return chain


def encode(text: str, kind: str) -> str:
    kind = kind.lower()
    if kind == "base64":
        return base64.b64encode(text.encode()).decode()
    if kind == "base64url":
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    if kind == "hex":
        return text.encode().hex()
    if kind == "url":
        return urllib.parse.quote(text, safe="")
    if kind == "html":
        return html.escape(text)
    if kind == "rot13":
        return codecs.encode(text, "rot13")
    raise ValueError(f"unknown encoding {kind!r} — try base64, base64url, hex, url, html, rot13")


ENCODINGS = ("base64", "base64url", "hex", "url", "html", "rot13")
