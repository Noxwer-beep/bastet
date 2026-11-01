"""CVE lookup via the NVD API, with an on-disk cache.

The API is free and needs no key (a key only raises the rate limit). Every answer
is cached, so the second lookup of the same CVE works with no network — which is
what you want when the laptop is on a segmented network.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .config import cve_cache_dir

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
USER_AGENT = "Bastet/1.0 (analyst lookup)"


class LookupError_(Exception):
    """The lookup could not be completed (network, bad response)."""


@dataclass
class Cve:
    id: str
    published: str = ""
    description: str = ""
    cvss: float | None = None
    severity: str = "unknown"
    vector: str = ""
    cwes: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    source: str = "nvd"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "published": self.published, "description": self.description,
            "cvss": self.cvss, "severity": self.severity, "vector": self.vector,
            "cwes": self.cwes, "refs": self.refs, "source": self.source,
        }


def normalise(text: str) -> str:
    """Accept cve-2021-44228, 2021-44228, CVE 2021 44228."""
    cleaned = text.strip().upper().replace("_", "-")
    if not cleaned.startswith("CVE"):
        cleaned = "CVE-" + cleaned
    cleaned = re.sub(r"^CVE[-\s]?", "CVE-", cleaned)
    cleaned = re.sub(r"[^\d-]", "-", cleaned.replace("CVE-", "", 1))
    parts = [p for p in cleaned.strip("-").split("-") if p]
    if len(parts) < 2:
        raise ValueError(f"not a CVE id: {text!r}")
    return f"CVE-{parts[0]}-{parts[1]}"


def is_cve(text: str) -> bool:
    try:
        return bool(CVE_RE.match(normalise(text)))
    except ValueError:
        return False


# ---------------------------------------------------------------- parsing

def _score(metrics: dict) -> tuple[float | None, str, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            severity = data.get("baseSeverity") or entry.get("baseSeverity") or "unknown"
            return float(score), str(severity).lower(), data.get("vectorString", "")
    return None, "unknown", ""


def parse(payload: dict, cve_id: str = "") -> Cve:
    """Turn an NVD 2.0 response into a Cve. Raised separately so it can be tested."""
    items = payload.get("vulnerabilities") or []
    if not items:
        raise LookupError_(f"no record for {cve_id or 'that id'}")

    cve = items[0].get("cve") or {}
    identifier = cve.get("id") or cve_id

    description = ""
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break

    score, severity, vector = _score(cve.get("metrics") or {})

    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            value = entry.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    refs = [r.get("url", "") for r in (cve.get("references") or []) if r.get("url")]

    return Cve(
        id=identifier,
        published=(cve.get("published") or "")[:10],
        description=description,
        cvss=score,
        severity=severity,
        vector=vector,
        cwes=cwes[:4],
        refs=refs[:5],
    )


# ---------------------------------------------------------------- cache

def _cache_path(cve_id: str):
    return cve_cache_dir() / f"{cve_id}.json"


def cache_get(cve_id: str) -> Cve | None:
    path = _cache_path(cve_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    data["source"] = "cache"
    known = {f for f in Cve.__dataclass_fields__}
    return Cve(**{k: v for k, v in data.items() if k in known})


def cache_put(cve: Cve) -> None:
    path = _cache_path(cve.id)
    try:
        path.write_text(json.dumps(cve.to_dict(), indent=1), encoding="utf-8")
    except OSError:
        pass  # a read-only home is not a reason to fail a lookup


def cache_count() -> int:
    return len(list(cve_cache_dir().glob("CVE-*.json")))


# ---------------------------------------------------------------- network

def fetch(cve_id: str, timeout: float = 12.0) -> Cve:
    url = f"{NVD_URL}?cveId={cve_id}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    key = os.environ.get("NVD_API_KEY")
    if key:
        request.add_header("apiKey", key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise LookupError_(f"NVD returned HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise LookupError_(f"network: {exc.reason}") from None
    except (TimeoutError, ValueError) as exc:
        raise LookupError_(f"{type(exc).__name__}: {exc}") from None

    cve = parse(payload, cve_id)
    cache_put(cve)
    return cve


def get(text: str, refresh: bool = False) -> Cve:
    """Cache first, network second. `refresh` forces the network."""
    cve_id = normalise(text)
    if not refresh:
        cached = cache_get(cve_id)
        if cached:
            return cached
    try:
        return fetch(cve_id)
    except LookupError_:
        cached = cache_get(cve_id)
        if cached:
            cached.source = "cache (offline)"
            return cached
        raise
