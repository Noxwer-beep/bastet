"""Indicator triage: what is this, is it dangerous, and what do I paste where.

Everything here is offline and deterministic — a shift should not depend on an API
key to answer "is that a private address". Reputation services are linked, not
queried, unless you ask for them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

#: Endings that show up far more in phishing than in real infrastructure.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "support", "rest", "cam", "sbs",
    "tk", "gq", "cf", "ml", "ga", "work", "loan", "review", "country", "stream",
}

#: Hashes every analyst should recognise on sight.
KNOWN_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "md5 of an empty file",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1 of an empty file",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "sha256 of an empty file",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file (md5)",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR test file (sha256)",
}

#: Ports that turn a boring URL into a question.
NOTABLE_URL_PORTS = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8081, 8443, 9200}

DEFANG_DOT = "[.]"
REFANG_DOT = re.compile(r"\[\.\]|\(\.\)|\{\.\}")


@dataclass
class Indicator:
    raw: str
    kind: str
    notes: list[str] = field(default_factory=list)
    links: dict[str, str] = field(default_factory=dict)
    risk: str = "info"

    @property
    def value(self) -> str:
        """The value with refanged dots, ready to paste into a lookup."""
        return refang(self.raw)

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "value": self.value,
            "kind": self.kind,
            "risk": self.risk,
            "notes": self.notes,
            "links": self.links,
            "defanged": defang(self.value),
        }


# ---------------------------------------------------------------- defang

def defang(text: str) -> str:
    """Make an indicator safe to paste into a ticket or a chat."""
    if classify_bare(text) in ("md5", "sha1", "sha256", "sha512"):
        return text
    out = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    out = out.replace(".", DEFANG_DOT)
    return out


def refang(text: str) -> str:
    out = REFANG_DOT.sub(".", text)
    out = out.replace("hxxps://", "https://").replace("hxxp://", "http://")
    return out.replace("[://]", "://").replace("[:]", ":")


# ---------------------------------------------------------------- classify

def classify_bare(text: str) -> str:
    """The type of an indicator, without any enrichment."""
    value = text.strip()
    if not value:
        return "empty"

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return "ipv4" if ip.version == 4 else "ipv6"

    if CVE_RE.match(value):
        return "cve"

    if HEX_RE.match(value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)]

    if "://" in value:
        return "url"

    if EMAIL_RE.match(value):
        return "email"

    if DOMAIN_RE.match(value):
        return "domain"

    if HEX_RE.match(value) and len(value) >= 16 and len(value) % 2 == 0:
        return "hex"

    return "unknown"


def classify(text: str) -> Indicator:
    """Classify and annotate one indicator."""
    value = text.strip()
    indicator = Indicator(raw=text.strip(), kind=classify_bare(refang(value)))

    if indicator.kind in ("ipv4", "ipv6"):
        _annotate_ip(indicator, refang(value))
    elif indicator.kind == "domain":
        _annotate_domain(indicator, refang(value).lower())
    elif indicator.kind == "url":
        _annotate_url(indicator, refang(value))
    elif indicator.kind in ("md5", "sha1", "sha256", "sha512"):
        _annotate_hash(indicator, value.lower())
    elif indicator.kind == "cve":
        indicator.notes.append("CVE identifier — `bastet cve` will fetch the details")
        indicator.links["nvd"] = f"https://nvd.nist.gov/vuln/detail/{value.upper()}"
    elif indicator.kind == "email":
        _annotate_email(indicator, refang(value).lower())
    elif indicator.kind == "hex":
        indicator.notes.append("looks like raw hex — try `bastet decode`")

    return indicator


def _annotate_ip(indicator: Indicator, value: str) -> None:
    ip = ipaddress.ip_address(value)
    if ip.is_loopback:
        indicator.notes.append("loopback — never a remote attacker")
    elif ip.is_private:
        indicator.notes.append("private address (RFC1918) — lateral movement, not the internet")
        indicator.risk = "low"
    elif ip.is_link_local:
        indicator.notes.append("link-local — discovery protocol, not routable")
    elif ip.is_multicast:
        indicator.notes.append("multicast")
    elif ip.is_reserved or ip.is_unspecified:
        indicator.notes.append("reserved / unspecified range")
    else:
        indicator.notes.append("public address — reputation lookup is worth the paste")
        indicator.risk = "medium"

    if ip.is_global:
        indicator.links["virustotal"] = f"https://www.virustotal.com/gui/ip-address/{value}"
        indicator.links["abuseipdb"] = f"https://www.abuseipdb.com/check/{value}"
        indicator.links["shodan"] = f"https://www.shodan.io/host/{value}"


def _annotate_domain(indicator: Indicator, value: str) -> None:
    labels = value.split(".")
    tld = labels[-1]

    if value.startswith("xn--") or ".xn--" in value:
        indicator.notes.append("punycode — the displayed name is not the real one")
        indicator.risk = "high"

    if tld in SUSPICIOUS_TLDS:
        indicator.notes.append(f".{tld} is common in throwaway phishing infrastructure")
        indicator.risk = max(indicator.risk, "high", key=_risk_rank)

    digits = sum(c.isdigit() for c in value)
    if digits >= 4 and len(value) < 30:
        indicator.notes.append("digit-heavy domain — typical of algorithmically generated names")

    if value.count("-") >= 3:
        indicator.notes.append("three or more hyphens — check for a brand impersonation")

    if len(labels) >= 4:
        indicator.notes.append(f"{len(labels)} labels deep — count the real registrable domain")

    if len(value) > 40:
        indicator.notes.append("long hostname — padding is used to push the real name out of view")

    if indicator.risk == "info":
        indicator.risk = "medium"

    indicator.links["virustotal"] = f"https://www.virustotal.com/gui/domain/{value}"
    indicator.links["urlscan"] = f"https://urlscan.io/domain/{value}"
    indicator.links["whois"] = f"https://who.is/whois/{value}"


def _annotate_url(indicator: Indicator, value: str) -> None:
    try:
        parts = urlsplit(value)
    except ValueError:
        indicator.notes.append("could not be parsed as a URL")
        return

    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()

    if scheme == "http":
        indicator.notes.append("plain HTTP — anything on the path can read or change it")

    if "@" in (parts.netloc or ""):
        indicator.notes.append("credentials in the URL — the part before @ is not the host")
        indicator.risk = "high"

    if host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            indicator.notes.append("host is a literal IP — no domain to check, no certificate story")
            indicator.risk = max(indicator.risk, "medium", key=_risk_rank)

    if host.startswith("xn--") or ".xn--" in host:
        indicator.notes.append("punycode host — the link text will not match the address")
        indicator.risk = "high"

    port = parts.port
    if port and port not in (80, 443) and port in NOTABLE_URL_PORTS:
        indicator.notes.append(f"non-standard port {port} on a web URL")

    if host and host.count(".") >= 4:
        indicator.notes.append("deep subdomain chain — usually a free-hosting sandbox")

    if indicator.risk == "info":
        indicator.risk = "low"

    indicator.links["urlscan"] = f"https://urlscan.io/liveshot/?url={value}"
    if host:
        indicator.links["virustotal"] = f"https://www.virustotal.com/gui/domain/{host}"


def _annotate_hash(indicator: Indicator, value: str) -> None:
    note = KNOWN_HASHES.get(value)
    if note:
        indicator.notes.append(f"known hash — {note}")
    if len(set(value)) == 1:
        indicator.notes.append("every character is identical — placeholder, not a real hash")
        indicator.risk = "low"
    if indicator.risk == "info":
        indicator.risk = "medium"
    indicator.links["virustotal"] = f"https://www.virustotal.com/gui/file/{value}"
    indicator.links["malwarebazaar"] = f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{value}"


def _annotate_email(indicator: Indicator, value: str) -> None:
    domain = value.split("@", 1)[1]
    indicator.notes.append("email address — check the domain, not the display name")
    indicator.risk = "medium"
    indicator.links["hibp"] = f"https://haveibeenpwned.com/account/{value}"
    indicator.links["virustotal"] = f"https://www.virustotal.com/gui/domain/{domain}"


def _risk_rank(value: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(value, 0)


def triage(values: list[str]) -> list[Indicator]:
    return [classify(value) for value in values]


def worst_risk(indicators: list[Indicator]) -> str:
    if not indicators:
        return "info"
    return max((i.risk for i in indicators), key=_risk_rank)
