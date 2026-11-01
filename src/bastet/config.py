"""Paths, constants, and the one place that decides where data lives."""

from __future__ import annotations

import os
from pathlib import Path

APP = "bastet"

#: Severity vocabulary, ordered the way a queue is read.
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

SEVERITY_STYLE = {
    "critical": "bold #ff5c5c",
    "high": "bold #ff9474",
    "medium": "#f0c45a",
    "low": "#92acbe",
    "info": "dim",
}

STATUSES = ("open", "investigating", "contained", "closed")
CASE_STATUS_STYLE = {
    "open": "bold #ff9474",
    "investigating": "#f0c45a",
    "contained": "#8bd67a",
    "closed": "dim",
}

ACCENT = "#c9f24d"
DIM = "dim"

#: Ports that make an analyst look twice when they answer on a workstation.
SUSPICIOUS_PORTS = {
    23: "telnet — cleartext, usually a legacy device nobody patched",
    445: "SMB — the ransomware favourite; check for SMBv1",
    3389: "RDP — check exposure, NLA, and failed-login volume",
    5900: "VNC — often unauthenticated on appliances",
    6379: "Redis — unauthenticated by default",
    9200: "Elasticsearch — unauthenticated by default",
    11211: "memcached — amplification and data exposure",
    27017: "MongoDB — unauthenticated by default",
    2375: "Docker API — unauthenticated root on the host",
    2376: "Docker API over TLS — check the cert is not self-signed",
    10250: "kubelet — anonymous auth is a known default",
    2379: "etcd — unauthenticated by default",
}


def data_dir() -> Path:
    """Where Bastet keeps its cache and cases."""
    env = os.environ.get("BASTET_DATA_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / APP


def ensure_dirs() -> dict[str, Path]:
    root = data_dir()
    dirs = {
        "root": root,
        "cache": root / "cache",
        "cases": root / "cases",
        "exports": root / "exports",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def db_path() -> Path:
    ensure_dirs()
    return data_dir() / "cases.db"


def cve_cache_dir() -> Path:
    path = ensure_dirs()["cache"] / "cve"
    path.mkdir(parents=True, exist_ok=True)   # cache_put must not fail silently
    return path


def resource(*parts: str) -> Path:
    """A bundled data file (attack.json, ports.json)."""
    return Path(__file__).resolve().parent.joinpath("data", *parts)
