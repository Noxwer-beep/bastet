"""MITRE ATT&CK lookup from a bundled subset.

The full enterprise matrix is ~15 MB of STIX. The 36 techniques here are the ones
that come up in real alert queues, each with the detection that actually catches it.
"""

from __future__ import annotations

import json
from functools import lru_cache

from .config import resource

TACTICS = (
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
)


@lru_cache(maxsize=1)
def load() -> list[dict]:
    return json.loads(resource("attack.json").read_text(encoding="utf-8"))


def normalise(query: str) -> str:
    text = query.strip().upper()
    if text and not text.startswith("T"):
        text = "T" + text.lstrip("T")
    return text


def by_id(query: str) -> dict | None:
    wanted = normalise(query)
    for technique in load():
        if technique["id"].upper() == wanted:
            return technique
    # a parent of a sub-technique: T1059 matches T1059.001
    for technique in load():
        if technique["id"].upper().split(".")[0] == wanted.split(".")[0]:
            return technique
    return None


def search(query: str, tactic: str = "") -> list[dict]:
    text = query.strip().lower()
    results = []
    for technique in load():
        if tactic and technique["tactic"] != tactic.lower():
            continue
        haystack = f"{technique['id']} {technique['name']} {technique['description']} {technique['tactic']}".lower()
        if text in haystack:
            results.append(technique)
    return results


def by_tactic() -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for technique in load():
        grouped.setdefault(technique["tactic"], []).append(technique)
    return {tactic: grouped[tactic] for tactic in TACTICS if tactic in grouped}


def tactics() -> list[str]:
    return sorted({technique["tactic"] for technique in load()})
