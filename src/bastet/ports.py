"""Port reference with the reason an analyst cares.

A number on a scan is not a finding. "6379 is open" means nothing until you know
that Redis has no auth by default, which is what this table is for.
"""

from __future__ import annotations

import json
from functools import lru_cache

from .config import resource


@lru_cache(maxsize=1)
def load() -> list[dict]:
    return json.loads(resource("ports.json").read_text(encoding="utf-8"))


def lookup(port: int) -> dict | None:
    for entry in load():
        if entry["port"] == port:
            return entry
    return None


def search(term: str) -> list[dict]:
    text = term.strip().lower()
    if text.isdigit():
        found = lookup(int(text))
        return [found] if found else []
    return [
        entry for entry in load()
        if text in entry["service"].lower() or text in entry["note"].lower()
    ]


def dangerous(minimum: str = "high") -> list[dict]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cutoff = order.get(minimum, 1)
    return [e for e in load() if order.get(e["risk"], 9) <= cutoff]
