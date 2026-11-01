"""Terminal rendering: one place for panels, tables, bars and the sparkline.

Rich is a hard dependency for the pretty path, but every function here degrades to
plain text if it is missing, so a locked-down work laptop still gets usable output.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Iterable, Sequence

from . import __version__
from . import cat as catmod
from .config import ACCENT, SEVERITY_STYLE

try:  # pragma: no cover - exercised by the fallback branch only
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH = True
except ModuleNotFoundError:  # pragma: no cover
    RICH = False

    class _Fake:
        def print(self, *args, **kwargs):
            print(*[str(a) for a in args])

    Console = _Fake  # type: ignore

# Piped output must not reflow at 80 columns; tables wrap mid-row and the result
# is unreadable. Same rule as the other tools in this repo.
_WIDTH = None if sys.stdout.isatty() else int(os.environ.get("COLUMNS", "100"))
console = Console(width=_WIDTH)
err_console = Console(stderr=True)

SPARK = "▁▂▃▄▅▆▇█"


# ---------------------------------------------------------------- identity

COMPACT_CAT = [r" /\_/\  ", r"( |_| ) ", r"  \_/   "]


def header(title: str, subtitle: str = "", plain_mark: bool = True) -> None:
    """Small cat + title. The big cat is for `bastet` and `bastet cat`."""
    if not RICH:
        console.print(f"{title} — {subtitle}")
        return

    text = Text()
    for index, line in enumerate(COMPACT_CAT):
        if index:
            text.append("\n")
        text.append(line, style=ACCENT)
    text.append("\n")

    body = Text()
    body.append(title.upper(), style="bold")
    if subtitle:
        body.append(f"\n{subtitle}", style="dim")
    body.append(f"\nbastet {__version__}", style="dim")

    grid = Table.grid(padding=(0, 2))
    grid.add_row(text, body)
    console.print(grid)
    console.print()


def big_cat(mood: str = "awake") -> None:
    """The full mark with the tagline beside it."""
    if not RICH:
        console.print(catmod.plain(mood))
        return

    art = Text()
    for index, line in enumerate(catmod.art(mood)):
        if index:
            art.append("\n")
        if "v" in line and "|" in line:
            head, _, tail = line.partition("v")
            art.append(head)
            art.append("v", style=ACCENT)
            art.append(tail)
        else:
            art.append(line)

    side = Text()
    side.append("\n\n")
    side.append("BASTET", style="bold")
    side.append(f"  {__version__}\n", style="dim")
    for line in (
        "the night-shift toolbox",
        "triage an indicator, read a log, write the case up",
        "one prompt instead of nine tabs",
    ):
        side.append(line + "\n", style="dim")

    grid = Table.grid(padding=(0, 3))
    grid.add_row(art, side)
    console.print()
    console.print(grid)
    console.print()


# ---------------------------------------------------------------- building blocks

def panel(body: Any, title: str = "", border: str = "#232a32") -> None:
    if not RICH:
        if title:
            console.print(f"-- {title} --")
        console.print(body)
        return
    console.print(Panel(body, title=title or None, border_style=border,
                        padding=(0, 1), expand=False))


def table(columns: Sequence[tuple[str, int | None]], expand: bool = False):
    """columns: (heading, content width or None for flexible).

    Rich counts padding and the ellipsis inside the column width, so a caller
    asking for 8 gets 5 visible characters. +3 makes the number mean what it says.
    """
    if not RICH:
        return None
    t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=expand)
    for heading, width in columns:
        kwargs = {"no_wrap": True, "overflow": "ellipsis"}
        if width:
            kwargs["width"] = width + 3
        else:
            kwargs["ratio"] = 1
        t.add_column(heading, **kwargs)
    return t


def severity(value: str) -> Any:
    value = (value or "info").lower()
    style = SEVERITY_STYLE.get(value, "dim")
    if not RICH:
        return value.upper()
    return Text(value.upper(), style=style)


def kv(items: Iterable[tuple[str, Any]], title: str = "") -> None:
    if not RICH:
        for key, value in items:
            console.print(f"{key}: {value}")
        return
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column(overflow="fold")
    for key, value in items:
        grid.add_row(key, value if isinstance(value, Text) else str(value))
    panel(grid, title)


def sparkline(values: Sequence[float], width: int | None = None) -> str:
    """A one-line histogram. Silence beats a chart nobody reads."""
    data = [v for v in values]
    if not data:
        return ""
    if width and len(data) > width:
        # downsample by summing buckets, so peaks survive
        bucket = len(data) / width
        reduced = []
        for i in range(width):
            start = int(i * bucket)
            end = max(start + 1, int((i + 1) * bucket))
            reduced.append(sum(data[start:end]))
        data = reduced
    top = max(data) or 1
    return "".join(SPARK[min(len(SPARK) - 1, int(v / top * (len(SPARK) - 1)))] for v in data)


def bar(value: float, maximum: float, width: int = 20) -> str:
    if maximum <= 0:
        return ""
    filled = int(round(width * min(value / maximum, 1.0)))
    return "█" * filled + "·" * (width - filled)


def rule(label: str = "") -> None:
    if not RICH:
        console.print(f"--- {label} ---" if label else "---")
        return
    line = Text("─" * 4, style="dim")
    if label:
        line.append(f" {label} ", style="dim")
        line.append("─" * 40, style="dim")
    console.print(line)


def emit_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def warn(message: str) -> None:
    if RICH:
        err_console.print(f"[#f0c45a]![/] {message}")
    else:
        err_console.print(f"! {message}")


def fail(message: str) -> None:
    if RICH:
        err_console.print(f"[bold #ff5c5c]x[/] {message}")
    else:
        err_console.print(f"x {message}")
