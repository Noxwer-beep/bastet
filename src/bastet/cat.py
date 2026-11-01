"""The cat.

Same silhouette as the rest of the lab — ears, slit eyes, one nose — so the tools
look like they were made by the same person. Bastet gets two moods because a night
shift has two moods.
"""

from __future__ import annotations

ART = [
    r"        /\                 /\ ",
    r"       /  \_______________/  \ ",
    r"      |    {eyes}         {eyes}    | ",
    r"      |          {nose}           | ",
    r"       \___________________/  ",
]

MOODS = {
    "awake": ("||", "v"),
    "sleepy": ("--", "v"),
}

FACES = ["( o.o )", "( -.- )", "( o_o )", "( ^.^ )", "( ._. )"]


def art(mood: str = "awake") -> list[str]:
    """The mark, as text. `{eyes}` and `{nose}` stay unformatted for the caller."""
    eyes, nose = MOODS.get(mood, MOODS["awake"])
    return [line.replace("{eyes}", eyes).replace("{nose}", nose) for line in ART]


def plain(mood: str = "awake") -> str:
    return "\n".join(art(mood))


def face(index: int = 0) -> str:
    return FACES[index % len(FACES)]
