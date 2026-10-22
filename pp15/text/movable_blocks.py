"""Blocks of strings that the build lays out again, so that each may be longer or shorter than its Japanese.

Normally a string sits in a fixed slot and the English must fit it. A few lists, such as the 24 entries of the
schedule (scs_data.rel section 5, offsets 22308..22752), stand back to back and are reached through one pointer table
right behind them. For these the build rewrites the block and the pointers, so what counts is only that all the
entries fit the block together and that no entry is wider than its column (BLOCKS in string_tables.py gives "max").
An entry that is the end of another one shares its cells ("Japan Champ Qual Final" inside "Exam, Japan Champ Qual
Final": start the shared part on an even letter).

Public names: block_of(name, section, offset), block_layout(seqs), block_fit(name, strs, english).
"""
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from pp15.build.font import text_segments
from pp15.text.string_tables import BLOCKS


def block_of(name: str, sec: int, off: int) -> Optional[dict]:
    """The block (a dict of BLOCKS) that the string at (section sec, offset off) of module `name` belongs to, or None."""
    for b in BLOCKS.get(name, ()):
        if b["section"] == sec and b["start"] <= off < b["end"]:
            return b
    return None


def block_layout(seqs: Sequence[tuple]) -> Tuple[List[int], int]:
    """Where the strings of a block go: ([start of each, in cells from the start of the block], cells used).

    seqs = the cells of every string (tuples, without the 0xFFFF), in the order of the pointer table. Strings are
    laid back to back, each closed by one cell; a string that is the end of another shares its cells."""
    host = {}                           # string i -> the longer string whose tail it is
    for i, a in enumerate(seqs):
        for j, b in enumerate(seqs):
            if i != j and (len(b) > len(a) or (len(b) == len(a) and j < i)) and b[len(b) - len(a):] == a:
                host[i] = j
                break
    starts, pos = {}, 0
    for i, a in enumerate(seqs):
        if i not in host:
            starts[i] = pos
            pos += len(a) + 1

    def start(i):
        if i not in starts:
            starts[i] = start(host[i]) + len(seqs[host[i]]) - len(seqs[i])
        return starts[i]
    return [start(i) for i in range(len(seqs))], pos


def block_fit(name: str, strs: Iterable[dict], english: Dict[Tuple[int, int], str]) -> List[str]:
    """Problems (a list of text lines) if a block of `name` cannot hold its strings, English where there is some.

    strs = the strings of strings_of(name); english = {(section, offset): text}."""
    problems = []
    for b in BLOCKS.get(name, ()):
        mine = sorted((s for s in strs if s.get("block") is b), key=lambda s: s["offset"])
        seqs = [tuple(text_segments(english[(s["section"], s["offset"])]))
                if english.get((s["section"], s["offset"])) else tuple(s["units"][:s["cells"]]) for s in mine]
        used, room = block_layout(seqs)[1], (b["end"] - b["start"]) // 2
        if used > room:
            problems.append("%d:%d: the block is %d cells (%d letters) too full: %d of %d cells"
                            % (b["section"], b["start"], used - room, (used - room) * 2, used, room))
    return problems
