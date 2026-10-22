"""Line widths of multi-line menu strings: how many cells fit on one line of a text box.

Some fixed-slot strings (tooltips, help texts) fill a box of two or three lines, but the slot has no line-break code.
The game wraps the text at the width of the box, and the Japanese text pads each line with spaces so that the next
line starts at the right place. To translate such a string the tool has to know the line width, which is not stored
anywhere, so it is recovered from the padding of the Japanese (a "width" in cells; a cell holds two English letters).

The rule, in order:
 1. LINE_WIDTH (one string) and LINE_CELLS (all slots of one size in a file) are overrides found by trying in game.
 2. The padding of a string is the end of its first run of two or more spaces that has text behind it (runs that end
    before cell MIN_WIDTH are spacing inside a line, no box is that narrow). When at least two padded strings near it
    (NEAR strings up or down the same table) are padded to half or a third of that, the smaller number counts: the
    first line was full and the run closed line 2. A table is a run of strings less than TABLE_GAP bytes apart.
 3. A padded string is confirmed when another padded string near it has the same width.
 4. Every other string takes the width of the nearest confirmed string before and after it (within NEAR): the smallest
    of them, and of its own padding if it has one. Without such a neighbour a padded string keeps its own padding and
    an unpadded string is one line.
 5. A string is marked uncertain ("?" in the export) when its width is a guess: its own padding disagrees with its
    neighbours or nothing confirms it, the neighbours before and after disagree, or the Japanese runs past the first
    line with no space in front of the break. A string that is not longer than one line of the box is never uncertain.
    More than MAX_LINES lines: not a text box, one line, uncertain.

Public names: line_widths(name, found), line_caps(s), japanese_lines(s), padding(units), used_cells(units).
"""
from typing import List, Optional, Sequence

from pp15.text.colour_text import units_text
from pp15.text.string_tables import LINE_CELLS, LINE_WIDTH, MAX_LINES, MIN_WIDTH, NEAR, TABLE_GAP


def used_cells(units: Sequence[int]) -> int:
    """Cells of a string up to its last non-space cell."""
    n = len(units)
    while n and units[n - 1] == 0:
        n -= 1
    return n


def padding(units: Sequence[int]) -> Optional[int]:
    """End of the first run of two or more spaces with text behind it, or None."""
    n, i = used_cells(units), 0
    while i < n:
        if units[i]:
            i += 1
            continue
        j = i
        while units[j] == 0:
            j += 1
        if j - i >= 2 and j >= MIN_WIDTH:
            return j
        i = j
    return None


def line_widths(name: str, found: List[dict]) -> List[dict]:
    """Adds "width" (cells per line, 0 = one line) and "uncertain" to the strings of a module and returns them.

    name = module file name; found = the strings of strings_of() in file order. The rule is in the module docstring."""
    n = len(found)
    pad = [padding(s["units"]) for s in found]
    table, t = [], 0                    # table[k] = number of the run of nearby strings that string k belongs to
    for k, s in enumerate(found):
        p = found[k - 1]
        if k and (s["section"] != p["section"] or s["offset"] - (p["offset"] + p["cells"] * 2 + 2) > TABLE_GAP):
            t += 1
        table.append(t)

    def near(k):
        return [j for j in range(max(0, k - NEAR), min(n, k + NEAR + 1)) if j != k and table[j] == table[k]]

    for k in range(n):                      # a full first line: the run closed line 2 or 3
        if pad[k]:
            around = [pad[j] for j in near(k)]
            for m in (3, 2):
                if pad[k] % m == 0 and pad[k] // m >= MIN_WIDTH and around.count(pad[k] // m) >= 2:
                    pad[k] //= m
                    break
    sure = [bool(pad[k]) and any(pad[j] == pad[k] for j in near(k)) for k in range(n)]
    for k, s in enumerate(found):
        cells, used = s["cells"], used_cells(s["units"])
        key = (name, s["section"], s["offset"])
        if key in LINE_WIDTH or (name, cells) in LINE_CELLS:
            width, unsure = LINE_WIDTH.get(key, LINE_CELLS.get((name, cells))), False
        elif sure[k]:
            width, unsure = pad[k], False
        else:
            around = set()
            for js in (range(k - 1, -1, -1), range(k + 1, n)):
                j = next((j for j in js if abs(j - k) <= NEAR and table[j] == table[k] and sure[j]), None)
                if j is not None:
                    around.add(pad[j])
            if pad[k]:
                width, unsure = min(around | {pad[k]}), True
            elif not around or cells <= min(around):
                width, unsure = 0, False
            else:
                width = min(around)
                unsure = len(around) > 1 or (used > width and s["units"][width - 1] != 0)
        if width and cells <= width:
            width = 0
        if width and -(-cells // width) > MAX_LINES:
            width, unsure = 0, True
        s["width"], s["uncertain"] = width, unsure
    return found


def line_caps(s: dict) -> List[int]:
    """Cells of each line of a slot: [width, width, ..., remainder], or [cells] for a one-line string."""
    cells, width = s["cells"], s.get("width", 0)
    if not width:
        return [cells]
    return [width] * (cells // width) + ([cells % width] if cells % width else [])


def japanese_lines(s: dict) -> str:
    """The Japanese with | where the game breaks the line, padding removed."""
    if s.get("width"):
        w, u = s["width"], s["units"]
        lines = [units_text(u[i:i + w]).rstrip("　") for i in range(0, len(u), w)]
        while len(lines) > 1 and not lines[-1]:
            lines.pop()
        return "|".join(lines)
    return s["text"]
