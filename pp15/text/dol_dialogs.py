"""The blue system dialogs of main.dol (save prompts, memory-card notices): 264 strings in one block of the program.

main.dol is the game's main program (docs/GLOSSARY.md, "DOL"). Its dialog strings stand back to back at file offsets
0x143AA0..0x145ACE. Each unit is 0x1000 | glyph number and 0xFFFF ends a string; there are no slots and no padding, and
each string is one line of a dialog. The unit 0x1FFD, shown as `{}`, is the blank cell of these strings (the Japanese
never uses glyph 0 here): it indents the menu options and the Yes/No and "press A" rows, which come in copies with 1 to 9
and 1 to 12 of them in front. The English must keep the same number of `{}`. Two spaces that fill a cell of the English
become glyph 0 (unit 0x1000), which no Japanese dialog line uses.

main_prg.rel has a table of 252 pointers (relocations against module 0): 251 point at the start of a string, the last
one at a row of ten stars right behind the block. The 13 strings no relocation points at cannot move ("fixed"): their
English must fit the Japanese cell count. All others are laid out again by the build and re-pointed, so a line may
grow: at most to the longest Japanese line of the block, with a warning from DOL_OVER cells over its own Japanese (the
box was sized for the Japanese). The strings between two fixed strings must fit the space between them, and all
together the block (a fixed string that is shorter in English leaves the rest of its place to the strings behind it).
check, merge and the build apply the same rules. The IDs of these strings are `0:<file offset>`.

The untouched original is kept at _work/orig_sys/main.dol and strings are always read from there.

Public names: dol_data(), dol_strings(), dol_cells(english), dol_need(english), dol_segments(strs, need),
dol_fit(strs, english).
"""
import hashlib
import os
import shutil
import struct
import sys
from typing import Callable, Dict, List, Optional, Tuple

from pp15 import config
from pp15.glyphs import MAX_GLYPH, glyph_to_char
from pp15.script.rel import Rel
from pp15.text.colour_text import letters
from pp15.text.string_tables import (DOL, DOL_ADDRESS, DOL_BLOCK, DOL_CTRL, DOL_GLYPH, DOL_ORIG, DOL_SHA1, DOL_SOURCE,
                                     DOL_STRINGS, END)

_dol_cache: Optional[List[dict]] = None


def dol_data() -> bytes:
    """The untouched main.dol, from _work/orig_sys (copied there from DATA/sys on first use, if its SHA-1 is the
    original's). Exits with a message when only a changed copy exists."""
    if not os.path.exists(DOL_ORIG):
        if not os.path.exists(DOL_SOURCE):
            sys.exit("%s not found" % DOL_SOURCE)
        with open(DOL_SOURCE, "rb") as f:
            if hashlib.sha1(f.read()).hexdigest() != DOL_SHA1:
                sys.exit("%s is not the original (sha1 differs) and %s does not exist" % (DOL_SOURCE, DOL_ORIG))
        os.makedirs(os.path.dirname(DOL_ORIG), exist_ok=True)
        shutil.copy2(DOL_SOURCE, DOL_ORIG)
        print("Saved the original %s to %s" % (DOL, DOL_ORIG))
    with open(DOL_ORIG, "rb") as f:
        data = f.read()
    if hashlib.sha1(data).hexdigest() != DOL_SHA1:
        sys.exit("%s is not the original main.dol (sha1 differs)" % DOL_ORIG)
    return data


def dol_strings() -> List[dict]:
    """The dialog strings of main.dol, read once: one dict per string with section (always 0), offset (file offset),
    cells, units, text, ctrl (number of 0x1FFD units) and fixed (True when no pointer allows moving it)."""
    global _dol_cache
    if _dol_cache is None:
        data, (a, b) = dol_data(), DOL_BLOCK
        hw = struct.unpack_from(">%dH" % ((b - a) // 2), data, a)
        assert hw[-1] == END, "the dialog block of main.dol does not end with 0xFFFF"
        orig = os.path.join(config.WORK_DIR, "orig", "main_prg.rel")
        rel = Rel(orig if os.path.exists(orig) else os.path.join(config.DATA_FILES, "main_prg.rel"))
        # file offsets that main_prg.rel's pointer table (relocations against module 0 = main.dol) points at
        targets = sorted(r[5] - DOL_ADDRESS for r in rel.relocs() if r[3] == 0 and a <= r[5] - DOL_ADDRESS < b)
        out, start = [], 0
        for i, u in enumerate(hw):
            if u != END:
                continue
            units, off = list(hw[start:i]), a + start * 2
            assert all(x == DOL_CTRL or (x & 0xF000 == DOL_GLYPH and x & 0xFFF <= MAX_GLYPH) for x in units), off
            inside = [x for x in targets if off <= x <= a + i * 2]
            out.append({"section": 0, "offset": off, "cells": len(units), "units": units,
                        "ctrl": units.count(DOL_CTRL), "fixed": inside != [off],
                        "text": "".join("{}" if x == DOL_CTRL else glyph_to_char(x & 0xFFF) or "?" for x in units)})
            start = i + 1
        assert len(out) == DOL_STRINGS, len(out)
        _dol_cache = out
    return _dol_cache


def dol_cells(en: str) -> int:
    """Units of a main.dol string: {} is one unit and the letter pairs start again behind it."""
    return en.count("{}") + sum(letters(part) for part in en.split("{}"))


def dol_need(english: Dict[Tuple[int, int], str]) -> Callable[[dict], int]:
    """A function giving the units a string takes with its 0xFFFF: the English where english = {(0, offset): English}
    has some, else the Japanese."""
    def need(s):
        en = english.get((0, s["offset"]))
        return (s["cells"] if en is None else dol_cells(en)) + 1
    return need


def dol_segments(strs: List[dict], need: Optional[Callable[[dict], int]] = None) -> List[Tuple[List[dict], int]]:
    """[(strings that can move, units of space for them)]: the runs between the fixed strings.

    need = dol_need(English): a fixed string that is shorter in English leaves the rest of its place to the strings
    behind it, as the build lays them out (default: the Japanese)."""
    need = need or dol_need({})
    out, run, start = [], [], DOL_BLOCK[0]
    for s in strs + [None]:
        if s is not None and not s["fixed"]:
            run.append(s)
            continue
        if run:
            out.append((run, ((s["offset"] if s else DOL_BLOCK[1]) - start) // 2))
        if s:
            run, start = [], s["offset"] + need(s) * 2
    return out


def dol_fit(strs: List[dict], english: Dict[Tuple[int, int], str]) -> List[str]:
    """Problems of the block as a whole (a list of messages; empty when it fits).
    english = {(0, offset): English}."""
    need = dol_need(english)
    out = []
    total, space = sum(need(s) for s in strs), (DOL_BLOCK[1] - DOL_BLOCK[0]) // 2
    if total > space:
        out.append("%s: all strings together need %d units, the block has %d: shorten %d cells (%d letters)"
                   % (DOL, total, space, total - space, (total - space) * 2))
    for run, room in dol_segments(strs, need):
        n = sum(need(s) for s in run)
        if n > room:
            done = [s for s in run if (0, s["offset"]) in english] or run
            out.append("0:%d..0:%d: these %d strings need %d units, there are %d up to the next fixed string: "
                       "shorten %d cells (%d letters) among the %d translated ones (0:%d..0:%d)"
                       % (run[0]["offset"], run[-1]["offset"], len(run), n, room, n - room, (n - room) * 2,
                          len(done), done[0]["offset"], done[-1]["offset"]))
    return out
