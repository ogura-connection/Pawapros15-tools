"""Finding the fixed-slot strings in the game's modules.

Besides the story dialogue, the modules (.rel files, see docs/GLOSSARY.md) hold plain tables of 16-bit glyph numbers,
big-endian: a string is a run of glyph numbers padded with glyph 0 (a full-width space) and closed by 0xFFFF, in a slot
of fixed size (the command tooltips of scs_main.rel are 18 cells + 0xFFFF + 0). The English goes into the same slot,
two letters per cell, so nothing moves and no file grows: a slot of 18 cells holds 36 letters.

What counts as a string: at least two kana or kanji (or listed in SHORT_TEXT), closed by 0xFFFF, outside the script
region of the script modules. The search also finds tables of glyph numbers that are not text; those just stay
untranslated (NOT_TEXT lists the known ones, START_TRIM cuts binary data off the front of a few strings).
Help texts (HELP_FILES) use 0x1FFF as the end and 0x1FFE as a line break; the colour of a string may sit in the top bits
of its units (colour_text.py).

Public names: strings_of(name, mods), find(rel, region), load_mods(), script_region(rel, mods).
Each string is a dict: "section", "offset" (bytes in the section), "cells" (glyphs in front of the 0xFFFF, padding
included: what the English may fill), "units", "text", and after strings_of also "width", "uncertain", maybe "block".
"""
import struct
import sys
from typing import Dict, List, Optional, Tuple

from pp15.glyphs import MAX_GLYPH
from pp15.script.rel import Rel, load_all_rels
from pp15.script.scripts import SCRIPT_FILES, Script
from pp15.text.colour_text import (MAX_COLOURED_TAIL, COLOUR_SHIFT, coloured_text_ok, is_coloured, is_kana_or_kanji,
                                   units_text)
from pp15.text.dol_dialogs import dol_strings
from pp15.text.line_layout import line_widths
from pp15.text.movable_blocks import block_of
from pp15.text.string_tables import (DOL, END, HELP_END, HELP_FILES, HELP_NL, NOT_TEXT, SHORT_TEXT, START_TRIM,
                                     TAIL_SLOTS, WIDE_SLOTS)

_mods_cache: Optional[Dict[int, Rel]] = None


def load_mods() -> Dict[int, Rel]:
    """Every .rel module of the game (the untouched originals once the build has run), {module id: Rel}."""
    return load_all_rels()


def script_region(rel: Rel, mods: Dict[int, Rel]) -> Optional[Tuple[int, int, int]]:
    """(section, first byte, end byte) of the packed script of a script module, or None for any other module."""
    if rel.name not in SCRIPT_FILES:
        return None
    sc = Script(rel, mods)
    idx = sorted(sc.kind)
    return sc.sec, idx[0] * 2, (idx[-1] + 1) * 2


def _halfwords(rel: Rel, section: int):
    """The section as a tuple of big-endian 16-bit values (a trailing odd byte is ignored)."""
    d = rel.sec_data(section)
    return struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])


def _is_japanese(text: str) -> bool:
    """True when the text has at least two kana or kanji."""
    return sum(is_kana_or_kanji(c) for c in text) >= 2


def help_text(units) -> str:
    """The text of a help string with HELP_NL (line break) shown as |."""
    parts, cur = [], []
    for u in units:
        if u == HELP_NL:
            parts.append(cur)
            cur = []
        else:
            cur.append(u)
    parts.append(cur)
    return "|".join(units_text(p) for p in parts)


def find_help(rel: Rel) -> List[dict]:
    """The help strings of HELP_FILES (see HELP_END), each with "help": True."""
    out = []
    if rel.name not in HELP_FILES:
        return out
    for sec in rel.sections:
        if sec["exec"] or sec["bss"] or not sec["offset"] or sec["size"] < 4:
            continue
        hw = _halfwords(rel, sec["index"])
        for k, u in enumerate(hw):
            if u not in (HELP_END, END):
                continue
            i = k
            while i > 0 and hw[i - 1] != 0 and (hw[i - 1] <= MAX_GLYPH or hw[i - 1] == HELP_NL
                                                 or is_coloured(hw[i - 1])):
                i -= 1
            units = hw[i:k]
            text = help_text(units)
            if HELP_NL in units and _is_japanese(text):
                out.append({"section": sec["index"], "offset": i * 2, "cells": k - i, "units": list(units),
                            "text": text, "help": True})
    return out


def find_tails(rel: Rel) -> List[dict]:
    """Strings listed in TAIL_SLOTS: they end a longer glyph run, so their slot is cut at the listed offset."""
    out = []
    for name, sec, off in TAIL_SLOTS:
        if name != rel.name:
            continue
        hw = _halfwords(rel, sec)
        i = off // 2
        j = hw.index(END, i)
        out.append({"section": sec, "offset": off, "cells": j - i, "units": list(hw[i:j]), "text": units_text(hw[i:j])})
    return out


def find(rel: Rel, region: Optional[Tuple[int, int, int]] = None) -> List[dict]:
    """Every string slot of a module: [{"section", "offset", "cells", "units", "text"}].

    region = script_region(): the stretch of packed story text to skip. cells = glyphs in front of the 0xFFFF,
    padding included: what an English string may fill."""
    helps = find_help(rel)
    out = helps + find_tails(rel)
    inside = {(h["section"], h["offset"] + 2 * n) for h in helps for n in range(1, h["cells"] + 1)}
    for sec in rel.sections:
        if sec["exec"] or sec["bss"] or not sec["offset"] or sec["size"] < 4:
            continue
        hw = _halfwords(rel, sec["index"])
        i = 0
        while i < len(hw):
            if region and region[0] == sec["index"] and region[1] <= i * 2 < region[2]:
                i = region[2] // 2
                continue
            if not (0 < hw[i] <= MAX_GLYPH):
                i += 1
                continue
            j = i
            while j < len(hw) and hw[j] <= MAX_GLYPH:
                j += 1
            k = j                                       # a coloured tail: glyph | colour << 12, then 0xFFFF
            while (k < len(hw) and k - j < MAX_COLOURED_TAIL and is_coloured(hw[k])
                   and hw[k] >> COLOUR_SHIFT == hw[j] >> COLOUR_SHIFT):
                k += 1
            if k - j >= 2 and k < len(hw) and hw[k] == END and coloured_text_ok(hw[i:j], hw[j:k]):
                j = k
            if j < len(hw) and hw[j] == END:
                units = hw[i:j]
                text = units_text(units)
                if (sec["index"], i * 2) in inside:
                    pass                                # part of a help string already found
                elif _is_japanese(text) or (rel.name, sec["index"], i * 2) in SHORT_TEXT:
                    # a slot flagged in WIDE_SLOTS may also use the alignment cell behind its 0xFFFF
                    wide = (rel.name, sec["index"], i * 2) in WIDE_SLOTS and j + 1 < len(hw) and hw[j + 1] == 0 \
                        and (j + 2) * 2 % 4 == 0
                    out.append({"section": sec["index"], "offset": i * 2, "cells": j - i + wide,
                                "units": list(units), "text": text})
            i = j + 1
    return out


def strings_of(name: str, mods: Optional[Dict[int, Rel]] = None) -> List[dict]:
    """The strings of a module (file name such as "scs_data.rel") or of main.dol ("main.dol"), with their layout.

    Exits with a message when there is no such module. mods = load_mods(); read once and cached when omitted."""
    global _mods_cache
    if name == DOL:
        return dol_strings()
    if mods is None:
        _mods_cache = mods = _mods_cache or load_mods()
    rel = next((m for m in mods.values() if m.name == name), None)
    if rel is None:
        sys.exit("%s: no such module (and not %s)" % (name, DOL))
    found = []
    for s in find(rel, script_region(rel, mods)):
        key = (name, s["section"], s["offset"])
        if key in NOT_TEXT:
            continue
        cut = START_TRIM.get(key)
        if cut:
            s["offset"], s["cells"], s["units"] = s["offset"] + cut * 2, s["cells"] - cut, s["units"][cut:]
            s["text"] = units_text(s["units"])
        found.append(s)
    found = line_widths(name, found)
    for s in found:
        b = block_of(name, s["section"], s["offset"])
        if b:
            s["block"] = b
    return found
