#!/usr/bin/env python3
"""Fixed-slot UI strings: the menu and system text that is not in the story scripts.

  ui_strings.py export [FILE ...]   Japanese strings to _work/strings/<file>.txt, with line layout
  ui_strings.py check FILE          validate "ID<tab>English" lines from stdin, write nothing
  ui_strings.py apply FILE          the same check, then store the lines (nothing if one fails)
  ui_strings.py set FILE ID TEXT    the English of one string ("" removes it)
  ui_strings.py merge               translation/strings/*.tsv -> _work/strings.json, with checks
  ui_strings.py status              translated / total per file

FILE is a module (scs_data.rel) or main.dol. ID is section:offset as in the export.

Besides the packed story text, the modules hold plain tables of 16-bit glyph numbers (big-endian):
a string is a run of glyphs padded with glyph 0 (a full-width space) and closed by 0xFFFF, in a slot
of fixed size (the command tooltips of scs_main.rel are 18 cells + 0xFFFF + 0). The English goes into
the same slot, two letters per cell with the pair font (see pair_font.py), so nothing moves and no
file grows: a slot of 18 cells holds 36 letters. `rebuild_scripts.py build` reads _work/strings.json
and writes the strings into the built modules.

A string is identified by file, section and section offset; translation/strings/<file>.tsv (in git)
holds section, offset, a hash of the original and the English, no Japanese. The Japanese lists stay
in _work/ (git-ignored).

What counts as a string: at least two kana or kanji (or listed in SHORT_TEXT), closed by 0xFFFF, outside the script region of
the script modules. The search also finds tables of glyph numbers that are not text (the name-entry
grids); those just stay untranslated (NOT_TEXT drops the ones of scs_data.rel and scs_item.rel, and
START_TRIM cuts binary data off the front of two strings).

Lines. Slots that hold two or three lines have no line-break code: the game wraps at the width of
the box and the Japanese pads each line with spaces. Write | for a new line in the English; the
tool pads every line but the last to the line width, so a line holds 2 x width letters and the last
line what is left of the slot (a slot of 41 cells in a box of 22: 44|38). The line width of a string
is found like this:
 1. LINE_WIDTH (one string) and LINE_CELLS (all slots of one size in a file) are overrides.
 2. The padding of a string is the end of its first run of two or more spaces that has text behind
    it (runs that end before cell 8 are spacing inside a line, no box is that narrow). When at
    least two padded strings near it (NEAR strings up or down the same table) are padded to half or
    a third of that, the smaller number counts: the first line was full and the run closed line 2.
    A table is a run of strings less than TABLE_GAP bytes apart.
 3. A padded string is confirmed when another padded string near it has the same width. Its width
    is its padding.
 4. Every other string takes the width of the nearest confirmed string before and after it
    (within NEAR): the smallest of them, and of its own padding if it has one. Without such a
    neighbour a padded string keeps its own padding and an unpadded string is one line.
 5. A string is marked uncertain ("?" in the export) when its width is a guess: its own padding
    disagrees with its neighbours or nothing confirms it, the neighbours before and after disagree,
    or the Japanese runs past the first line with no space in front of the break (a first line that
    exactly fills the box looks the same as one long line that the game wraps). A string that is
    not longer than one line of the box is never uncertain. More than MAX_LINES lines: not a text
    box, one line, uncertain.
The same rule gives the widths in LINE_CELLS (checked for the 3 x 17 tips, 2 x 18 system help,
2 x 16 title help, 2 x 14 rating comments); they stay listed because they were tested in the game.

Strings that can move (BLOCKS). The 24 entries of the schedule (scs_data.rel sec5+22308..22752) stand back to
back and each is reached through one R_PPC_ADDR32 of a pointer table right behind them. The build lays such a
block out again and rewrites the addends of the table, so an entry may be longer or shorter than its
Japanese: what counts is that all of them fit the block together, and that one entry is not wider than its
column ("max" cells). An entry that is the end of another one shares its cells ("Japan Champ Qual Final"
inside "Exam, Japan Champ Qual Final": start the shared part on an even letter).

main.dol holds the blue system dialogs (save prompts, memory notices): 264 strings back to back at
file offsets 0x143AA0..0x145ACE, each unit 0x1000 | glyph number, 0xFFFF ends a string, no slots and
no padding. Each string is one line of a dialog. 0x1FFD, shown as {}, is the blank cell of these
strings (the Japanese never uses glyph 0 here): it indents the menu options and the Yes/No and
"press A" rows, which come in copies with 1 to 9 and 1 to 12 of them in front. The English must
keep the same number of {}. Two spaces that fill a cell of the English become glyph 0 (0x1000),
which no Japanese dialog line uses. The IDs are 0:<file offset>. main_prg.rel has
a table of 252 pointers (relocations against module 0): 251 point at the start of a string, the
last one at a row of ten stars right behind the block. The 13 strings no relocation points at
cannot move ("fixed"): their English must fit the Japanese cell count. All others are laid out
again by the build and re-pointed, so a line may grow: at most to the longest Japanese line of the
block, with a warning from 4 cells over its own Japanese (the box was sized for the Japanese). The
strings between two fixed strings must fit the space between them, and all together the block
(a fixed string that is shorter in English leaves the rest of its place to the strings behind it).
check, merge and the build apply the same rules.
The untouched original is kept at _work/orig_sys/main.dol and strings are always read from there.
"""
import collections
import hashlib
import json
import os
import re
import shutil
import struct
import sys

import scan_story as S
from pawapuro15_text_tools import char_to_glyph, glyph_to_char

HERE = os.path.dirname(os.path.abspath(__file__))
TSV_DIR = os.path.join(HERE, "translation", "strings")
LIST_DIR = os.path.join(S.WORK_DIR, "strings")
OUT_JSON = os.path.join(S.WORK_DIR, "strings.json")
END = 0xFFFF
# Help texts of vs.rel (Exhibition menu, control setups): lines split by HELP_NL, closed by HELP_END (not 0xFFFF), a
# coloured first line allowed. English: "|" between lines, {c:...} for colour. Cells = units in front of HELP_END.
HELP_FILES = {"vs.rel", "gameplay.rel", "sct_card.rel", "sct_a_sy.rel"}   # also 0xFFFF strings with a HELP_NL inside
# Slots that may also use the alignment cell behind their 0xFFFF (a glyph 0 that ends on a 4-byte boundary): the
# pitching / batting form names of main_prg.rel whose English needs 9-10 letters. The build moves the 0xFFFF one cell on.
WIDE_SLOTS = {("main_prg.rel", 5, o) for o in (
    150532, 150688, 150736, 150748, 151000, 151024, 151756, 151860, 151920, 152152, 152256, 152852, 152900, 152936,
    153040, 153052, 153076, 153192, 153216, 153328, 153512, 153536, 154288)}
WIDE_SLOTS |= {("namein.rel", 5, o) for o in (24344, 24356, 24888, 24900, 24912, 25256, 25264, 25272, 25304, 25316, 25500, 25512, 26196, 26208, 26220, 26232, 26252, 26656, 26668, 27020, 27028, 27056, 27088, 27100, 27112, 27120, 27128, 27136, 27148, 27216, 27228, 27240, 27252, 27288, 27300, 27408, 27420, 27432, 27444, 27628, 28088, 28100, 28148, 28224, 28236, 28248, 28260, 28320, 28340, 28360, 28380, 28400, 28420, 28440, 28544, 28560, 28656, 28668, 28680, 28864, 28876, 29024, 29032, 29056, 29068, 29280, 29292, 29304, 29568, 29580, 29656, 29872, 29884, 30040, 30048, 30080, 30092, 30104, 30116, 30128, 30160, 30172, 30184, 30196, 30360, 30372, 30428, 30440, 30452, 30568, 30792, 30804, 30984, 30996, 31024, 31096, 31776, 31784, 31952, 31964, 32112, 32124, 32200, 32212, 32240, 32252, 32264, 32276, 32288, 32308, 32328, 32340, 32352, 32364, 32376, 32516, 32592, 32604, 32616, 32628, 32728, 32740, 32936, 32948, 32968, 33376, 33388, 33412, 33424, 33436, 33540, 33552, 33664, 33880, 33892, 33904, 33916, 33928, 33940, 33952, 34000, 34012, 34048, 34060, 34072, 34084, 34320,)}
WIDE_SLOTS |= {("are_main.rel", 5, o) for o in (124256, 124268, 124800, 124812, 124824, 125168, 125176, 125184, 125216, 125228, 125412, 125424, 126108, 126120, 126132, 126144, 126164, 126568, 126580, 126932, 126940, 126968, 127000, 127012, 127024, 127032, 127040, 127048, 127060, 127128, 127140, 127152, 127164, 127200, 127212, 127320, 127332, 127344, 127356, 127540, 128000, 128012, 128060, 128136, 128148, 128160, 128172, 128232, 128252, 128272, 128292, 128312, 128332, 128352, 128456, 128472, 128568, 128580, 128592, 128776, 128788, 128936, 128944, 128968, 128980, 129192, 129204, 129216, 129480, 129492, 129568, 129784, 129796, 129952, 129960, 129992, 130004, 130016, 130028, 130040, 130072, 130084, 130096, 130108, 130272, 130284, 130340, 130352, 130364, 130480, 130704, 130716, 130896, 130908, 130936, 131008, 131688, 131696, 131864, 131876, 132024, 132036, 132112, 132124, 132152, 132164, 132176, 132188, 132200, 132220, 132240, 132252, 132264, 132276, 132288, 132428, 132504, 132516, 132528, 132540, 132640, 132652, 132848, 132860, 132880, 133288, 133300, 133324, 133336, 133348, 133452, 133464, 133576, 133792, 133804, 133816, 133828, 133840, 133852, 133864, 133912, 133924, 133960, 133972, 133984, 133996, 134232,)}
WIDE_SLOTS |= {("scs_rens.rel", 5, o) for o in (12376, 12396, 12404, 12412)}   # Success cast names
HELP_NL, HELP_END = 0x1FFE, 0x1FFF
# Line width overrides. (file, cells of the slot) -> cells per line: tested in the game.
LINE_CELLS = {("scs_sys.rel", 36): 18, ("scs_titl.rel", 32): 16, ("scs_rens.rel", 28): 14,
              ("scs_main.rel", 51): 17, ("scs_main.rel", 33): 18, ("scs_main.rel", 44): 18}
# (file, section, offset) -> cells per line of one string, 0 = one line. For uncertain strings
# once the game has shown the answer.
LINE_WIDTH = {("main_prg.rel", 5, 90372): 23}   # boot controller screen: seen in game, 23 cells a line
TABLE_GAP = 64      # bytes between two strings of the same table, at most
NEAR = 8            # how many strings away a neighbour may be
MIN_WIDTH = 8       # padding that ends before this cell is not line padding
MAX_LINES = 4
# (file, section, offset as found) -> cells in front of the text that are other data
START_TRIM = {("scs_data.rel", 5, 106): 3, ("scs_data.rel", 5, 2148): 38,
              # a pointer of the module points at the cell where the text starts (_work/tl_bulk/pointer_check.py)
              ("main_prg.rel", 5, 174930): 7, ("school_g.rel", 5, 162498): 3, ("scs_end.rel", 5, 918): 9,
              ("arr_chg.rel", 5, 2972): 2, ("pn_fa.rel", 5, 106): 3,
              ("sct_a_pd.rel", 5, 106): 3}      # 右投 (the card's throwing hand), behind 3 cells of data
# number tables that look like strings
NOT_TEXT = {("scs_data.rel", 5, 1164), ("scs_data.rel", 5, 10002), ("scs_data.rel", 5, 17864),
            ("scs_data.rel", 5, 18946), ("scs_item.rel", 5, 1474), ("scs_item.rel", 5, 3822)}

# blocks of strings that the build lays out again: "table" = section offset of the pointer table, "count" its
# entries, "max" = cells one entry may take (the schedule column holds about 15 before the game icon)
BLOCKS = {"scs_data.rel": [{"section": 5, "start": 22308, "end": 22752, "table": 22756, "count": 24, "max": 15}]}

# strings of one character, which the search would not take for text: 月 and 週 of the schedule's date column
SHORT_TEXT = {("scs_data.rel", 5, 13824), ("scs_data.rel", 5, 13828)} | \
    {("sct_a_pd.rel", 5, o) for o in range(184, 212, 4)}      # Eikan player card: position letters 投捕一二三遊外

DOL = "main.dol"
DOL_SHA1 = "cd096d3bbfb5418316dad6e3035cba34a028f718"
DOL_SOURCE = os.path.join(HERE, "DATA", "sys", DOL)
DOL_ORIG = os.path.join(S.WORK_DIR, "orig_sys", DOL)
DOL_BLOCK = (0x143AA0, 0x145ACE)    # file offsets of the dialog strings, end exclusive
DOL_ADDRESS = 0x80003F00            # address - file offset in that part of main.dol
DOL_GLYPH, DOL_CTRL = 0x1000, 0x1FFD
DOL_STRINGS = 264
DOL_OVER = 3                        # cells a line may be longer than its Japanese without a warning


def text_hash(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:4]


def script_region(rel, mods):
    """(section, first byte, end byte) of the packed script of a script module, or None."""
    if rel.name not in S.SCRIPT_FILES:
        return None
    sc = S.Script(rel, mods)
    idx = sorted(sc.kind)
    return sc.sec, idx[0] * 2, (idx[-1] + 1) * 2


def help_text(units):
    """units_text of a help string, HELP_NL shown as |."""
    parts, cur = [], []
    for u in units:
        if u == HELP_NL:
            parts.append(cur)
            cur = []
        else:
            cur.append(u)
    parts.append(cur)
    return "|".join(units_text(p) for p in parts)


def find_help(rel):
    """The help strings of HELP_FILES (see HELP_END), each with "help": True."""
    out = []
    if rel.name not in HELP_FILES:
        return out
    for sec in rel.sections:
        if sec["exec"] or sec["bss"] or not sec["offset"] or sec["size"] < 4:
            continue
        d = rel.sec_data(sec["index"])
        hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        for k, u in enumerate(hw):
            if u not in (HELP_END, END):
                continue
            i = k
            while i > 0 and hw[i - 1] != 0 and (hw[i - 1] <= S.MAX_GLYPH or hw[i - 1] == HELP_NL
                                                 or is_coloured(hw[i - 1])):
                i -= 1
            units = hw[i:k]
            text = help_text(units)
            if HELP_NL in units and sum(0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF for c in text) >= 2:
                out.append({"section": sec["index"], "offset": i * 2, "cells": k - i, "units": list(units),
                            "text": text, "help": True})
    return out


# Strings that end a longer glyph run (a symbol table in front of them): their own slot from this offset to the 0xFFFF.
TAIL_SLOTS = {("sct_card.rel", 5, 3272)}                # 監督！ above the Eikan Nine command help ("Skip!")


def find_tails(rel):
    out = []
    for name, sec, off in TAIL_SLOTS:
        if name != rel.name:
            continue
        d = rel.sec_data(sec)
        hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        i = off // 2
        j = hw.index(END, i)
        out.append({"section": sec, "offset": off, "cells": j - i, "units": list(hw[i:j]), "text": units_text(hw[i:j])})
    return out


def find(rel, region=None):
    """[{"section", "offset", "cells", "units", "text"}] for every string slot of a module.
    cells = glyphs in front of the 0xFFFF, padding included: what an English string may fill."""
    helps = find_help(rel)
    out = helps + find_tails(rel)
    inside = {(h["section"], h["offset"] + 2 * n) for h in helps for n in range(1, h["cells"] + 1)}
    for sec in rel.sections:
        if sec["exec"] or sec["bss"] or not sec["offset"] or sec["size"] < 4:
            continue
        d = rel.sec_data(sec["index"])
        hw = struct.unpack(">%dH" % (len(d) // 2), d[:len(d) // 2 * 2])
        i = 0
        while i < len(hw):
            if region and region[0] == sec["index"] and region[1] <= i * 2 < region[2]:
                i = region[2] // 2
                continue
            if not (0 < hw[i] <= S.MAX_GLYPH):
                i += 1
                continue
            j = i
            while j < len(hw) and hw[j] <= S.MAX_GLYPH:
                j += 1
            k = j                                       # a coloured tail: glyph | colour << 12, then 0xFFFF
            while k < len(hw) and k - j < 64 and is_coloured(hw[k]) and hw[k] >> 12 == hw[j] >> 12:
                k += 1
            if k - j >= 2 and k < len(hw) and hw[k] == END and coloured_text_ok(hw[i:j], hw[j:k]):
                j = k
            if j < len(hw) and hw[j] == END:
                units = hw[i:j]
                text = units_text(units)
                if (sec["index"], i * 2) in inside:
                    pass
                elif sum(0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF for c in text) >= 2 \
                        or (rel.name, sec["index"], i * 2) in SHORT_TEXT:
                    wide = (rel.name, sec["index"], i * 2) in WIDE_SLOTS and j + 1 < len(hw) and hw[j + 1] == 0 \
                        and (j + 2) * 2 % 4 == 0
                    out.append({"section": sec["index"], "offset": i * 2, "cells": j - i + wide,
                                "units": list(units), "text": text})
            i = j + 1
    return out


def load_mods():
    orig = os.path.join(S.WORK_DIR, "orig")
    src = orig if os.path.isdir(orig) else S.DATA_FILES
    mods = {}
    for fn in sorted(os.listdir(src)):
        if fn.endswith(".rel"):
            r = S.Rel(os.path.join(src, fn))
            mods[r.mod_id] = r
    return mods


# ── Line layout ───────────────────────────────────────────────────────────

def used_cells(units):
    n = len(units)
    while n and units[n - 1] == 0:
        n -= 1
    return n


def padding(units):
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


def line_widths(name, found):
    """Adds "width" (cells per line, 0 = one line) and "uncertain" to the strings of a module.
    The rule is in the module docstring."""
    n = len(found)
    pad = [padding(s["units"]) for s in found]
    table, t = [], 0
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


def line_caps(s):
    """Cells of each line of a slot."""
    cells, width = s["cells"], s.get("width", 0)
    if not width:
        return [cells]
    return [width] * (cells // width) + ([cells % width] if cells % width else [])


def japanese_lines(s):
    """The Japanese with | where the game breaks the line, padding removed."""
    if s.get("width"):
        w, u = s["width"], s["units"]
        lines = [units_text(u[i:i + w]).rstrip("　") for i in range(0, len(u), w)]
        while len(lines) > 1 and not lines[-1]:
            lines.pop()
        return "|".join(lines)
    return s["text"]


# ── The strings of a file ─────────────────────────────────────────────────

_mods = None


def strings_of(name, mods=None):
    """The strings of a module or of main.dol, with their layout."""
    global _mods
    if name == DOL:
        return dol_strings()
    if mods is None:
        _mods = mods = _mods or load_mods()
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


def dol_data():
    """The untouched main.dol, from _work/orig_sys (copied there on first use)."""
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


_dol = None


def dol_strings():
    """The dialog strings of main.dol: like find(), plus "ctrl" (number of 0x1FFD) and "fixed"."""
    global _dol
    if _dol is None:
        data, (a, b) = dol_data(), DOL_BLOCK
        hw = struct.unpack_from(">%dH" % ((b - a) // 2), data, a)
        assert hw[-1] == END, "the dialog block of main.dol does not end with 0xFFFF"
        orig = os.path.join(S.WORK_DIR, "orig", "main_prg.rel")
        rel = S.Rel(orig if os.path.exists(orig) else os.path.join(S.DATA_FILES, "main_prg.rel"))
        targets = sorted(r[5] - DOL_ADDRESS for r in rel.relocs() if r[3] == 0 and a <= r[5] - DOL_ADDRESS < b)
        out, start = [], 0
        for i, u in enumerate(hw):
            if u != END:
                continue
            units, off = list(hw[start:i]), a + start * 2
            assert all(x == DOL_CTRL or (x & 0xF000 == DOL_GLYPH and x & 0xFFF <= S.MAX_GLYPH) for x in units), off
            inside = [x for x in targets if off <= x <= a + i * 2]
            out.append({"section": 0, "offset": off, "cells": len(units), "units": units,
                        "ctrl": units.count(DOL_CTRL), "fixed": inside != [off],
                        "text": "".join("{}" if x == DOL_CTRL else glyph_to_char(x & 0xFFF) or "?" for x in units)})
            start = i + 1
        assert len(out) == DOL_STRINGS, len(out)
        _dol = out
    return _dol


def dol_need(english):
    """english = {(0, offset): English} -> function: units a string takes with its 0xFFFF."""
    def need(s):
        en = english.get((0, s["offset"]))
        return (s["cells"] if en is None else dol_cells(en)) + 1
    return need


def dol_segments(strs, need=None):
    """[(strings that can move, units of space for them)]: the runs between the fixed strings.
    need = dol_need(English): a fixed string that is shorter in English leaves the rest of its
    place to the strings behind it, as the build lays them out (default: the Japanese)."""
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


def dol_fit(strs, english):
    """Problems of the block as a whole. english = {(0, offset): English}"""
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


# ── The English ───────────────────────────────────────────────────────────

def block_of(name, sec, off):
    """The block a string belongs to, or None."""
    for b in BLOCKS.get(name, ()):
        if b["section"] == sec and b["start"] <= off < b["end"]:
            return b
    return None


def block_layout(seqs):
    """Where the strings of a block go: ([start of each, in cells from the start of the block], cells used).
    seqs = the cells of every string (tuples, without the 0xFFFF), in the order of the pointer table. Strings
    are laid back to back, each closed by one cell; a string that is the end of another shares its cells."""
    host = {}
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


def block_fit(name, strs, english):
    """Problems (a list of text lines) if a block of `name` cannot hold its strings, English where there is
    some. english = {(section, offset): text}."""
    import pair_font
    problems = []
    for b in BLOCKS.get(name, ()):
        mine = sorted((s for s in strs if s.get("block") is b), key=lambda s: s["offset"])
        seqs = [tuple(pair_font.text_segments(english[(s["section"], s["offset"])]))
                if english.get((s["section"], s["offset"])) else tuple(s["units"][:s["cells"]]) for s in mine]
        used, room = block_layout(seqs)[1], (b["end"] - b["start"]) // 2
        if used > room:
            problems.append("%d:%d: the block is %d cells (%d letters) too full: %d of %d cells"
                            % (b["section"], b["start"], used - room, (used - room) * 2, used, room))
    return problems


def load_tsv(name):
    """{(section, offset): (hash, english)}"""
    rows = {}
    path = os.path.join(TSV_DIR, name + ".tsv")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    sec, off, h, en = line.rstrip("\n").split("\t", 3)
                    rows[(int(sec), int(off))] = (h, en)
    return rows


def save_tsv(name, rows):
    os.makedirs(TSV_DIR, exist_ok=True)
    with open(os.path.join(TSV_DIR, name + ".tsv"), "w", encoding="utf-8") as f:
        f.write("# section\toffset\thash of the original string\tEnglish (see ui_strings.py)\n")
        for key in sorted(rows):
            f.write("%d\t%d\t%s\t%s\n" % (key + rows[key]))


def letters(text):
    """Cells an English string takes: two ASCII letters per cell, other characters one each. A coloured
    run {6:...} starts its letter pairs again."""
    import pair_font
    return sum(len(pair_font.text_segments(part)) for _, part in colour_runs(text) if part)


# Coloured text. A few strings end in units with a colour in their top four bits (glyph | colour << 12:
# ore_ini.rel, the My Life title help lines end in プレイ年数：最大20年 in colour 6). The export shows such
# a run as {6:...}; the English writes it the same way and the build sets the colour on every unit of it.
COLOUR_RUN = re.compile(r"\{(\d{1,2}):([^{}]*)\}")


def is_coloured(u):
    return 0x1000 <= u < 0xF000 and (u & 0xFFF) <= S.MAX_GLYPH and glyph_to_char(u & 0xFFF) is not None


def coloured_text_ok(plain_units, tail):
    """A coloured tail counts only behind real text: the plain part has kana or kanji in most cells and
    the tail is kana, kanji, digits and punctuation of the font only."""
    def kind(u):
        c = glyph_to_char(u) or "?"
        return 2 if 0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF else \
            1 if c in "　、。！？：・ー（）０１２３４５６７８９" else 0
    body = [kind(u) for u in plain_units if u]
    tail = [kind(u & 0xFFF) for u in tail]
    return len(body) >= 4 and sum(k == 2 for k in body) * 4 >= len(body) * 3 and all(tail) and tail.count(2) >= 2


def units_text(units):
    """The text of a string's units, coloured runs as {colour:text}, trailing full-width spaces cut."""
    out, cur = [], None
    for u in units:
        c = u >> 12 if u > S.MAX_GLYPH else 0
        if c != cur:
            out.append("}" if cur else "")
            out.append("{%d:" % c if c else "")
            cur = c
        out.append(glyph_to_char(u & 0xFFF if c else u) or "?")
    if cur:
        out.append("}")
    text = "".join(out)
    return text.rstrip("　") if not cur else text


def colour_runs(text):
    """[(colour, text)] of a string with {colour:...} runs; colour 0 = plain."""
    out, pos = [], 0
    for m in COLOUR_RUN.finditer(text):
        out.append((0, text[pos:m.start()]))
        out.append((int(m.group(1)), m.group(2)))
        pos = m.end()
    out.append((0, text[pos:]))
    return [r for r in out if r[1]] or [(0, "")]


def plain(text):
    """The text with the colour marks taken out."""
    return COLOUR_RUN.sub(lambda m: m.group(2), text)


def dol_cells(en):
    """Units of a main.dol string: {} is one unit and the letter pairs start again behind it."""
    return en.count("{}") + sum(letters(part) for part in en.split("{}"))


def too_long(line, cap, count=letters):
    """How many letters a line is over its capacity of `cap` cells (0 = it fits)."""
    if line.isascii() and "{" not in line:
        return max(0, len(line) - cap * 2)
    return max(0, (count(line) - cap) * 2)


def pad_line(line, width):
    """A line filled up with spaces to `width` cells."""
    last = colour_runs(line)[-1][1]                     # the letter pairs start again in every coloured run
    tail = len(last) - len(last.rstrip("".join(map(chr, range(0x20, 0x7F)))))
    line += " " * (tail % 2)
    return line + "  " * (width - letters(line))


def judge(s, en, longest=0):
    """(errors, warnings, the English as the build takes it) for the English of one string."""
    errors, warnings = [], []
    if not en.strip():
        return ["empty English"], warnings, en
    bad = sorted({c for c in en if not 0x20 <= ord(c) <= 0x7E and char_to_glyph(c) is None})
    if bad or "\\n" in en:
        errors.append("the font cannot draw %s" % " ".join(["%r" % c for c in bad] + ["\\n"] * ("\\n" in en)))
        return errors, warnings, en
    lines = en.split("|")
    if "fixed" in s:                                    # main.dol: one line, no slot
        if len(lines) > 1:
            errors.append("%d lines, a dialog string is one line" % len(lines))
        if en.count("{}") != s["ctrl"]:
            errors.append("%d {} in the English, %d in the Japanese" % (en.count("{}"), s["ctrl"]))
        cells = dol_cells(en)
        if s["fixed"] and cells > s["cells"]:
            errors.append("%d letters too long: this string cannot move and holds %d cells (%d letters)"
                          % (too_long(en, s["cells"], dol_cells), s["cells"], (s["cells"] - s["ctrl"]) * 2))
        elif cells > longest:
            errors.append("%d letters too long: a line holds at most %d cells (%d letters), the longest "
                          "Japanese line" % (too_long(en, longest, dol_cells), longest, (longest - s["ctrl"]) * 2))
        elif cells > s["cells"] + DOL_OVER:
            warnings.append("%d cells, the Japanese has %d: the dialog box may be too narrow"
                            % (cells, s["cells"]))
        return errors, warnings, en
    if s.get("block"):                                  # a string the build moves: one line, no slot
        if len(lines) > 1:
            errors.append("%d lines, an entry of this list is one line" % len(lines))
        elif letters(en) > s["block"]["max"]:
            errors.append("%d letters too long: an entry holds at most %d cells (%d letters)"
                          % (too_long(en, s["block"]["max"]), s["block"]["max"], s["block"]["max"] * 2))
        return errors, warnings, en
    if s.get("help"):                                   # explicit line breaks (HELP_NL) in a slot of s["cells"] units
        jl = [re.sub(r"\{\d+:|\}", "", line) for line in s["text"].split("|")]
        width = max(len(line) for line in jl)            # the longest Japanese line, in cells
        if len(lines) > len(jl):
            errors.append("%d lines, the Japanese has %d" % (len(lines), len(jl)))
        need = len(lines) - 1
        for k, line in enumerate(lines):
            n = sum(-(-len(part) // 2) for _, part in colour_runs(line))
            need += n
            if n > width + 4:
                errors.append("line %d is %d cells, the longest Japanese line is %d" % (k + 1, n, width))
        if need > s["cells"]:
            errors.append("%d cells, the slot holds %d" % (need, s["cells"]))
        return errors, warnings, "\n".join(lines)
    caps = line_caps(s)
    if len(lines) > len(caps):
        errors.append("%d lines, the slot has %d (%s letters)"
                      % (len(lines), len(caps), "|".join(str(c * 2) for c in caps)))
        return errors, warnings, en
    for k, (line, cap) in enumerate(zip(lines, caps)):
        if too_long(line, cap):
            errors.append("line %d is %d letters too long (%d, it holds %d): %r"
                          % (k + 1, too_long(line, cap), len(line), cap * 2, line))
    if errors:
        return errors, warnings, en
    return errors, warnings, "".join(pad_line(line, s["width"]) for line in lines[:-1]) + lines[-1]


def check_rows(name, pairs):
    """pairs = [(ID, English)]. Returns (found, {(section, offset): English} of the good rows,
    problems, warnings); the last two are lists of "ID: text"."""
    strs = strings_of(name)
    found = {(s["section"], s["offset"]): s for s in strs}
    longest = max(s["cells"] for s in strs) if name == DOL else 0
    good, seen, problems, warnings = {}, set(), [], []
    for where, en in pairs:
        try:
            sec, off = (int(x) for x in where.split(":"))
        except ValueError:
            problems.append("%s: not an ID (section:offset)" % where)
            continue
        s = found.get((sec, off))
        if s is None:
            problems.append("%s: unknown ID" % where)
        elif (sec, off) in seen:
            problems.append("%s: duplicate ID" % where)
        else:
            seen.add((sec, off))
            errors, warns, _ = judge(s, en, longest)
            problems += ["%s: %s" % (where, e) for e in errors]
            warnings += ["%s: warning: %s" % (where, w) for w in warns]
            if not errors:
                good[(sec, off)] = en
    if name == DOL:                         # does the block still hold everything?
        english = {key: en for key, (_, en) in load_tsv(name).items()}
        english.update(good)
        problems += dol_fit(strs, english)
    elif name in BLOCKS:
        english = {key: en for key, (_, en) in load_tsv(name).items()}
        english.update(good)
        problems += block_fit(name, strs, english)
    return found, good, problems, warnings


def read_pairs():
    pairs = []
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line.strip() and not line.startswith("#"):
            pairs.append(tuple(line.split("\t", 1)) if "\t" in line else (line.strip(), ""))
    return pairs


def cmd_check(name, pairs, store=False):
    found, good, problems, warnings = check_rows(name, pairs)
    for line in problems + warnings:
        print(line)
    note = ", %d warnings" % len(warnings) if warnings else ""
    if problems:
        print("%s: %d problems in %d lines%s%s" % (name, len(problems), len(pairs), note,
                                               ", nothing stored" if store else ""))
        sys.exit(1)
    if store:
        rows = load_tsv(name)
        for key, en in good.items():
            rows[key] = (text_hash(found[key]["text"]), en)
        save_tsv(name, rows)
        print("%s: %d lines stored%s, %d of %d strings translated" % (name, len(pairs), note, len(rows), len(found)))
    else:
        print("%s: %d lines, no problems%s" % (name, len(pairs), note))


def cmd_set(name, where, en):
    if en:
        return cmd_check(name, [(where, en)], store=True)
    rows = load_tsv(name)
    sec, off = (int(x) for x in where.split(":"))
    if rows.pop((sec, off), None) is None:
        sys.exit("%s %s: not translated" % (name, where))
    if name == DOL:                         # the Japanese comes back: does the block still hold it?
        problems = dol_fit(dol_strings(), {key: en for key, (_, en) in rows.items()})
        if problems:
            sys.exit("\n".join(problems + ["%s %s: not removed, the Japanese line needs that room" % (name, where)]))
    save_tsv(name, rows)
    print("%s %s removed" % (name, where))


# ── Export, merge, status ─────────────────────────────────────────────────

HEADER = """# %s: one string per line, columns separated by tabs
# 1 ID        section:offset. Lines for check/apply are ID<tab>English.
# 2 cells     %s. One cell holds two letters, or one Japanese character.
# 3 capacity  %s
# 4 Japanese  %s
# 5 English   so far%s
"""
HEADER_REL = ("size of the slot",
              "letters each line holds, for example 44|38: two lines, 44 and 38 letters. A ? behind it: the line"
              "\n#             width is a guess (see ui_strings.py), check such a string in the game.",
              "with | where the game breaks the line (line padding removed)",
              "; | starts a new line, a line may be shorter and lines may be left out")
HEADER_DOL = ("length of the Japanese, each {} included",
              "soft/hard letters: beyond soft (3 cells over the Japanese) check warns, beyond hard it fails."
              "\n#             \"N fixed\": the string cannot move, N letters is all it holds. A {} is not counted,"
              "\n#             and letter pairs start again behind a {} (an odd run of letters wastes half a cell)."
              "\n#             The strings between two fixed ones share their space (the # lines): what one line"
              "\n#             grows, others must give back. check tells when it does not fit.",
              "one line of a blue system dialog. {} is a control code of the Yes/No rows: keep every {}.",
              "; always one line, no |")


def capacity(s, longest=0):
    if s.get("block"):
        return "%d movable" % (s["block"]["max"] * 2)
    if "fixed" not in s:
        return "|".join(str(c * 2) for c in line_caps(s)) + "?" * s["uncertain"]
    if s["fixed"]:
        return "%d fixed" % ((s["cells"] - s["ctrl"]) * 2)
    return "%d/%d" % ((min(s["cells"] + DOL_OVER, longest) - s["ctrl"]) * 2, (longest - s["ctrl"]) * 2)


def cmd_export(names):
    if not names:
        names = sorted(m.name for m in load_mods().values()) + [DOL]
    os.makedirs(LIST_DIR, exist_ok=True)
    total = 0
    for name in names:
        found = strings_of(name)
        path = os.path.join(LIST_DIR, name + ".txt")
        if not found:
            if os.path.exists(path):
                os.remove(path)
            continue
        done = load_tsv(name)
        longest = max(s["cells"] for s in found) if name == DOL else 0
        with open(path, "w", encoding="utf-8") as f:
            f.write(HEADER % ((name,) + (HEADER_DOL if name == DOL else HEADER_REL)))
            notes = {}
            if name == DOL:                 # the space each run of movable strings shares
                need = dol_need({key: en for key, (_, en) in done.items()})
                for run, room in dol_segments(found, need):
                    used = sum(need(s) for s in run)
                    notes[run[0]["offset"]] = ("# the %d strings from here to the next fixed string share %d units "
                                               "(cells + 1 per string); in use now: %d\n" % (len(run), room, used))
            for s in found:
                f.write(notes.get(s["offset"], ""))
                f.write("%d:%d\t%d\t%s\t%s\t%s\n" % (s["section"], s["offset"], s["cells"], capacity(s, longest),
                                                     japanese_lines(s), done.get((s["section"], s["offset"]), ("", ""))[1]))
        total += len(found)
        if name == DOL:
            print("%-14s %5d strings, %d fixed, longest line %d cells" % (name, len(found), sum(s["fixed"] for s in found), longest))
            continue
        lines = collections.Counter(len(line_caps(s)) for s in found)
        widths = collections.Counter(s["width"] for s in found if s["width"])
        unsure = ["%d:%d" % (s["section"], s["offset"]) for s in found if s["uncertain"]]
        print("%-14s %5d strings; lines %s; line widths %s; %d uncertain%s"
              % (name, len(found), ", ".join("%d: %d" % kv for kv in sorted(lines.items())),
                 ", ".join("%d cells: %d" % kv for kv in sorted(widths.items())) or "-",
                 len(unsure), (": " + " ".join(unsure)) if unsure else ""))
    print("%d strings -> %s" % (total, LIST_DIR))


def cmd_merge():
    entries, names = [], []
    if os.path.isdir(TSV_DIR):
        names = sorted(fn[:-4] for fn in os.listdir(TSV_DIR) if fn.endswith(".tsv"))
    for name in names:
        if name == DOL:
            continue
        found = {(s["section"], s["offset"]): s for s in strings_of(name)}
        for (sec, off), (h, en) in sorted(load_tsv(name).items()):
            s = found.get((sec, off))
            if s is None or text_hash(s["text"]) != h:
                sys.exit("%s %d:%d: the original string changed or is gone" % (name, sec, off))
            errors, _, en = judge(s, en)
            if errors:
                sys.exit("%s %d:%d: %s" % (name, sec, off, "; ".join(errors)))
            entries.append({"file": name, "section": sec, "offset": off, "cells": s["cells"], "en": en})
        problems = block_fit(name, found.values(), {key: en for key, (_, en) in load_tsv(name).items()})
        if problems:
            sys.exit("\n".join("%s %s" % (name, line) for line in problems))
    count = len(entries)
    if DOL in names or os.path.exists(DOL_ORIG) or os.path.exists(DOL_SOURCE):
        strs, rows = dol_strings(), load_tsv(DOL)
        found = {(0, s["offset"]): s for s in strs}
        longest = max(s["cells"] for s in strs)
        for key, (h, en) in sorted(rows.items()):
            s = found.get(key)
            if s is None or text_hash(s["text"]) != h:
                sys.exit("%s %d:%d: the original string changed or is gone" % ((DOL,) + key))
            errors, warnings, _ = judge(s, en, longest)
            if errors:
                sys.exit("%s %d:%d: %s" % (DOL, key[0], key[1], "; ".join(errors)))
            for w in warnings:
                print("%s %d:%d: warning: %s" % (DOL, key[0], key[1], w))
        problems = dol_fit(strs, {key: en for key, (_, en) in rows.items()})
        if problems:
            sys.exit("\n".join(problems))
        for s in strs:                      # all of them: the build lays the block out again
            entries.append({"file": DOL, "section": 0, "offset": s["offset"], "cells": s["cells"],
                            "en": rows.get((0, s["offset"]), (None, None))[1], "fixed": s["fixed"]})
        print("%s: %d of %d strings translated" % (DOL, len(rows), len(strs)))
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    print("%d strings -> %s" % (count, OUT_JSON))


def cmd_status():
    if os.path.isdir(TSV_DIR):
        for fn in sorted(os.listdir(TSV_DIR)):
            if fn.endswith(".tsv"):
                print("%-14s %5d / %d" % (fn[:-4], len(load_tsv(fn[:-4])), len(strings_of(fn[:-4]))))


def load_for_build():
    """{module name: {(section, offset): (cells, english)}} from _work/strings.json, for the build.
    Modules only: the main.dol entries come from load_dol_for_build()."""
    out = collections.defaultdict(dict)
    if os.path.exists(OUT_JSON):
        with open(OUT_JSON, encoding="utf-8") as f:
            for e in json.load(f):
                if e["file"] != DOL:
                    out[e["file"]][(e["section"], e["offset"])] = (e["cells"], e["en"])
    return out


def load_dol_for_build():
    """The main.dol entries of _work/strings.json, all 264 strings of the block in file order:
    [{"offset": file offset, "cells": units of the Japanese without its 0xFFFF, "en": English or
    None (keep the Japanese), "fixed": must stay at its offset}]. In "en", {} stands for one
    0x1FFD unit and the letter pairs start again behind it (dol_cells counts the units); every
    other unit is 0x1000 | glyph number. Empty when merge found no main.dol."""
    if not os.path.exists(OUT_JSON):
        return []
    with open(OUT_JSON, encoding="utf-8") as f:
        return [{k: e[k] for k in ("offset", "cells", "en", "fixed")} for e in json.load(f) if e["file"] == DOL]


def main():
    a = sys.argv[1:]
    if a[:1] == ["export"]:
        cmd_export(a[1:])
    elif a[:1] == ["set"] and len(a) == 4:
        cmd_set(a[1], a[2], a[3])
    elif a[:1] == ["check"] and len(a) == 2:
        cmd_check(a[1], read_pairs())
    elif a[:1] == ["apply"] and len(a) == 2:
        cmd_check(a[1], read_pairs(), store=True)
    elif a[:1] == ["merge"]:
        cmd_merge()
    elif a[:1] == ["status"]:
        cmd_status()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
