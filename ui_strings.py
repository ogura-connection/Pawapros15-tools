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

What counts as a string: at least two kana or kanji, closed by 0xFFFF, outside the script region of
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

main.dol holds the blue system dialogs (save prompts, memory notices): 264 strings back to back at
file offsets 0x143AA0..0x145ACE, each unit 0x1000 | glyph number, 0xFFFF ends a string, no slots and
no padding. Each string is one line of a dialog. 0x1FFD is a control unit of the Yes/No rows, shown
as {} ; the English must keep the same number of {}. The IDs are 0:<file offset>. main_prg.rel has
a table of 252 pointers (relocations against module 0): 251 point at the start of a string, the
last one at a row of ten stars right behind the block. The 13 strings no relocation points at
cannot move ("fixed"): their English must fit the Japanese cell count. All others are laid out
again by the build and re-pointed, so a line may grow: at most to the longest Japanese line of the
block, with a warning from 4 cells over its own Japanese (the box was sized for the Japanese). The
strings between two fixed strings must fit the space between them, and all together the block.
The untouched original is kept at _work/orig_sys/main.dol and strings are always read from there.
"""
import collections
import hashlib
import json
import os
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
# Line width overrides. (file, cells of the slot) -> cells per line: tested in the game.
LINE_CELLS = {("scs_sys.rel", 36): 18, ("scs_titl.rel", 32): 16, ("scs_rens.rel", 28): 14,
              ("scs_main.rel", 51): 17, ("scs_main.rel", 33): 18, ("scs_main.rel", 44): 18}
# (file, section, offset) -> cells per line of one string, 0 = one line. For uncertain strings
# once the game has shown the answer.
LINE_WIDTH = {}
TABLE_GAP = 64      # bytes between two strings of the same table, at most
NEAR = 8            # how many strings away a neighbour may be
MIN_WIDTH = 8       # padding that ends before this cell is not line padding
MAX_LINES = 4
# (file, section, offset as found) -> cells in front of the text that are other data
START_TRIM = {("scs_data.rel", 5, 106): 3, ("scs_data.rel", 5, 2148): 38}
# number tables that look like strings
NOT_TEXT = {("scs_data.rel", 5, 1164), ("scs_data.rel", 5, 10002), ("scs_data.rel", 5, 17864),
            ("scs_data.rel", 5, 18946), ("scs_item.rel", 5, 1474), ("scs_item.rel", 5, 3822)}

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


def find(rel, region=None):
    """[{"section", "offset", "cells", "units", "text"}] for every string slot of a module.
    cells = glyphs in front of the 0xFFFF, padding included: what an English string may fill."""
    out = []
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
            if j < len(hw) and hw[j] == END:
                units = hw[i:j]
                text = "".join(glyph_to_char(u) or "?" for u in units).rstrip("　")
                if sum(0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF for c in text) >= 2:
                    out.append({"section": sec["index"], "offset": i * 2, "cells": j - i,
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
        chars = [glyph_to_char(u) or "?" for u in s["units"]]
        lines = ["".join(chars[i:i + s["width"]]).rstrip("　") for i in range(0, len(chars), s["width"])]
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
            s["text"] = "".join(glyph_to_char(u) or "?" for u in s["units"]).rstrip("　")
        found.append(s)
    return line_widths(name, found)


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


def dol_segments(strs):
    """[(strings that can move, units of space for them)]: the runs between the fixed strings."""
    out, run, start = [], [], DOL_BLOCK[0]
    for s in strs + [{"fixed": True, "offset": DOL_BLOCK[1], "cells": -1}]:
        if not s["fixed"]:
            run.append(s)
            continue
        if run:
            out.append((run, (s["offset"] - start) // 2))
        run, start = [], s["offset"] + s["cells"] * 2 + 2
    return out


def dol_fit(strs, english):
    """Problems of the block as a whole. english = {(0, offset): English}"""
    def need(s):
        en = english.get((0, s["offset"]))
        return (s["cells"] if en is None else dol_cells(en)) + 1
    out = []
    total, space = sum(need(s) for s in strs), (DOL_BLOCK[1] - DOL_BLOCK[0]) // 2
    if total > space:
        out.append("%s: all strings together need %d units, the block has %d: shorten %d cells (%d letters)"
                   % (DOL, total, space, total - space, (total - space) * 2))
    for run, room in dol_segments(strs):
        n = sum(need(s) for s in run)
        if n > room:
            done = [s for s in run if (0, s["offset"]) in english]
            out.append("0:%d..0:%d: these %d strings need %d units, there are %d up to the next fixed string: "
                       "shorten %d cells (%d letters) among the %d translated ones (0:%d..0:%d)"
                       % (run[0]["offset"], run[-1]["offset"], len(run), n, room, n - room, (n - room) * 2,
                          len(done), done[0]["offset"], done[-1]["offset"]))
    return out


# ── The English ───────────────────────────────────────────────────────────

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
    """Cells an English string takes: two ASCII letters per cell, other characters one each."""
    import pair_font
    return len(pair_font.text_segments(text))


def dol_cells(en):
    """Units of a main.dol string: {} is one unit and the letter pairs start again behind it."""
    return en.count("{}") + sum(letters(part) for part in en.split("{}"))


def too_long(line, cap):
    """How many letters a line is over its capacity of `cap` cells (0 = it fits)."""
    if line.isascii() and "{}" not in line:
        return max(0, len(line) - cap * 2)
    return max(0, (dol_cells(line) - cap) * 2)


def pad_line(line, width):
    """A line filled up with spaces to `width` cells."""
    tail = len(line) - len(line.rstrip("".join(map(chr, range(0x20, 0x7F)))))
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
                          % (too_long(en, s["cells"]), s["cells"], (s["cells"] - s["ctrl"]) * 2))
        elif cells > longest:
            errors.append("%d letters too long: a line holds at most %d cells (%d letters), the longest "
                          "Japanese line" % (too_long(en, longest), longest, (longest - s["ctrl"]) * 2))
        elif cells > s["cells"] + DOL_OVER:
            warnings.append("%d cells, the Japanese has %d: the dialog box may be too narrow"
                            % (cells, s["cells"]))
        return errors, warnings, en
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
    good, problems, warnings = {}, [], []
    for where, en in pairs:
        try:
            sec, off = (int(x) for x in where.split(":"))
        except ValueError:
            problems.append("%s: not an ID (section:offset)" % where)
            continue
        s = found.get((sec, off))
        if s is None:
            problems.append("%s: unknown ID" % where)
        elif (sec, off) in good:
            problems.append("%s: duplicate ID" % where)
        else:
            errors, warns, _ = judge(s, en, longest)
            problems += ["%s: %s" % (where, e) for e in errors]
            warnings += ["%s: warning: %s" % (where, w) for w in warns]
            if not errors:
                good[(sec, off)] = en
    if name == DOL and not problems:        # does the block still hold everything?
        english = {key: en for key, (_, en) in load_tsv(name).items()}
        english.update(good)
        problems += dol_fit(strs, english)
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
    save_tsv(name, rows)
    print("%s %s removed" % (name, where))


# ── Export, merge, status ─────────────────────────────────────────────────

HEADER = """# %s: one string per line, columns separated by tabs
# 1 ID        section:offset. Lines for check/apply are ID<tab>English.
# 2 cells     size of the slot. One cell holds two letters, or one Japanese character.
# 3 capacity  %s
# 4 Japanese  %s
# 5 English   so far; | starts a new line
"""
HEADER_REL = ("letters each line holds, for example 44|38: two lines, 44 and 38 letters. A ? behind it: the line"
              "\n#             width is a guess (see ui_strings.py), check such a string in the game.",
              "with | where the game breaks the line (line padding removed)")
HEADER_DOL = ("soft/hard letters: beyond soft (3 cells over the Japanese) check warns, beyond hard it fails."
              "\n#             \"N fixed\": the string cannot move, N letters is all it holds. A {} is not counted,"
              "\n#             and letter pairs start again behind a {} (an odd run of letters wastes half a cell)."
              "\n#             The strings between two fixed ones must also fit together: check tells.",
              "one line of a blue system dialog. {} is a control code of the Yes/No rows: keep every {}.")


def capacity(s, longest=0):
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
            for s in found:
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
