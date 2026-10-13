#!/usr/bin/env python3
"""Fixed-slot UI strings: the menu and system text that is not in the story scripts.

  ui_strings.py export [FILE ...]   Japanese strings of the modules to _work/strings/<file>.txt
  ui_strings.py set FILE OFFSET TEXT  the English of one string
  ui_strings.py apply FILE          read "OFFSET<tab>English" lines from stdin
  ui_strings.py merge               translation/strings/*.tsv -> _work/strings.json, with checks
  ui_strings.py status              translated / total per file

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
grids); those just stay untranslated.
"""
import collections
import hashlib
import json
import os
import struct
import sys

import scan_story as S
from pawapuro15_text_tools import glyph_to_char

HERE = os.path.dirname(os.path.abspath(__file__))
TSV_DIR = os.path.join(HERE, "translation", "strings")
LIST_DIR = os.path.join(S.WORK_DIR, "strings")
OUT_JSON = os.path.join(S.WORK_DIR, "strings.json")
END = 0xFFFF


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


def strings_of(name, mods):
    rel = next(m for m in mods.values() if m.name == name)
    return find(rel, script_region(rel, mods))


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


def cmd_export(names):
    mods = load_mods()
    names = names or sorted(m.name for m in mods.values())
    os.makedirs(LIST_DIR, exist_ok=True)
    total = 0
    for name in names:
        found = strings_of(name, mods)
        path = os.path.join(LIST_DIR, name + ".txt")
        if not found:
            if os.path.exists(path):
                os.remove(path)
            continue
        done = load_tsv(name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# section:offset\tcells (x2 = letters)\tJapanese\tEnglish so far\n")
            for s in found:
                f.write("%d:%d\t%d\t%s\t%s\n" % (s["section"], s["offset"], s["cells"], s["text"],
                                                 done.get((s["section"], s["offset"]), ("", ""))[1]))
        total += len(found)
        print("%-14s %5d strings" % (name, len(found)))
    print("%d strings -> %s" % (total, LIST_DIR))


def set_rows(name, pairs):
    """pairs = [("sec:offset", english)]. Checks that each string exists and fits."""
    mods = load_mods()
    found = {(s["section"], s["offset"]): s for s in strings_of(name, mods)}
    rows = load_tsv(name)
    for where, en in pairs:
        sec, off = (int(x) for x in where.split(":"))
        s = found.get((sec, off))
        if s is None:
            sys.exit("%s %s: no string there" % (name, where))
        if letters(en) > s["cells"]:
            sys.exit("%s %s: %r takes %d cells, the slot holds %d (%d letters)"
                     % (name, where, en, letters(en), s["cells"], s["cells"] * 2))
        if en == "":
            rows.pop((sec, off), None)
        else:
            rows[(sec, off)] = (text_hash(s["text"]), en)
    save_tsv(name, rows)
    print("%s: %d of %d strings translated" % (name, len(rows), len(found)))


def cmd_merge():
    mods = load_mods()
    entries = []
    if os.path.isdir(TSV_DIR):
        for fn in sorted(os.listdir(TSV_DIR)):
            if not fn.endswith(".tsv"):
                continue
            name = fn[:-4]
            found = {(s["section"], s["offset"]): s for s in strings_of(name, mods)}
            for (sec, off), (h, en) in sorted(load_tsv(name).items()):
                s = found.get((sec, off))
                if s is None or text_hash(s["text"]) != h:
                    sys.exit("%s %d:%d: the original string changed or is gone" % (name, sec, off))
                if letters(en) > s["cells"]:
                    sys.exit("%s %d:%d: %r does not fit %d cells" % (name, sec, off, en, s["cells"]))
                entries.append({"file": name, "section": sec, "offset": off, "cells": s["cells"], "en": en})
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    print("%d strings -> %s" % (len(entries), OUT_JSON))


def cmd_status():
    mods = load_mods()
    if os.path.isdir(TSV_DIR):
        for fn in sorted(os.listdir(TSV_DIR)):
            if fn.endswith(".tsv"):
                print("%-14s %5d / %d" % (fn[:-4], len(load_tsv(fn[:-4])), len(strings_of(fn[:-4], mods))))


def load_for_build():
    """{module name: {(section, offset): (cells, english)}} from _work/strings.json, for the build."""
    out = collections.defaultdict(dict)
    if os.path.exists(OUT_JSON):
        with open(OUT_JSON, encoding="utf-8") as f:
            for e in json.load(f):
                out[e["file"]][(e["section"], e["offset"])] = (e["cells"], e["en"])
    return out


def main():
    a = sys.argv[1:]
    if a[:1] == ["export"]:
        cmd_export(a[1:])
    elif a[:1] == ["set"] and len(a) == 4:
        set_rows(a[1], [(a[2], a[3])])
    elif a[:1] == ["apply"] and len(a) == 2:
        set_rows(a[1], [line.rstrip("\n").split("\t", 1) for line in sys.stdin if "\t" in line])
    elif a[:1] == ["merge"]:
        cmd_merge()
    elif a[:1] == ["status"]:
        cmd_status()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
