#!/usr/bin/env python3
"""
rebuild_scripts.py - rebuild the Success Mode scripts with new (longer or shorter) text

Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1). See FINDINGS.md for the format.

Text is stored inline in the scripts, so changing its length moves everything behind it.
This tool re-emits each script region and then fixes every reference to the moved data:

  - relocation addends in ALL modules that point into a rebuilt section (the label tables
    in scs_main.rel, the ADDR16_HA/LO pairs in code, pointers to the tables behind the script)
  - the positions of relocations that are applied inside a rebuilt section
  - the section size, relocation/import table offsets and fixSize in the REL header
  - the module's file size and memory size in moduleID2addr.o (see "Memory plan" below)

Memory plan: the game loads every module at a fixed address. /moduleID2addr.o on the disc holds
three tables (address, memory size, file size) and the game reads exactly "file size" bytes, so
a grown module that is not entered there loads truncated. In the original plan scs_main.rel ends
8 bytes before the scenario modules (scs_sce1/2/3.rel, one slot of 0x5D980 bytes). When that is
not enough the build moves the scenario slot to memory the plan leaves unused
(0x812CB800..0x814E0000, 2.1 MB) and scs_main.rel grows into the old slot (up to +383 KB).
The build stops if a module does not fit even then.

Translation file: a JSON list of entries in the format of _work/story_text.json
(scan_story.py extract --dump) with an added "en" field:
  {"file": "scs_sce1.rel", "section_offset": 25148, "text": "<original>", "en": "New text"}
"file" + "section_offset" identify the run, "text" (optional) is checked against the original,
"en" is the replacement. Use \\n for a line break inside the run. Entries without "en" are ignored.

English is stored two letters per glyph cell (see pair_font.py): every letter pair that occurs
gets a glyph slot of a kanji the remaining Japanese text does not use, and the build draws the
pairs into fonttex2.rel. A dialogue line is 17 cells, so 34 letters. Japanese characters in an
"en" text keep their own cell.

Original .rel files and moduleID2addr.o are kept in _work/orig/ (copied from DATA/files on first use, so the first
run must be on unpatched files). Built files are checked in _work/build/ before they are
installed to DATA/files. Both folders are game data: git-ignored, never commit them.
"""

import argparse
import collections
import filecmp
import json
import os
import shutil
import struct
import sys

import pair_font
import scan_story as S
from pawapuro15_text_tools import char_to_glyph

ORIG_DIR = os.path.join(S.WORK_DIR, "orig")
BUILD_DIR = os.path.join(S.WORK_DIR, "build")
R_NOP, R_SECTION, R_END = S.R_NOP, S.R_SECTION, S.R_END
SECTION_ALIGN = 8      # data behind a script keeps its alignment (REL header align = 8)
LINE_CELLS = 17        # width of the dialogue box (window type 29) in glyph cells
POPUP_WINDOW, POPUP_CELLS = 31, 30   # glossary pop-ups: the original lines run to about 31 cells
PLAN_FILE = "moduleID2addr.o"
# Memory plan. scs_main.rel is followed by the scenario slot, then by scs_load.rel / scs_face.rel.
# The game reserves everything below 0x814E0000 for modules (main.dol 0x8003A938 raises the OS
# arena to it) and its plan ends at 0x812CB794: the area in between is free.
MAIN, SCENARIOS = "scs_main.rel", ("scs_sce1.rel", "scs_sce2.rel", "scs_sce3.rel")
SCENARIO_SLOT = (0x80B5F880, 0x80BBD200)
FREE_AREA = (0x812CB800, 0x814E0000)

# ── English -> glyph units ────────────────────────────────────────────────

def encode_text(text, slots):
    """String -> list of 12-bit units. slots = {letter pair: glyph index}"""
    units = []
    for kind, value in pair_font.text_segments(text):
        if kind == "newline":
            units.append(S.TEXT_NEWLINE)
        elif kind == "pair":
            units.append(0 if value == "  " else slots[value])
        else:
            g = char_to_glyph(value)
            if g is None:
                raise ValueError("no glyph for %r in %r" % (value, text))
            units.append(g)
    return units


# ── REL relocation streams ────────────────────────────────────────────────

def parse_imports(data, imp_off, imp_size):
    """[(target module, stream offset, entries, stream end)], entries =
    [section, position, type, target section, addend, file offset of the entry]"""
    out = []
    for k in range(imp_size // 8):
        mod, off = struct.unpack_from(">II", data, imp_off + k * 8)
        start, sec, pos, entries = off, 0, 0, []
        while True:
            delta, typ, tsec, addend = struct.unpack_from(">HBBI", data, off)
            off += 8
            pos += delta
            if typ == R_END:
                break
            if typ == R_SECTION:
                sec, pos = tsec, 0
            elif typ != R_NOP:
                entries.append([sec, pos, typ, tsec, addend, off - 8])
        out.append((mod, start, entries, off))
    return out


def encode_stream(entries):
    out, cur_sec, cur = [], None, 0
    for sec, pos, typ, tsec, addend, _ in entries:
        if sec != cur_sec:
            out.append(struct.pack(">HBBI", 0, R_SECTION, sec, 0))
            cur_sec, cur = sec, 0
        delta = pos - cur
        assert delta >= 0, "relocations out of order"
        while delta > 0xFFFF:
            out.append(struct.pack(">HBBI", 0xFFFF, R_NOP, 0, 0))
            delta -= 0xFFFF
        out.append(struct.pack(">HBBI", delta, typ, tsec, addend))
        cur = pos
    out.append(struct.pack(">HBBI", 0, R_END, 0, 0))
    return b"".join(out)


# ── Script re-emission ────────────────────────────────────────────────────

class Remap:
    """Old section offset -> new section offset for one rebuilt script section."""

    def __init__(self, lo, hi, newidx, growth):
        self.lo, self.hi, self.newidx, self.growth = lo * 2, hi * 2, newidx, growth

    def __call__(self, off):
        if off < self.lo:
            return off
        if off >= self.hi:
            return off + self.growth
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2


def emit_script(sc, repl, pad=0):
    """Re-emit one script section. repl = {halfword index of the text instruction: units}.
    Returns (section bytes, Remap). pad = extra zero bytes at the end (memory headroom tests)."""
    hw = sc.hw
    lo, hi = min(sc.kind), max(sc.kind) + 1
    out, newidx, i = list(hw[:lo]), {}, lo
    while i < hi:
        newidx[i] = len(out)
        out.append(hw[i])
        if i in sc.texts:
            _, _, j = sc.texts[i]
            out += S.pack_text(repl[i]) if i in repl else hw[i + 1:j]
            i = j
        else:
            i += 1
    while (len(out) - hi) * 2 % SECTION_ALIGN:
        out.append(0)
    growth = (len(out) - hi) * 2
    out += hw[hi:]
    data = struct.pack(">%dH" % len(out), *out) + b"\0" * pad
    return data, Remap(lo, hi, newidx, growth)


# ── Memory plan (moduleID2addr.o) ─────────────────────────────────────────

def plan_tables(d):
    """File offsets of the three tables in the ELF object and their entry count."""
    shoff = struct.unpack_from(">I", d, 0x20)[0]
    shentsize, shnum = struct.unpack_from(">HH", d, 0x2E)
    secs = [struct.unpack_from(">10I", d, shoff + i * shentsize) for i in range(shnum)]
    symtab = next(s for s in secs if s[1] == 2)
    strtab = secs[symtab[6]][4]
    out = {}
    for k in range(symtab[5] // 16):
        name, value, size, _, _, shndx = struct.unpack_from(">IIIBBH", d, symtab[4] + k * 16)
        name = d[strtab + name:d.index(b"\0", strtab + name)].decode()
        if name.startswith("moduleID2") and shndx < shnum:
            out[name] = (secs[shndx][4] + value, size // 4)
    return out["moduleID2addr"][0], out["moduleID2size"][0], out["moduleID2relFileSize"][0], out["moduleID2addr"][1]


def memory_size(image):
    """Memory a module needs once linked: the part kept after linking, then its BSS."""
    bss_size, bss_align, fix_size = (struct.unpack_from(">I", image, o)[0] for o in (0x20, 0x44, 0x48))
    return (fix_size + bss_align - 1) // bss_align * bss_align + bss_size


def update_plan(plan, images):
    """images = {name: (original image, new image)} for the four script modules.
    Returns the new moduleID2addr.o."""
    d = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    index = {}
    for name, (old, _) in images.items():
        hits = [i for i in range(n) if struct.unpack_from(">I", plan, t_file + i * 4)[0] == len(old)
                and struct.unpack_from(">I", plan, t_size + i * 4)[0] == memory_size(old)]
        if len(hits) != 1:
            raise ValueError("%s: not found in the memory plan" % name)
        index[name] = hits[0]
    addr = {name: struct.unpack_from(">I", plan, t_addr + i * 4)[0] for name, i in index.items()}
    need = {name: memory_size(new) for name, (_, new) in images.items()}
    if addr[MAIN] + need[MAIN] > SCENARIO_SLOT[0] or \
            max(need[fn] for fn in SCENARIOS) > SCENARIO_SLOT[1] - SCENARIO_SLOT[0]:
        for fn in SCENARIOS:
            addr[fn] = FREE_AREA[0]
        print("  memory plan: scenario modules moved to 0x%08X, scs_main.rel may use their old slot" % FREE_AREA[0])
        limit = {MAIN: SCENARIO_SLOT[1], **{fn: FREE_AREA[1] for fn in SCENARIOS}}
    else:
        limit = {MAIN: SCENARIO_SLOT[0], **{fn: SCENARIO_SLOT[1] for fn in SCENARIOS}}
    for name, (old, new) in images.items():
        i, end = index[name], addr[name] + need[name]
        struct.pack_into(">I", d, t_addr + i * 4, addr[name])
        struct.pack_into(">I", d, t_size + i * 4, need[name])
        struct.pack_into(">I", d, t_file + i * 4, len(new))
        if end > limit[name]:
            sys.exit("%s does not fit in memory: it needs 0x%X bytes at 0x%08X, the limit is 0x%08X "
                     "(%d bytes too many)." % (name, need[name], addr[name], limit[name], end - limit[name]))
        if old != new:
            print("  %-13s 0x%08X..0x%08X, %d KB of room left" % (name, addr[name], end, (limit[name] - end) // 1024))
    return bytes(d)


# ── Build ─────────────────────────────────────────────────────────────────

def ensure_orig():
    if not os.path.isdir(ORIG_DIR):
        os.makedirs(ORIG_DIR)
        print("Saving the original files to %s" % ORIG_DIR)
    for fn in sorted(os.listdir(S.DATA_FILES)):
        if (fn.endswith(".rel") or fn == PLAN_FILE) and not os.path.exists(os.path.join(ORIG_DIR, fn)):
            shutil.copy2(os.path.join(S.DATA_FILES, fn), os.path.join(ORIG_DIR, fn))


def load_dir(*dirs):
    """Load every module, later directories overriding earlier ones. {module id: Rel}"""
    paths = {}
    for d in dirs:
        for fn in os.listdir(d):
            if fn.endswith(".rel"):
                paths[fn] = os.path.join(d, fn)
    mods = {}
    for fn in sorted(paths):
        r = S.Rel(paths[fn])
        mods[r.mod_id] = r
    return mods


def load_scripts(mods, remaps=None):
    """Parse the four script modules. remaps: the label tables have moved (rebuilt files)."""
    by_name = {m.name: m for m in mods.values()}
    main = by_name["scs_main.rel"]
    move = (remaps or {}).get((main.mod_id, main.script_section()), lambda off: off)
    tables = tuple(move(off) for off in S.LABEL_TABLES)
    return [S.Script(by_name[fn], mods, tables) for fn in S.SCRIPT_FILES]


def rebuild_module(rel, sec, new_sec, remaps):
    """New file image for a module whose section `sec` was re-emitted."""
    d = rel.data
    s = rel.sections[sec]
    sec_end = s["offset"] + s["size"]
    later = [t for t in rel.sections if t["offset"] > s["offset"]]
    if later or not sec_end <= rel.imp_off < sec_end + 32 or rel.imp_off + rel.imp_size != rel.rel_off:
        raise ValueError("%s: unexpected file layout" % rel.name)
    imports = parse_imports(d, rel.imp_off, rel.imp_size)
    spans = sorted((start, end) for _, start, _, end in imports)
    if spans[0][0] != rel.rel_off or any(a[1] != b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError("%s: relocation streams are not contiguous" % rel.name)
    tail = d[spans[-1][1]:]
    sec_table, fix_size = struct.unpack_from(">I", d, 0x10)[0], struct.unpack_from(">I", d, 0x48)[0]

    head = bytearray(d[:s["offset"]]) + new_sec + d[sec_end:rel.imp_off]
    struct.pack_into(">I", head, sec_table + sec * 8 + 4, len(new_sec))
    imp_off = len(head)
    rel_off = imp_off + rel.imp_size
    table, streams, off, new_fix = [], [], rel_off, None
    for mod, start, entries, _ in imports:
        for e in entries:
            if e[0] == sec:
                e[1] = remaps[(rel.mod_id, sec)](e[1])
            if (mod, e[3]) in remaps:
                e[4] = remaps[(mod, e[3])](e[4])
        blob = encode_stream(entries)
        if start == fix_size:
            new_fix = off
        table.append(struct.pack(">II", mod, off))
        streams.append(blob)
        off += len(blob)
    if new_fix is None:
        raise ValueError("%s: fixSize does not match a relocation stream" % rel.name)
    struct.pack_into(">II", head, 0x24, rel_off, imp_off)
    struct.pack_into(">I", head, 0x48, new_fix)
    return bytes(head) + b"".join(table) + b"".join(streams) + tail


def patch_addends(rel, remaps):
    """Other modules: addends that point into a rebuilt section, patched in place."""
    d, n = bytearray(rel.data), 0
    for mod, _, entries, _ in parse_imports(rel.data, rel.imp_off, rel.imp_size):
        for sec, pos, typ, tsec, addend, off in entries:
            if (mod, tsec) in remaps:
                new = remaps[(mod, tsec)](addend)
                if new != addend:
                    struct.pack_into(">I", d, off + 4, new)
                    n += 1
    return bytes(d), n


def load_translation(path, scripts):
    """{module name: {halfword index: new text}}"""
    by_name = {sc.rel.name: sc for sc in scripts}
    texts = collections.defaultdict(dict)
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    for e in entries:
        if e.get("en") is None:
            continue
        sc = by_name.get(e["file"])
        i = e["section_offset"] // 2
        if sc is None or e["section_offset"] % 2 or i not in sc.texts:
            sys.exit("%s +0x%X: not a text run" % (e["file"], e["section_offset"]))
        old = S.decode_units(sc.texts[i][1])
        if "text" in e and e["text"] != old:
            sys.exit("%s +0x%X: original text is %r, the translation file says %r"
                     % (e["file"], e["section_offset"], old, e["text"]))
        texts[e["file"]][i] = e["en"]
        cells, line = 0, 0
        for kind, _ in pair_font.text_segments(e["en"]):
            line = 0 if kind == "newline" else line + 1
            cells = max(cells, line)
        limit = POPUP_CELLS if sc.texts[i][0] == POPUP_WINDOW else LINE_CELLS
        if cells > limit:
            print("warning: %s +0x%X is %d cells wide, the line holds %d (%d letters): %r"
                  % (e["file"], e["section_offset"], cells, limit, limit * 2, e["en"]))
    return texts


def assign_pairs(scripts, texts, orig):
    """Choose a glyph slot for every letter pair in the translation. Returns {pair: glyph index}."""
    pairs, usage = set(), collections.Counter()
    for sc in scripts:
        new = texts.get(sc.rel.name, {})
        for i, (_, units, _) in sc.texts.items():
            if i not in new:
                usage.update(units)
                continue
            for kind, value in pair_font.text_segments(new[i]):
                if kind == "pair" and value != "  ":
                    pairs.add(value)
                elif kind == "char":
                    usage[char_to_glyph(value)] += 1
    if not pairs:
        return {}
    # namein.rel is the name-entry kanji picker: it lists every kanji once and is not text
    usage.update(pair_font.other_text_usage(orig, set(S.SCRIPT_FILES) | {"fonttex2.rel", "namein.rel"}))
    slots, taken = pair_font.allocate(pairs, usage)
    print("Font: %d letter pairs in %d kanji slots (%d slots left)%s"
          % (len(slots), len(slots), len(pair_font.KANJI_SLOTS) - len(slots),
             "" if not taken else "; %d of them are kanji that Japanese text elsewhere still uses" % taken))
    return slots


def build_font_file(orig, slots):
    """fonttex2.rel with the pair glyphs. The file keeps its size."""
    rel = next(m for m in orig.values() if m.name == "fonttex2.rel")
    cache_path, cache = os.path.join(S.WORK_DIR, "pair_glyphs.json"), {}
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            cache = json.load(f)
    known = len(cache)
    image = pair_font.build_font(rel.data, rel.sections[4]["offset"], {g: p for p, g in slots.items()}, cache)
    if len(cache) != known:
        with open(cache_path, "w") as f:
            json.dump(cache, f)
    sec4 = image[rel.sections[4]["offset"]:]
    for name, pos, _ in pair_font.FONTS:                       # read it back
        old = pair_font.font_glyphs(rel.sec_data(4), pos)
        new = pair_font.font_glyphs(sec4, pos)
        for pair, g in slots.items():
            assert new[g] == pair_font.pair_glyph(pair, name == "large", cache), pair
        assert all(a == b for g, (a, b) in enumerate(zip(old, new)) if g not in set(slots.values())), name
    assert len(image) == len(rel.data)
    return image


def build(texts, pad=None):
    """Build every changed module into _work/build/. Returns the list of file names."""
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig)
    for sc in scripts:
        if sc.errors or len(sc.hw) * 2 != sc.rel.sections[sc.sec]["size"]:
            sys.exit("%s: script does not parse cleanly, not rebuilding" % sc.rel.name)
    slots = assign_pairs(scripts, texts, orig)
    repl = {name: {i: encode_text(t, slots) for i, t in runs.items()} for name, runs in texts.items()}
    remaps, new_secs = {}, {}
    for sc in scripts:
        r = repl.get(sc.rel.name, {})
        p = (pad or {}).get(sc.rel.name, 0)
        if not r and not p:
            continue
        data, remap = emit_script(sc, r, p)
        remaps[(sc.rel.mod_id, sc.sec)] = remap
        new_secs[sc.rel.mod_id] = (sc.sec, data)
        print("%-13s %5d runs replaced, script section 0x%X -> 0x%X bytes (data behind it moves %+d)"
              % (sc.rel.name, len(r), sc.rel.sections[sc.sec]["size"], len(data), remap.growth))
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    os.makedirs(BUILD_DIR)
    changed, images = [], {sc.rel.name: (sc.rel.data, sc.rel.data) for sc in scripts}
    for m in orig.values():
        if m.name == "fonttex2.rel" and slots:
            image, note = build_font_file(orig, slots), "%d glyphs replaced in both fonts" % len(slots)
        elif m.mod_id in new_secs:
            sec, data = new_secs[m.mod_id]
            image, note = rebuild_module(m, sec, data, remaps), "rebuilt"
            images[m.name] = (m.data, image)
        else:
            image, n = patch_addends(m, remaps)
            note = "%d addends" % n
        if image != m.data:
            with open(os.path.join(BUILD_DIR, m.name), "wb") as f:
                f.write(image)
            changed.append(m.name)
            print("  %-13s %s, 0x%X -> 0x%X bytes" % (m.name, note, len(m.data), len(image)))
    with open(os.path.join(ORIG_DIR, PLAN_FILE), "rb") as f:
        plan = f.read()
    new_plan = update_plan(plan, images)
    if new_plan != plan:
        with open(os.path.join(BUILD_DIR, PLAN_FILE), "wb") as f:
            f.write(new_plan)
        changed.append(PLAN_FILE)
    verify(orig, scripts, repl, remaps)
    return changed


def verify(orig, old_scripts, repl, remaps):
    """Re-read the built files and compare them with the originals, structure by structure."""
    new = load_dir(ORIG_DIR, BUILD_DIR)
    new_scripts = load_scripts(new, remaps)
    for old, sc in zip(old_scripts, new_scripts):
        name = old.rel.name
        remap = remaps.get((old.rel.mod_id, old.sec), lambda off: off)
        assert not sc.errors, (name, sc.errors)
        # same instructions at the mapped positions, same labels, same text except replacements
        assert {remap(i * 2) // 2 for i, k in old.kind.items() if k == "op"} == \
               {i for i, k in sc.kind.items() if k == "op"}, name + ": instructions moved"
        assert collections.Counter({remap(i * 2) // 2: n for i, n in old.labels.items()}) == sc.labels, \
            name + ": labels differ"
        assert old.op_count == sc.op_count and len(old.texts) == len(sc.texts), name
        for i, (window, units, _) in old.texts.items():
            w2, u2, _ = sc.texts[remap(i * 2) // 2]
            assert w2 == window and u2 == repl.get(name, {}).get(i, units), "%s: text at 0x%X" % (name, i * 2)
    # every relocation: same kind and target, positions and addends moved exactly as mapped
    for mid, m in orig.items():
        a, b = m.relocs(), new[mid].relocs()
        assert len(a) == len(b), m.name
        for (s, pos, typ, tm, ts, ad), (s2, pos2, typ2, tm2, ts2, ad2) in zip(a, b):
            pos = remaps[(mid, s)](pos) if (mid, s) in remaps else pos
            ad = remaps[(tm, ts)](ad) if (tm, ts) in remaps else ad
            assert (s, pos, typ, tm, ts, ad) == (s2, pos2, typ2, tm2, ts2, ad2), \
                "%s: relocation sec%d+0x%X" % (m.name, s, pos)
        # everything in front of a rebuilt section, and the data behind the script, is untouched
        for t, t2 in zip(m.sections, new[mid].sections):
            if (mid, t["index"]) in remaps:
                r = remaps[(mid, t["index"])]
                assert m.sec_data(t["index"])[r.hi:] == \
                    new[mid].sec_data(t["index"])[r.hi + r.growth:r.growth + t["size"]], m.name + ": tail"
            elif m.name != "fonttex2.rel":          # the font is checked in build_font_file()
                assert m.sec_data(t["index"]) == new[mid].sec_data(t["index"]), m.name + ": section data"
    print("Verified: scripts re-parse, labels, text and all relocations match the originals.")


def install(changed):
    """DATA/files = originals + built files."""
    n = 0
    for fn in sorted(os.listdir(ORIG_DIR)):
        src = os.path.join(BUILD_DIR if fn in changed else ORIG_DIR, fn)
        dst = os.path.join(S.DATA_FILES, fn)
        if not filecmp.cmp(src, dst, shallow=False):
            shutil.copy2(src, dst)
            n += 1
    print("Installed: %d file(s) written to DATA/files (%d differ from the originals)." % (n, len(changed)))


def cmd_check(args):
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig)
    bad = 0
    for sc in scripts:
        data, remap = emit_script(sc, {})
        remaps = {(sc.rel.mod_id, sc.sec): remap}
        image = rebuild_module(sc.rel, sc.sec, data, remaps)
        ok = image == sc.rel.data and remap.growth == 0
        bad += not ok
        print("%-13s rebuilt with no changes: %s" % (sc.rel.name, "identical" if ok else "DIFFERENT"))
    n = 0
    for m in orig.values():
        for mod, start, entries, end in parse_imports(m.data, m.imp_off, m.imp_size):
            n += 1
            if encode_stream(entries) != m.data[start:end]:
                bad += 1
                print("%-13s relocation stream for module %d does not re-encode identically" % (m.name, mod))
    print("%d relocation streams in %d modules re-encoded" % (n, len(orig)))
    with open(os.path.join(ORIG_DIR, PLAN_FILE), "rb") as f:
        plan = f.read()
    same = update_plan(plan, {sc.rel.name: (sc.rel.data, sc.rel.data) for sc in scripts}) == plan
    bad += not same
    print("memory plan (%s): %s" % (PLAN_FILE, "entries found and unchanged" if same else "DIFFERENT"))
    font = next(m for m in orig.values() if m.name == "fonttex2.rel")
    for name, pos, _ in pair_font.FONTS:
        glyphs = pair_font.font_glyphs(font.sec_data(4), pos)
        size = pair_font.FONT_END[pos] - pos
        used = 4 + 4 * len(glyphs) + sum(map(len, glyphs))
        ok = pair_font.pack_font(glyphs, size)[:used] == font.sec_data(4)[pos:pos + used] and all(
            pair_font.decompress(pair_font.compress(pair_font.decompress(g)[0]))[0] == pair_font.decompress(g)[0]
            for g in glyphs)
        bad += not ok
        print("%s font: %d glyphs repacked and recompressed: %s" % (name, len(glyphs), "identical" if ok else "DIFFERENT"))
    sys.exit("FAILED" if bad else None)


def cmd_build(args):
    scripts = load_scripts(load_dir(ORIG_DIR))
    texts = load_translation(args.json, scripts)
    pad = {}
    for item in args.pad or []:
        name, size = item.split("=")
        pad[name] = int(size, 0)
    install(build(texts, pad))


def cmd_restore(args):
    install([])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check", help="round-trip test, no files are changed").set_defaults(func=cmd_check)
    p = sub.add_parser("build", help="apply a translation file and install the result")
    p.add_argument("json", nargs="?", default=os.path.join(S.WORK_DIR, "translation.json"))
    p.add_argument("--pad", action="append", metavar="FILE=BYTES",
                   help="test only: add empty space to a script module, e.g. scs_main.rel=0x80000")
    p.set_defaults(func=cmd_build)
    sub.add_parser("restore", help="put the original files back").set_defaults(func=cmd_restore)
    args = ap.parse_args()
    if not args.cmd:
        return ap.print_help()
    if not os.path.isdir(S.DATA_FILES):
        sys.exit("Game files not found at %s" % S.DATA_FILES)
    ensure_orig()
    args.func(args)


if __name__ == "__main__":
    main()
