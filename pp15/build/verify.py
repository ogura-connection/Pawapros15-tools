"""Re-read the built modules and prove they match the originals, structure by structure.

What it is for: the build writes new files into _work/build/. Before anything is installed this module loads the
originals and the built files again, from disk, and checks that: every script still parses with the same
instructions and labels, text differs only where a translation was applied, every relocation has the same kind and
target with its position and address moved exactly as mapped, and everything outside the changed regions is
byte-for-byte untouched. A failed check stops the build with an AssertionError.

Public functions:
    verify(...)   -> the built modules as re-read (main.dol is checked afterwards by dol_block.verify_dol)
"""
import collections

from pp15 import config
from pp15.build.module_files import load_dir, load_scripts
from pp15.script import scan

ORIG_DIR = config.ORIG_DIR
BUILD_DIR = config.BUILD_DIR


def _expected_section(module, idx: int, patched: dict) -> bytes:
    """Section `idx` of the original module with the in-place changes of `patched` ({(section, offset): bytes}) written in."""
    d = bytearray(module.sec_data(idx))
    for (sec, off), data in patched.get(module.mod_id, {}).items():
        if sec == idx:
            d[off:off + len(data)] = data
    return bytes(d)


def _verify_scripts(old_scripts, new_scripts, repl, remaps, inplace, by_script) -> None:
    """Same instructions at the mapped positions, same labels, same text except the replacements."""
    for old, sc in zip(old_scripts, new_scripts):
        name = old.rel.name
        remap = remaps.get((old.rel.mod_id, old.sec)) or inplace.get((old.rel.mod_id, old.sec), lambda off: off)
        ore = by_script.get((old.rel.mod_id, old.sec))
        if ore and old is ore["sc"]:
            remap = ore["remap"]
        assert not sc.errors, (name, sc.errors)
        assert {remap(i * 2) // 2 for i, k in old.kind.items() if k == "op"} == \
               {i for i, k in sc.kind.items() if k == "op"}, name + ": instructions moved"
        assert collections.Counter({remap(i * 2) // 2: n for i, n in old.labels.items()}) == sc.labels, \
            name + ": labels differ"
        assert old.op_count == sc.op_count and len(old.texts) == len(sc.texts), name
        for i, (window, units, _) in old.texts.items():
            w2, u2, _ = sc.texts[remap(i * 2) // 2]
            assert w2 == window and u2 == repl.get(name, {}).get(i, units), "%s: text at 0x%X" % (name, i * 2)


def _expected_relocations(relocs, mid, remaps, inplace, moved, by_script) -> list:
    """The relocations of module `mid` as they must read after the build, given the original ones."""
    want = []
    for (s, pos, typ, tm, ts, ad) in relocs:
        pos = remaps[(mid, s)](pos) if (mid, s) in remaps else pos
        ad = remaps[(tm, ts)](ad) if (tm, ts) in remaps else ad
        ad = inplace[(tm, ts)](ad) if (tm, ts) in inplace else ad
        ad = (moved or {}).get((mid, s, pos), ad)
        ore = by_script.get((tm, ts))
        if ore:
            ad = ore["remap"](ad)                   # a label of a script of the My Life kind
            if ore["remap"].address(ad) is not None:
                tm, ts, ad = 0, 4, ore["remap"].address(ad)     # in the annex: an absolute address
        want.append((s, pos, typ, tm, ts, ad))
    return want


def verify(orig: dict, old_scripts: list, repl: dict, remaps: dict, patched: dict | None = None,
           moved: dict | None = None, inplace: dict | None = None, blocks=(), ores=(), dropped=()) -> dict:
    """Re-read the built files and compare them with the originals.

    orig = the original modules; old_scripts, blocks = the original Success Mode and block scripts; repl = the
    units of every replaced text; remaps = how rebuilt sections moved; patched = in-place byte changes
    {module id: {(section, offset): bytes}}; moved = relocations whose address the build changed on purpose
    (pointers to strings that were laid out again) {(module, section, position): addend}; inplace = remaps of
    block scripts; ores = the My Life scripts; dropped = relocations turned into R_NOP.
    Returns the modules as re-read (for dol_block.verify_dol).
    """
    new = load_dir(ORIG_DIR, BUILD_DIR)
    inplace = inplace or {}
    by_script = {(o["sc"].rel.mod_id, o["sc"].sec): o for o in ores}     # scripts of the My Life kind
    new_scripts = load_scripts(new, remaps) + scan.load_block_scripts(new)
    _verify_scripts(list(old_scripts) + list(blocks), new_scripts, repl, remaps, inplace, by_script)
    # every relocation: same kind and target, positions and addends moved exactly as mapped
    for mid, m in orig.items():
        a, b = [r for r in m.relocs() if (mid, r[0], r[1]) not in dropped], new[mid].relocs()   # dropped: now NOP
        assert len(a) == len(b), m.name
        want = _expected_relocations(a, mid, remaps, inplace, moved, by_script)
        if any(m is o["sc"].rel for o in ores):         # labels changed stream: the same set, another order
            assert sorted(want) == sorted(b), m.name + ": relocations"
            want = b
        for (s, pos, typ, tm, ts, ad), got in zip(want, b):
            assert (s, pos, typ, tm, ts, ad) == got, "%s: relocation sec%d+0x%X" % (m.name, s, pos)
        # everything in front of a rebuilt section, and the data behind the script, is untouched
        for t, t2 in zip(m.sections, new[mid].sections):
            if (mid, t["index"]) in remaps:
                r = remaps[(mid, t["index"])]
                assert _expected_section(m, t["index"], patched or {})[r.hi:] == \
                    new[mid].sec_data(t["index"])[r.hi + r.growth:r.growth + t["size"]], m.name + ": tail"
                assert _expected_section(m, t["index"], patched or {})[:r.lo] == new[mid].sec_data(t["index"])[:r.lo], m.name + ": head"
            elif m.name != "fonttex2.rel":          # the font is checked in build_font_file()
                assert _expected_section(m, t["index"], patched or {}) == new[mid].sec_data(t["index"]), m.name + ": section data"
    print("Verified: scripts re-parse, labels, text and all relocations match the originals.")
    return new
