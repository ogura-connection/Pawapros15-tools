"""Round-trip test of the build machinery: write everything out again with NO translation and expect no change.

What it is for: `pp15 build-check`. If the tools can parse every script, relocation stream, font glyph and dialog
string of the original game and write them back byte for byte, then the build itself (which changes only the text)
has a trustworthy foundation. Nothing is written to disk. Needs the game data, but no translation.

Public functions:
    run_check()   print one line per test; exit with "FAILED" if any differs
"""
import os
import sys

from pp15.build import dol_block, font
from pp15.build.glyph_codec import compress, decompress, font_glyphs, pack_font
from pp15.build.memory_plan import PLAN_FILE, update_plan
from pp15.build.module_files import ORIG_DIR, load_dir, load_scripts
from pp15.build.relocations import encode_stream, parse_imports, rebuild_module
from pp15.build.script_emit import emit_script
from pp15.text import strings


def _check_scripts(orig: dict, scripts: list) -> int:
    """Every Success Mode script written out with no replacements must give the identical module. Returns failures."""
    bad = 0
    for sc in scripts:
        data, remap = emit_script(sc, {})
        remaps = {(sc.rel.mod_id, sc.sec): remap}
        image = rebuild_module(sc.rel, sc.sec, data, remaps)
        ok = image == sc.rel.data and remap.growth == 0
        bad += not ok
        print("%-13s rebuilt with no changes: %s" % (sc.rel.name, "identical" if ok else "DIFFERENT"))
    return bad


def _check_relocation_streams(orig: dict) -> int:
    """Every relocation stream of every module must re-encode to the same bytes. Returns failures."""
    bad = n = 0
    for m in orig.values():
        for mod, start, entries, end in parse_imports(m.data, m.imp_off, m.imp_size):
            n += 1
            if encode_stream(entries) != m.data[start:end]:
                bad += 1
                print("%-13s relocation stream for module %d does not re-encode identically" % (m.name, mod))
    print("%d relocation streams in %d modules re-encoded" % (n, len(orig)))
    return bad


def _check_fonts(orig: dict) -> int:
    """Both fonts of fonttex2.rel must repack and recompress to the same bytes. Returns failures."""
    bad = 0
    rel = next(m for m in orig.values() if m.name == "fonttex2.rel")
    for name, pos, _ in font.FONTS:
        glyphs = font_glyphs(rel.sec_data(4), pos)
        size = font.FONT_END[pos] - pos
        used = 4 + 4 * len(glyphs) + sum(map(len, glyphs))
        ok = pack_font(glyphs, size)[:used] == rel.sec_data(4)[pos:pos + used] and all(
            decompress(compress(decompress(g)[0]))[0] == decompress(g)[0] for g in glyphs)
        bad += not ok
        print("%s font: %d glyphs repacked and recompressed: %s" % (name, len(glyphs), "identical" if ok else "DIFFERENT"))
    return bad


def _check_dol(orig: dict) -> int:
    """The dialog block of main.dol laid out again with no translation must be the original. Returns failures."""
    dol = dol_block.load_dol(None)
    if not dol:
        return 0
    strs = [s for s, _ in dol]
    block, starts = dol_block.layout_dol(strs, [s["units"] for s in strs])
    data, (a, b) = strings.dol_data(), strings.DOL_BLOCK
    remaps = {}
    ok = block == data[a:b] and starts == [s["offset"] for s in strs] and \
        dol_block.parse_dol(data) == [(s["offset"], s["units"]) for s in strs] and \
        dol_block.build_dol(dol, {}, orig, remaps) == data and not remaps
    print("%-13s dialog block re-emitted with no translations: %s" % (dol_block.DOL, "identical" if ok else "DIFFERENT"))
    return not ok


def run_check() -> None:
    """Run all the round trips; `sys.exit("FAILED")` if any result differs."""
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig)
    bad = _check_scripts(orig, scripts)
    bad += _check_relocation_streams(orig)
    with open(os.path.join(ORIG_DIR, PLAN_FILE), "rb") as f:
        plan = f.read()
    same = update_plan(plan, {sc.rel.name: (sc.rel.data, sc.rel.data) for sc in scripts}) == plan
    bad += not same
    print("memory plan (%s): %s" % (PLAN_FILE, "entries found and unchanged" if same else "DIFFERENT"))
    bad += _check_fonts(orig)
    bad += _check_dol(orig)
    sys.exit("FAILED" if bad else None)
