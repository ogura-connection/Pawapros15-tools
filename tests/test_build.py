"""Unit tests of the build package (pp15/build): small synthetic inputs, no game data, a few seconds.

    python3 tests/test_build.py          (also collected by pytest)

Each test builds a tiny stand-in for a game structure (a font glyph, a relocation stream, a REL module, a memory plan)
and checks that the build code reads it, writes it back, or moves it the way the real game files need.
"""
import contextlib
import io
import os
import struct
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pp15.build import dol_block, font, font_usage, memory_plan, ore_script, script_emit, verify
from pp15.build import code_patches, translation_file
from pp15.build.build_state import BuildState, exit_on_value_error
from pp15.build.glyph_codec import CELL_H, ROW_BYTES, compress, decompress, font_glyphs, pack_font
from pp15.build.pair_text import split_pairs, text_segments
from pp15.build.relocations import HEADER_FIX_SIZE, encode_stream, parse_imports, patch_addends, rebuild_module
from pp15.build.text_encode import encode_text
from pp15.glyphs import char_to_glyph
from pp15.script import scan
from pp15.text import strings


def raises(exc, func, *args):
    """True if func(*args) raises exc."""
    try:
        func(*args)
    except exc:
        return True
    return False


# ── pair_text ─────────────────────────────────────────────────────────────

def test_split_pairs_pads_the_last_pair():
    assert split_pairs("abcd") == ["ab", "cd"]
    assert split_pairs("abc") == ["ab", "c "]
    assert split_pairs("") == []


def test_text_segments_restart_pairs_on_lines_and_japanese():
    assert text_segments("abc\nde") == [("pair", "ab"), ("pair", "c "), ("newline", None), ("pair", "de")]
    assert text_segments("a\\nb") == [("pair", "a "), ("newline", None), ("pair", "b ")]      # backslash-n is a line break
    # a Japanese character is its own cell, and the pair after it starts again
    assert text_segments("abあcd") == [("pair", "ab"), ("char", "あ"), ("pair", "cd")]


# ── glyph_codec ───────────────────────────────────────────────────────────

def _sample_grid(seed: int) -> list[int]:
    """308 pixel bytes with flat areas (so fills are used) and noisy areas (so literals are used)."""
    grid = [0xFF] * (CELL_H * ROW_BYTES)
    for y in range(CELL_H):
        for x in range(ROW_BYTES):
            if (x + y + seed) % 5 == 0 or y > 20:
                grid[y * ROW_BYTES + x] = (x * 37 + y * 11 + seed) & 0xFF
    return grid


def test_glyph_compression_round_trips():
    for seed in range(8):
        grid = _sample_grid(seed)
        packed = compress(grid)
        decoded, used = decompress(packed + b"\xAA" * 10)      # extra bytes behind the glyph must not be read
        assert decoded == grid and used == len(packed), seed


def test_flat_glyph_is_small():
    assert len(compress([0xFF] * (CELL_H * ROW_BYTES))) < 60


def test_font_dataset_round_trips_and_checks_size():
    glyphs = [compress(_sample_grid(s)) for s in range(3)]
    size = 4 + 4 * 3 + sum(map(len, glyphs)) + 20
    dataset = pack_font(glyphs, size)
    assert len(dataset) == size and dataset.endswith(b"\xff" * 20)
    assert font_glyphs(dataset, 0) == glyphs
    assert raises(ValueError, pack_font, glyphs, size - 21)


# ── text_encode ───────────────────────────────────────────────────────────

def test_encode_text_uses_pair_slots_and_keeps_japanese():
    slots = {"he": 900, "ll": 901, "o ": 902}
    assert encode_text("hello", slots) == [900, 901, 902]
    assert encode_text("he\nll", slots) == [900, scan.TEXT_NEWLINE, 901]
    assert encode_text("he    ll", {"he": 900, "ll": 901}) == [900, 0, 0, 901]      # a blank pair is unit 0, no slot
    assert encode_text("heあ", slots) == [900, char_to_glyph("あ")]
    assert raises(KeyError, encode_text, "zz", slots)
    assert raises(ValueError, encode_text, "he\U0001F600", slots)                  # no glyph for an emoji


def test_encode_text_narrow_pairs_apply_to_the_first_cells_only():
    slots = {font.NARROW + "ab": 950, "ab": 951}
    text = "ab" * (font.NARROW_CELLS + 1)
    units = encode_text(text, slots, narrow=True)
    assert units == [950] * font.NARROW_CELLS + [951]


# ── relocations ───────────────────────────────────────────────────────────

def test_relocation_stream_round_trips_with_long_gaps():
    entries = [[1, 8, 1, 2, 0x100, 0], [1, 8 + 70000, 1, 2, 0x200, 0], [3, 4, 6, 1, 0x10, 0]]
    stream = encode_stream(entries)
    table = struct.pack(">II", 7, 8)                      # one row: target module 7, its stream at file offset 8
    parsed = parse_imports(table + stream, 0, 8)
    assert len(parsed) == 1 and parsed[0][0] == 7 and parsed[0][1] == 8 and parsed[0][3] == 8 + len(stream)
    assert [e[:5] for e in parsed[0][2]] == [e[:5] for e in entries]      # the 70000 gap was bridged with NOP entries


def _make_rel(directory: str, tail: bytes = b"") -> scan.Rel:
    """A minimal REL module: one 16-byte data section (index 1), a stream of its own pointers, a stream for main.dol."""
    sec_off, sec_size = 0x60, 0x10
    imp_off, rel_off = sec_off + sec_size, sec_off + sec_size + 16
    own = encode_stream([[1, 4, 1, 1, 8, 0], [1, 8, 1, 1, 12, 0]])
    dol = encode_stream([[1, 0, 1, 0, 0x80001000, 0]])
    header = bytearray(0x60)
    struct.pack_into(">12I", header, 0, 5, 0, 0, 2, 0x4C, 0, 0, 3, 0x20, rel_off, imp_off, 16)
    struct.pack_into(">I", header, 0x44, 8)
    struct.pack_into(">I", header, 0x48, rel_off + len(own))             # fixSize = start of the stream applied last
    struct.pack_into(">IIII", header, 0x4C, 0, 0, sec_off, sec_size)     # section 0: empty, section 1: the data
    body = bytes(range(sec_size)) + struct.pack(">IIII", 5, rel_off, 0, rel_off + len(own)) + own + dol + tail
    path = os.path.join(directory, "synthetic.rel")
    with open(path, "wb") as f:
        f.write(bytes(header) + body)
    return scan.Rel(path)


def test_rebuild_module_with_an_unchanged_section_gives_the_same_file():
    with tempfile.TemporaryDirectory() as d:
        rel = _make_rel(d, tail=b"TAIL")
        identity = {(5, 1): lambda off: off}
        assert rebuild_module(rel, 1, rel.sec_data(1), identity) == rel.data


def test_rebuild_module_moves_pointers_and_updates_the_header():
    with tempfile.TemporaryDirectory() as d:
        rel = _make_rel(d)
        grow = lambda off: off + 8 if off >= 8 else off          # 8 bytes were inserted at offset 8
        new_sec = rel.sec_data(1)[:8] + b"\0" * 8 + rel.sec_data(1)[8:]
        image = rebuild_module(rel, 1, new_sec, {(5, 1): grow})
        path = os.path.join(d, "built.rel")
        with open(path, "wb") as f:
            f.write(image)
        built = scan.Rel(path)
        assert built.sections[1]["size"] == 24
        own = [r for r in built.relocs() if r[3] == 5]
        assert [(r[1], r[5]) for r in own] == [(4, 16), (16, 20)]       # position 8 moved to 16; addends 8, 12 -> 16, 20
        assert struct.unpack_from(">I", image, 0x48)[0] == struct.unpack_from(">II", image, built.imp_off + 8)[1]


def test_patch_addends_aims_other_modules_at_the_new_places():
    with tempfile.TemporaryDirectory() as d:
        rel = _make_rel(d)
        image, n = patch_addends(rel, {(5, 1): lambda off: off + 100})
        assert n == 2
        path = os.path.join(d, "patched.rel")
        with open(path, "wb") as f:
            f.write(image)
        assert [r[5] for r in scan.Rel(path).relocs() if r[3] == 5] == [108, 112]
        assert patch_addends(rel, {})[1] == 0


# ── script_emit and ore_script ────────────────────────────────────────────

def test_remap_moves_what_follows_and_refuses_the_middle_of_an_instruction():
    remap = script_emit.Remap(lo=2, hi=6, newidx={2: 2, 3: 3, 5: 6}, growth=4)
    assert remap(2) == 2                      # in front of the script
    assert remap(12) == 16                    # behind it: moved by `growth`
    assert remap(10) == 12                    # halfword 5 -> halfword 6
    assert raises(ValueError, remap, 9)       # odd offset
    assert raises(ValueError, remap, 8)       # halfword 4 is not the start of anything


class _FakeScript:
    """A script of three halfwords-instructions, the middle one followed by a text run ('a')."""
    def __init__(self):
        self.text = scan.pack_text([char_to_glyph("あ")])
        j = 2 + len(self.text)
        self.hw = [0x0001, 0x0002] + self.text + [0x0003]
        self.kind = {0: "op", 1: "op", j: "op"}
        self.texts = {1: (29, [char_to_glyph("あ")], j)}


def test_emit_script_without_changes_gives_back_the_same_bytes():
    sc = _FakeScript()
    data, remap = script_emit.emit_script(sc, {})
    assert data == struct.pack(">%dH" % len(sc.hw), *sc.hw) and remap.growth == 0


def test_emit_script_with_longer_text_moves_the_instruction_behind():
    sc = _FakeScript()
    units = [char_to_glyph("あ")] * 12
    data, remap = script_emit.emit_script(sc, {1: units})
    new_text = scan.pack_text(units)
    expected = [0x0001, 0x0002] + new_text + [0x0003]
    assert list(struct.unpack(">%dH" % (len(data) // 2), data))[:len(expected)] == expected
    old_third, new_third = (2 + len(sc.text)) * 2, (2 + len(new_text)) * 2
    assert remap(old_third) == new_third and remap(0) == 0
    assert remap.growth % script_emit.SECTION_ALIGN == 0     # the data behind the script keeps its alignment


def test_ore_remap_keeps_islands_and_converts_annex_offsets_to_addresses():
    remap = ore_script.OreRemap(lo=0, hi=100, newidx={2: 3, 30: 40}, annex_lo=64, base=0x81400000, islands=[(10, 20)])
    assert remap(15) == 15 and remap(500) == 500          # island and outside: unchanged
    assert remap(4) == 6 and remap(60) == 80
    assert remap.address(80) == 0x81400000 + 16 and remap.address(6) is None


# ── memory_plan ───────────────────────────────────────────────────────────

def _make_plan(rows: list[tuple[int, int, int]]) -> bytes:
    """A minimal ELF object with the three tables moduleID2addr / moduleID2size / moduleID2relFileSize."""
    n = len(rows)
    tables = b"".join(struct.pack(">%dI" % n, *(r[k] for r in rows)) for k in range(3))
    names = b"\0moduleID2addr\0moduleID2size\0moduleID2relFileSize\0"
    offsets = [names.index(b"moduleID2addr"), names.index(b"moduleID2size"), names.index(b"moduleID2relFileSize")]
    symtab = struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0)
    for k, off in enumerate(offsets):
        symtab += struct.pack(">IIIBBH", off, k * 4 * n, 4 * n, 0, 0, 1)
    data_at, names_at, sym_at, sh_at = 0x40, 0x40 + len(tables), 0x100, 0x200
    elf = bytearray(sh_at + 4 * 40)
    struct.pack_into(">I", elf, 0x20, sh_at)
    struct.pack_into(">HH", elf, 0x2E, 40, 4)
    elf[data_at:data_at + len(tables)] = tables
    elf[names_at:names_at + len(names)] = names
    elf[sym_at:sym_at + len(symtab)] = symtab
    headers = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0), (0, 1, 0, 0, data_at, len(tables), 0, 0, 0, 0),
               (0, 3, 0, 0, names_at, len(names), 0, 0, 0, 0), (0, 2, 0, 0, sym_at, len(symtab), 2, 0, 0, 16)]
    for i, h in enumerate(headers):
        struct.pack_into(">10I", elf, sh_at + i * 40, *h)
    return bytes(elf)


def _module_image(file_size: int, fix_size: int, bss_size: int = 0x100, bss_align: int = 0x20) -> bytes:
    image = bytearray(file_size)
    struct.pack_into(">I", image, memory_plan.HEADER_BSS_SIZE, bss_size)
    struct.pack_into(">I", image, memory_plan.HEADER_BSS_ALIGN, bss_align)
    struct.pack_into(">I", image, HEADER_FIX_SIZE, fix_size)
    return bytes(image)


def test_memory_size_aligns_the_fixed_part_then_adds_the_bss():
    assert memory_plan.memory_size(_module_image(0x200, fix_size=0x101)) == 0x120 + 0x100


def test_update_plan_keeps_an_unchanged_plan_and_moves_scenarios_when_the_main_script_grows():
    names = (memory_plan.MAIN,) + memory_plan.SCENARIOS
    old = {n: _module_image(0x1000 + 0x100 * k, 0x1000) for k, n in enumerate(names)}
    start = memory_plan.SCENARIO_SLOT[0]
    addrs = [start - 0x2000] + [start] * 3
    rows = [(a, memory_plan.memory_size(old[n]), len(old[n])) for a, n in zip(addrs, names)]
    plan = _make_plan(rows)
    assert memory_plan.plan_tables(plan)[3] == 4
    assert memory_plan.update_plan(plan, {n: (old[n], old[n]) for n in names}) == plan
    grown = dict(old)
    grown[memory_plan.MAIN] = _module_image(0x4000, 0x4000)      # now it reaches into the scenario slot
    new_plan = memory_plan.update_plan(plan, {n: (old[n], grown[n]) for n in names})
    t_addr, t_size, t_file, _ = memory_plan.plan_tables(new_plan)
    read = lambda table, i: struct.unpack_from(">I", new_plan, table + 4 * i)[0]
    assert [read(t_addr, i) for i in (1, 2, 3)] == [memory_plan.FREE_AREA[0]] * 3      # scenarios moved
    assert read(t_file, 0) == 0x4000 and read(t_addr, 0) == addrs[0]
    huge = _module_image(0x4000, memory_plan.SCENARIO_SLOT[1] - addrs[0] + 0x1000)
    assert raises(SystemExit, memory_plan.update_plan, plan, {n: (old[n], huge if n == memory_plan.MAIN else old[n]) for n in names})


def test_plan_index_finds_a_module_by_its_sizes():
    a, b = _module_image(0x1000, 0x800), _module_image(0x1100, 0x800)
    plan = _make_plan([(0x80100000, memory_plan.memory_size(a), len(a)), (0x80200000, memory_plan.memory_size(b), len(b))])
    assert memory_plan.plan_index(plan, b) == 1
    assert raises(ValueError, memory_plan.plan_index, plan, _module_image(0x1200, 0x800))


# ── font_usage ────────────────────────────────────────────────────────────

def test_allocate_takes_unused_kanji_first_and_keeps_the_name_kanji_for_last():
    top = font_usage.KANJI_SLOTS[-1]
    slots, taken, lost = font_usage.allocate({"ab", "cd"}, {})
    assert slots == {"ab": top, "cd": top - 1} and (taken, lost) == (0, 0)
    slots, taken, lost = font_usage.allocate({"ab"}, {top: 9}, keep=[top - 1])
    assert slots["ab"] == top - 2 and taken == 0           # the used kanji and the name kanji are both avoided
    assert 0xE77 not in font_usage.allocate({"p%d" % i for i in range(3000)}, {})[0].values()


def test_allocate_reports_slots_taken_from_used_kanji_and_refuses_too_many_pairs():
    everything = {g: 1 for g in font_usage.KANJI_SLOTS}
    slots, taken, lost = font_usage.allocate({"ab"}, everything, keep=[3743])
    assert taken == 1 and lost == 0
    assert raises(ValueError, font_usage.allocate, {str(i) for i in range(4000)}, {})


def test_name_cells_recognises_player_names():
    assert font_usage._name_cells((0, 0, 0, 0, 0, 0)) == 0
    assert font_usage._name_cells((300, 301, 0, 0, 0, 0)) == 1                 # kana only
    assert font_usage._name_cells((800, 0, 801, 0, 0, 0)) == 2                 # two kanji spread out with a blank
    assert font_usage._name_cells((800, 0, 0, 801, 0, 0)) == 0                 # two blanks inside: not a name
    assert font_usage._name_cells((5, 300, 0, 0, 0, 0)) == 0                   # glyph 5 is not text a name may hold


# ── dol_block ─────────────────────────────────────────────────────────────

class _patched_dol_block:
    """Context manager: pretend the dialog block of main.dol is at file offsets 1000..1020 (address 0x80000000+...)."""
    def __enter__(self):
        self.saved = strings.DOL_BLOCK, strings.DOL_ADDRESS
        strings.DOL_BLOCK, strings.DOL_ADDRESS = (1000, 1020), 0x80000000

    def __exit__(self, *exc):
        strings.DOL_BLOCK, strings.DOL_ADDRESS = self.saved


def test_dol_strings_encode_and_decode_through_font_slots():
    slots = {"hi": 900, "ya": 901}
    units = dol_block.encode_dol("hiya{}hi", slots)
    assert units == [strings.DOL_GLYPH | 900, strings.DOL_GLYPH | 901, strings.DOL_CTRL, strings.DOL_GLYPH | 900]
    assert dol_block.decode_dol(units, slots) == "hiya{}hi"
    assert raises(ValueError, dol_block.encode_dol, "hi\nya", slots)         # a dialog string is a single line


def test_layout_dol_keeps_fixed_strings_in_place_and_fills_the_gaps():
    with _patched_dol_block():
        strs = [{"offset": 1000, "fixed": False, "units": [1, 2]}, {"offset": 1006, "fixed": True, "units": [3]}]
        block, starts = dol_block.layout_dol(strs, [[1], [3]])
        assert starts == [1000, 1006] and len(block) == 20
        units = struct.unpack(">10H", block)
        assert units == (1, 0xFFFF, 0xFFFF, 3, 0xFFFF) + (0xFFFF,) * 5
        assert raises(ValueError, dol_block.layout_dol, strs, [[1, 2, 3, 4], [3]])      # too long to reach the fixed string
        assert dol_block.parse_dol(b"\0" * 1000 + block) == [(1000, [1]), (1006, [3])]
        remap = dol_block.DolRemap(strs, [1000, 1004])
        assert remap(0x80000000 + 1006) == 0x80000000 + 1004 and remap(0x80000000 + 50) == 0x80000000 + 50
        assert raises(ValueError, remap, 0x80000000 + 1007)                      # inside a string that moved


# ── translation_file, code_patches, verify, build_state ──────────────────

def test_load_translation_reads_checks_and_warns():
    import json
    ja = char_to_glyph("あ")
    sc = types.SimpleNamespace(rel=types.SimpleNamespace(name="scs_x.rel"), texts={5: (29, [ja, ja], 9)})
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.json")

        def load(entries):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f)
            return translation_file.load_translation(path, [sc])
        assert load([{"file": "scs_x.rel", "section_offset": 10, "text": "ああ", "en": "Hi"},
                     {"file": "scs_x.rel", "section_offset": 12}]) == {"scs_x.rel": {5: "Hi"}}
        assert raises(SystemExit, load, [{"file": "scs_x.rel", "section_offset": 12, "en": "x"}])         # not a text run
        assert raises(SystemExit, load, [{"file": "scs_x.rel", "section_offset": 10, "text": "wrong", "en": "x"}])


def test_patch_code_words_applies_only_to_the_expected_original_words():
    words = code_patches.CODE_PATCHES["scc_tops.rel"]
    data = bytearray(0x4200)
    for (sec, off), (old, new) in words.items():
        struct.pack_into(">I", data, off, old)
    module = types.SimpleNamespace(name="scc_tops.rel", data=bytes(data), relocs=lambda: [],
                                   sections=[{"exec": False, "offset": 0}, {"exec": True, "offset": 0}])
    image, written = code_patches.patch_code_words(module, bytes(data))
    for (sec, off), (old, new) in words.items():
        assert struct.unpack_from(">I", image, off)[0] == new and written[(sec, off)] == struct.pack(">I", new)
    assert code_patches.patch_code_words(types.SimpleNamespace(name="other.rel"), b"abc") == (b"abc", {})
    assert raises(ValueError, code_patches.patch_code_words, module, image)          # already patched: not the original
    module.relocs = lambda: [(1, 0x4004, 1, 5, 1, 0)]
    assert raises(ValueError, code_patches.patch_code_words, module, bytes(data))    # a relocation would overwrite it


def test_expected_relocations_follow_the_remaps():
    relocs = [(1, 8, 1, 5, 1, 0x20), (1, 40, 1, 7, 2, 0x20)]
    shift = lambda off: off + 16
    want = verify._expected_relocations(relocs, 5, {(5, 1): shift, (7, 2): shift}, {}, {}, {})
    assert want == [(1, 24, 1, 5, 1, 0x30), (1, 56, 1, 7, 2, 0x30)]
    moved = verify._expected_relocations(relocs[:1], 5, {}, {}, {(5, 1, 8): 0x99}, {})
    assert moved == [(1, 8, 1, 5, 1, 0x99)]


def test_build_state_helpers():
    state = BuildState({}, [], [], {"m.rel": {(1, 40): (4, "x")}}, {}, [], {})
    module = types.SimpleNamespace(name="m.rel", mod_id=3)
    assert state.ui_string_inside(module, [(1, 32, 48)]) and not state.ui_string_inside(module, [(1, 0, 40), (2, 32, 48)])
    assert not state.is_rebuilt(module)
    state.remaps[(3, 1)] = None
    assert state.is_rebuilt(module)
    state.record(module, 1, 8, b"ab")
    assert state.patched == {3: {(1, 8): b"ab"}}


def test_exit_on_value_error_turns_a_check_failure_into_a_clean_exit():
    def failing():
        with exit_on_value_error():
            raise ValueError("this input is wrong")
    try:
        failing()
    except SystemExit as e:
        assert str(e) == "this input is wrong"
    else:
        raise AssertionError("no exit")


if __name__ == "__main__":
    tests = [(name, func) for name, func in sorted(globals().items()) if name.startswith("test_")]
    for name, func in tests:
        captured = io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):      # the build prints progress lines; show them only on failure
                func()
        except Exception:
            sys.stdout.write(captured.getvalue())
            raise
    print("%d build tests passed" % len(tests))
