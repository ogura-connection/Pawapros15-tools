"""Unit tests for the text side of the package: the character table, the packed story text, REL reading, the script
parser, and the checks for menu strings and news messages.

They use small made-up inputs (a hand-built REL file, hand-written text units), so they need no game data and run in a
second:

    python3 tests/test_script_text.py        (also collected by pytest)
"""
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pp15 import glyphs                                                    # noqa: E402
from pp15.script import block_scripts, rel as relmod, scripts, translate   # noqa: E402
from pp15.script.packed_text import (TEXT_END, TEXT_NEWLINE, decode_units, pack_text, unpack_text,  # noqa: E402
                                     units_valid)
from pp15.text import (colour_text, dol_dialogs, line_layout, messages, movable_blocks, slot_finder,  # noqa: E402
                       string_rules, string_tables, strings, tsv_store)

A, I, U = glyphs.char_to_glyph("あ"), glyphs.char_to_glyph("い"), glyphs.char_to_glyph("う")   # three hiragana


# ── helpers: a REL file built by hand ─────────────────────────────────────

def make_rel(directory, name, mod_id, sections, relocs=()):
    """Write a minimal REL file. sections = [(bytes, is_code)]; relocs = [(src section, offset, type, target module,
    target section, addend)] (all from one importing module list). Returns the path."""
    header_size, table = 0x40, 0x40
    body_at = table + 8 * len(sections)
    offsets, blob = [], b""
    for data, is_code in sections:
        offsets.append((body_at + len(blob)) | (1 if is_code else 0))
        blob += data + b"\0" * (-len(data) % 4)
    imp_at = body_at + len(blob)
    by_module = {}
    for r in relocs:
        by_module.setdefault(r[3], []).append(r)
    imports, stream = b"", b""
    stream_at = imp_at + 8 * len(by_module)
    for mod, rs in by_module.items():
        imports += struct.pack(">II", mod, stream_at + len(stream))
        sec, pos = None, 0
        for (s, off, typ, _, ts, addend) in sorted(rs):
            if s != sec:
                stream += struct.pack(">HBBI", 0, relmod.R_SECTION, s, 0)
                sec, pos = s, 0
            while off - pos > 0xFFFF:                    # a long gap is crossed with padding records
                stream += struct.pack(">HBBI", 0xFFFF, relmod.R_NOP, 0, 0)
                pos += 0xFFFF
            stream += struct.pack(">HBBI", off - pos, typ, ts, addend)
            pos = off
        stream += struct.pack(">HBBI", 0, relmod.R_END, 0, 0)
    head = struct.pack(">12I", mod_id, 0, 0, len(sections), table, 0, 0, 3, 0, stream_at, imp_at, len(imports))
    head += b"\0" * (header_size - len(head))
    table_bytes = b"".join(struct.pack(">II", off, len(d)) for off, (d, _) in zip(offsets, sections))
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(head + table_bytes + blob + imports + stream)
    return path


def halfwords(*values):
    return struct.pack(">%dH" % len(values), *values)


# ── glyph table ───────────────────────────────────────────────────────────

def test_glyph_char_round_trip():
    for g in range(glyphs.MAX_GLYPH + 1):
        ch = glyphs.glyph_to_char(g)
        if ch and ch != "�":
            assert glyphs.char_to_glyph(ch) == g, (g, ch)


def test_known_glyphs():
    assert glyphs.glyph_to_char(0) == "　"          # glyph 0 is the full-width space
    assert glyphs.glyph_to_char(A) == "あ" and A == 283
    assert glyphs.char_to_glyph("A") is None             # a one-byte letter is not in this table; English uses the pair font
    assert glyphs.glyph_to_char(-1) is None and glyphs.glyph_to_char(glyphs.MAX_GLYPH + 1) is None


def test_decode_glyph_string():
    assert glyphs.decode_glyph_string([A, I, 0x1FFF, U]) == "あい"       # stops at the terminator
    assert glyphs.decode_glyph_string([A | 0x2000]) == "あ"                # flag bits are ignored
    assert glyphs.decode_glyph_string([0x1FFE]) == "[0x1FFE]"             # not a glyph


def test_is_clean_text():
    assert glyphs.is_clean_text("こんにちは")
    assert not glyphs.is_clean_text("ab")
    assert not glyphs.is_clean_text("")


def test_bit_reader():
    bits = glyphs.BitReader(bytes([0b10110000]))
    assert [bits.read_bit() for _ in range(4)] == [1, 0, 1, 1]
    assert glyphs.BitReader(b"").read_bit() == 0                          # past the end reads zeros
    assert glyphs.BitReader(bytes([0b01000000])).read_varlen() == 1       # two bits 01
    assert glyphs.BitReader(bytes([0b00001100])).read_varlen() == 4 + 0b0011   # 00 then four more bits


def test_decompress_glyph_literals_and_runs():
    assert glyphs.decompress_glyph(b"")[0] == [0xFF] * 512
    # all literals: 308 zero control bits (39 bytes), then 308 literal bytes
    data = bytes([39]) + bytes(39) + bytes(range(256)) + bytes(range(52))
    out, _ = glyphs.decompress_glyph(data)
    assert len(out) == 512 and out[:11] == list(range(11)) and out[11:16] == [0xFF] * 5
    # a run: slot 0 of row 0 starts a run (bit 1, fill 1 = '01', repeat 3 = '11') of the literal 0xAB
    bits = "1" + "01" + "11" + "0" * 10                       # then the other ten slots of row 0 are literals
    bits += "0" * (308 - 3 * 1 - 10 - 3 - 7)                    # the rest are literals as well (generous padding)
    stream = int(bits.ljust(8 * 40, "0"), 2).to_bytes(40, "big")
    literal = bytes([0xAB]) + bytes(range(1, 11)) + bytes(300)
    out, _ = glyphs.decompress_glyph(bytes([40]) + stream + literal)
    column0 = [out[row * 16] for row in range(4)]
    assert column0[:3] == [0xAB] * 3 and column0[3] != 0xAB     # the run lasts the three rows asked for


# ── packed story text ─────────────────────────────────────────────────────

def test_pack_known_value():
    assert pack_text([1, 2, 3]) == [0x0010, 0x0200, 0x3FFF]


def test_pack_unpack_round_trip():
    for n in range(0, 9):
        units = [(37 * k + 5) % 0xE00 for k in range(n)]
        hw = pack_text(units)
        assert unpack_text(hw, 0) == (units, len(hw)), n
        padded = [0xABCD, *hw, 0x1234]                         # a run in the middle of other data
        assert unpack_text(padded, 1) == (units, 1 + len(hw)), n


def test_unpack_failure_modes():
    assert unpack_text([0x0010, 0x0200], 0) is None            # no terminator
    assert unpack_text(pack_text([1] * 10), 0, max_units=3) is None
    assert unpack_text(pack_text([0xEA0]), 0, strict=True) is None     # between the last glyph and the control range
    assert unpack_text(pack_text([0xEA0]), 0) is not None


def test_decode_and_validate_units():
    assert decode_units([A, TEXT_NEWLINE, I, 0xF05]) == "あ\\nい<F05>"
    assert units_valid([A, 0xF00, 0xFFE]) and not units_valid([0xEA0])
    assert TEXT_END == 0xFFF


# ── REL files and the script parser ───────────────────────────────────────

def test_rel_reading():
    with tempfile.TemporaryDirectory() as d:
        path = make_rel(d, "x.rel", 9, [(b"CODE", True), (b"\1\2\3\4\5\6\7\x08", False)],
                        relocs=[(1, 4, 1, 3, 0, 0x20), (1, 8, 1, 3, 0, 0x24)])
        r = relmod.Rel(path)
        assert (r.mod_id, r.name) == (9, "x.rel")
        assert [s["exec"] for s in r.sections] == [True, False]
        assert r.sec_data(1) == b"\1\2\3\4\5\6\7\x08"
        assert r.relocs() == [(1, 4, 1, 3, 0, 0x20), (1, 8, 1, 3, 0, 0x24)]
        assert r.data_relocs(1, 8) == [(1, 3, 0, 0x24)] and r.data_relocs(1, 12) == []
        assert r.script_section() == 1                          # the largest stored non-code section
        assert glyphs.parse_rel_header(path)["mod_id"] == 9


def make_script_module(directory, instructions, label_halfwords):
    """A scs_main.rel with only relocations (its label table) and a scs_sce1.rel holding `instructions`."""
    script = make_rel(directory, "scs_sce1.rel", 7, [(b"", True), (instructions, False)])
    table = scripts.LABEL_TABLES[0]
    labels = [(5, table + 4 * k, 1, 7, 1, hw * 2) for k, hw in enumerate(label_halfwords)]
    main = make_rel(directory, "scs_main.rel", 1, [(b"", True)] + [(b"", False)] * 5, relocs=labels)
    return relmod.Rel(main), relmod.Rel(script)


def story_script(directory):
    """Two scenes: [text あい, wait, return] and [text う, goto]."""
    text1, text2 = pack_text([A, I]), pack_text([U])
    code = [0x0000, *text1, scripts.OP_WAIT, scripts.OP_RETURN,
            0x0000, *text2, scripts.OP_GOTO, 0]
    main, sce = make_script_module(directory, halfwords(*code), [0, 3 + len(text1)])
    return scripts.Script(sce, {1: main, 7: sce}), len(text1)


def test_script_parses_text_and_flow():
    with tempfile.TemporaryDirectory() as d:
        sc, n1 = story_script(d)
        assert sorted(sc.labels) == [0, 3 + n1]                       # two entry points: both scenes
        assert [u for (_, u, _) in (sc.texts[i] for i in sorted(sc.texts))] == [[A, I], [U]]
        assert sc.errors == {}
        assert sc.op_count[scripts.OP_WAIT] == 1
        rows = translate.scenes(sc)
        assert [[r["text"] for r in scene] for scene in rows] == [["あい"], ["う"]]
        assert rows[0][0]["off"] == 0 and rows[0][0]["mark"] == "B"


def test_instruction_lengths():
    assert scripts.instruction_length([0x0001], 0) == 1
    assert scripts.instruction_length([0x0016, 0, 0, 0], 0) == 4                   # opcode 0x16 has 3 operands
    assert scripts.instruction_length([scripts.OP_SKIPLIST, 5, 6, 0, 9], 0) == 4   # list up to the zero
    # an if: opcode, expr, comparison, operand, label
    assert scripts.instruction_length([scripts.OP_IF, 1, 2, 3, 9, 0, 0], 0) == 5
    assert scripts.opcode_lengths({3: [5, 6]})[5] == 3 and scripts.opcode_lengths({3: [5]})[7] == 1


def test_block_script_specs():
    specs = block_scripts.BLOCK_SCRIPTS
    assert list(specs) == ["sct_main.rel", "scs_comi.rel", "orepena.rel", "gdt_pn.rel", "koukai.rel"]
    assert specs["orepena.rel"]["engine"] == "ore" and "engine" not in specs["sct_main.rel"]
    assert specs["koukai.rel"]["annex_magic"] == (0x4B4B, 0x4558)
    assert block_scripts.EIKAN_OP_LEN[0x26] == 3 and block_scripts.EIKAN_OP_LEN[0x69] == 2


# ── translation workflow checks ───────────────────────────────────────────

def test_letters_and_odd_tail():
    assert translate.letters("abc") == 3 and translate.letters("あb") == 3
    assert translate.odd_tail("あabc") and not translate.odd_tail("あab")


def scene_rows(*runs):
    """Rows as scenes() makes them: runs = (offset, window, mark, Japanese text)."""
    return [{"off": o, "window": w, "face": 0, "mark": m, "text": t} for o, w, m, t in runs]


def test_check_scene_warnings():
    rows = scene_rows((0, 30, "B", "あ"), (10, 30, "B", "い"))
    done = {0: ("x", "short"), 10: ("x", "a" * 40)}
    warn = translate.check_scene("f", rows, done, per_line=34)
    assert len(warn) == 1 and "+10: line is 40 letters (max 34)" in warn[0]
    assert translate.check_scene("f", rows, {0: ("x", "ok")}, 34)[0].startswith("f: scene partly translated")
    odd = scene_rows((0, 30, "B", "あ"), (10, 30, "+", "い"))
    assert any("odd number of letters" in w for w in translate.check_scene("f", odd, {0: ("x", "abc"), 10: ("x", "d")}))


def test_translation_files_round_trip():
    with tempfile.TemporaryDirectory() as d:
        old = translate.TSV_DIR
        translate.TSV_DIR = d
        try:
            rows = {20: ("ab12", "two\nlines"), 4: ("cd34", "one")}
            translate.save_tsv("m.rel", rows)
            text = open(os.path.join(d, "m.rel.tsv"), encoding="utf-8").read()
            assert text.splitlines()[1:] == ["4\tcd34\tone", "20\tab12\ttwo\\nlines"]      # sorted, \n escaped
            assert translate.load_tsv("m.rel") == rows
            assert translate.load_tsv("missing.rel") == {}
        finally:
            translate.TSV_DIR = old


def test_tsv_store_and_hash():
    assert tsv_store.text_hash("") == "da39"                                   # start of the SHA-1 of nothing
    assert len(tsv_store.text_hash("こんにちは")) == 4
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sub", "t.tsv")
        tsv_store.write_rows(path, "# header\n", [(1, "a", "x\ty")])
        assert tsv_store.read_rows(path, 3) == [["1", "a", "x\ty"]]            # the last column keeps its tabs
        assert tsv_store.read_rows(os.path.join(d, "none.tsv"), 3) == []


# ── fixed-slot strings ────────────────────────────────────────────────────

def test_colour_text():
    assert colour_text.colour_runs("ab{6:cd}ef") == [(0, "ab"), (6, "cd"), (0, "ef")]
    assert colour_text.colour_runs("") == [(0, "")]
    assert colour_text.plain("ab{6:cd}ef") == "abcdef"
    units = [A, I | 0x6000, U | 0x6000]
    assert colour_text.units_text(units) == "あ{6:いう}"
    assert colour_text.units_text([A, 0, 0]) == "あ"                            # trailing spaces cut
    assert colour_text.letters("abc") == 2 and colour_text.letters("ab{6:c}") == 2 and colour_text.letters("a{6:bc}d") == 3


def padded(text_cells, width_pad):
    """Units: kana text then spaces up to width_pad."""
    return [A] * text_cells + [0] * (width_pad - text_cells)


def test_line_layout_from_padding():
    assert line_layout.padding([A, 0, 0, I]) is None                           # too early to be line padding
    assert line_layout.padding([A] * 9 + [0, 0, I]) == 11
    assert line_layout.used_cells([A, 0, I, 0, 0]) == 3
    # three neighbouring two-line strings padded to 10 cells: all take width 10, the slot is 20 cells
    found = [{"section": 5, "offset": 100 * k, "cells": 20, "units": padded(8, 10) + [I] * 10, "text": "x"}
             for k in range(3)]
    for s in line_layout.line_widths("m.rel", found):
        assert (s["width"], s["uncertain"]) == (10, False)
        assert line_layout.line_caps(s) == [10, 10]
    single = line_layout.line_widths("m.rel", [{"section": 5, "offset": 0, "cells": 6, "units": [A] * 6, "text": "x"}])[0]
    assert single["width"] == 0 and line_layout.line_caps(single) == [6]
    assert line_layout.line_caps({"cells": 25, "width": 10}) == [10, 10, 5]


def test_line_layout_overrides_and_japanese_lines():
    key = next(iter(string_tables.LINE_WIDTH))
    name, section, offset = key
    s = {"section": section, "offset": offset, "cells": 69, "units": [A] * 69, "text": "x"}
    assert line_layout.line_widths(name, [s])[0]["width"] == string_tables.LINE_WIDTH[key]
    jp = {"width": 3, "units": [A, I, 0, U, 0, 0, 0, 0, 0], "text": "ignored"}
    assert line_layout.japanese_lines(jp) == "あい|う"


def test_block_layout_shares_tails():
    seqs = [tuple("abcd"), tuple("cd"), tuple("xy")]
    starts, used = movable_blocks.block_layout(seqs)
    assert starts == [0, 2, 5] and used == 8                  # "cd" lives inside "abcd"; each other string +1 for its end
    assert movable_blocks.block_of("scs_data.rel", 5, 22308) is string_tables.BLOCKS["scs_data.rel"][0]
    assert movable_blocks.block_of("scs_data.rel", 5, 5) is None


def slot(cells=10, width=0, **extra):
    s = {"section": 5, "offset": 0, "cells": cells, "units": [A] * cells, "text": "x", "width": width,
         "uncertain": False}
    s.update(extra)
    return s


def test_judge_slot_strings():
    errors, warnings, out = string_rules.judge(slot(cells=5), "abcdefghij")
    assert (errors, out) == ([], "abcdefghij")                                  # 5 cells = 10 letters
    errors, _, _ = string_rules.judge(slot(cells=5), "abcdefghijk")
    assert errors and "1 letters too long" in errors[0]
    assert string_rules.judge(slot(), "")[0] == ["empty English"]
    assert "cannot draw" in string_rules.judge(slot(), "café ÿ")[0][0]
    # two lines of 3 cells: the first is padded to the width
    errors, _, out = string_rules.judge(slot(cells=6, width=3), "ab|cd")
    assert errors == [] and out == "ab    cd"
    errors, _, _ = string_rules.judge(slot(cells=6, width=3), "a|b|c")
    assert "3 lines, the slot has 2" in errors[0]
    assert string_rules.too_long("abcdef", 2) == 2 and string_rules.pad_line("ab", 3) == "ab    "


def test_judge_block_and_help_and_dol():
    block = {"max": 3}
    assert string_rules.judge(slot(block=block), "abcdef")[0] == []
    assert "too long" in string_rules.judge(slot(block=block), "abcdefg")[0][0]
    help_string = slot(cells=20, text="あいう|えおか", help=True)
    assert string_rules.judge(help_string, "abc|def")[0] == []
    assert "lines, the Japanese has 2" in string_rules.judge(help_string, "a|b|c")[0][0]
    assert string_rules.judge(help_string, "a|b")[2] == "a\nb"
    dol = slot(cells=6, fixed=False, ctrl=1)
    assert string_rules.judge(dol, "{}abc", longest=10)[0] == []
    assert "{} in the English" in string_rules.judge(dol, "abc", longest=10)[0][0]
    fixed = slot(cells=3, fixed=True, ctrl=0)
    assert "cannot move" in string_rules.judge(fixed, "abcdefgh", longest=10)[0][0]
    assert dol_dialogs.dol_cells("{}abc") == 3 and dol_dialogs.dol_cells("{}{}") == 2


def test_dol_need_and_segments():
    strs = [{"offset": string_tables.DOL_BLOCK[0] + 20 * k, "cells": 9, "fixed": k == 1} for k in range(3)]
    need = dol_dialogs.dol_need({(0, strs[1]["offset"]): "abcd"})        # the fixed string gets shorter in English
    assert need(strs[0]) == 10 and need(strs[1]) == 3
    segments = dol_dialogs.dol_segments(strs, need)
    assert [len(run) for run, _ in segments] == [1, 1]
    assert dol_dialogs.dol_fit([dict(s, units=[]) for s in strs], {}) == []


def test_find_strings_in_a_module():
    glyph_string = [A, I, U, 0, 0, 0xFFFF]                                   # three kana, two spaces, terminator
    junk = [5, 6, 0xFFFF]                                                    # no kana: not a string
    data = halfwords(0, *glyph_string, *junk, 0)
    with tempfile.TemporaryDirectory() as d:
        r = relmod.Rel(make_rel(d, "m.rel", 4, [(b"", True), (data, False)]))
        found = slot_finder.find(r)
        assert [(s["offset"], s["cells"], s["text"]) for s in found] == [(2, 5, "あいう")]
        assert slot_finder.find(r, region=(1, 0, 16)) == []              # the packed story region is skipped


def test_capacity_column():
    assert strings.capacity(slot(cells=6, width=3)) == "6|6"
    assert strings.capacity(slot(cells=6, width=3, uncertain=True)) == "6|6?"
    assert strings.capacity(slot(block={"max": 15})) == "30 movable"
    assert strings.capacity(slot(cells=9, fixed=True, ctrl=1)) == "16 fixed"
    assert strings.capacity(slot(cells=9, fixed=False, ctrl=1), longest=20) == "22/38"


def test_command_lines_parse():
    """Every command keeps its arguments (the `pp15 <command>` forms of docs and scripts)."""
    from pp15 import glyph_cli
    from pp15.script import scan
    show = translate.build_parser().parse_args(["show", "scs_sce1.rel", "3"])
    assert (show.file, show.first, show.last) == ("scs_sce1.rel", "3", None)
    assert translate._with_default_last(show).last == "3"
    assert translate.build_parser().parse_args(["apply", "scs_sce1.rel", "s0007"]).scene == "s0007"
    assert translate.build_parser().parse_args(["set", "f.rel", "12", "text"]).text == "text"
    args = strings.build_parser().parse_args(["set", "scs_data.rel", "5:100", ""])
    assert (args.file, args.id, args.text) == ("scs_data.rel", "5:100", "")      # "" removes the string
    assert strings.build_parser().parse_args(["export", "a.rel", "b.rel"]).files == ["a.rel", "b.rel"]
    assert messages.build_parser().parse_args(["export"]).files == []
    assert scan.build_parser().parse_args(["extract", "--dump", "--samples", "2"]).samples == 2
    assert glyph_cli.build_parser().parse_args(["decode-bytes", "01C0", "017B"]).values == ["01C0", "017B"]


# ── news messages ─────────────────────────────────────────────────────────

def piece_units(*pieces):
    """Message units: for each (codes, text units) the codes, 0, the text and 0xFFFF; then the stop code 0xF."""
    out = []
    for codes, text in pieces:
        out += [*codes, 0, *text, 0xFFFF]
    return out + [0xF]


def test_message_parse_tags_and_judge():
    units = piece_units(([], [A, I]), ([1], [U]), ([0x66, 7], [A]))
    pieces, trailer, kind = messages.parse(units)
    assert kind == "end" and trailer == (0xF,)
    assert [codes for codes, _, _ in pieces] == [(), (1,), (0x66, 7)]
    assert messages.form(pieces, messages.japanese) == "あい{n}う{66}{p}あ"
    assert messages.tags(1, (), 0) == ["{+}"] and messages.tags(0, (), 0) == []
    msg = {"section": 5, "offset": 0, "cells": len(units) + 12, "pieces": pieces, "trailer": trailer, "kind": kind}
    errors, texts = messages.judge(msg, "ab{n}c{66}{p}d")
    assert errors == [] and texts == ["ab", "c", "d"]
    assert "tags differ" in messages.judge(msg, "ab{n}c")[0][0]
    assert "empty" in messages.judge(msg, " ")[0][0]
    assert "cannot be drawn" in messages.judge(msg, "ab|c")[0][0]
    long_line = messages.judge(msg, "x" * 60 + "{n}c{66}{p}d")[0]
    assert any("too long" in e or "too wide" in e for e in long_line)


def test_message_width_room_and_encode():
    assert messages.width("abc") == 3 and messages.width("a{66}b") == 2 + 8 and messages.width("{70}") == 4
    units = piece_units(([], [A, I]), ([1], [U]))
    pieces, trailer, kind = messages.parse(units)
    msg = {"section": 5, "offset": 0, "cells": len(units) + 3, "pieces": pieces, "trailer": trailer, "kind": kind}
    assert messages.room(msg) == msg["cells"] - ((0 + 2) + (1 + 2) + 1)
    encoded = messages.encode(msg, ["ab", "c"], lambda text: [10 + ord(c) % 7 for c in text])
    assert len(encoded) == msg["cells"] and encoded[-1] == 0 and 0xF in encoded
    assert messages.parse(encoded[:len(encoded)])[2] == "end"
    with_pre = dict(msg, cells=msg["cells"] + 4, pre=(2, 0x303, 0x107, 0))
    assert messages.room(with_pre) == messages.room(msg)
    assert messages.encode(with_pre, ["ab", "c"], lambda text: [10 + ord(c) % 7 for c in text])[:4] == [2, 0x303, 0x107, 0]
    try:
        messages.encode(dict(msg, cells=3), ["ab", "c"], lambda text: [1] * len(text))
    except ValueError:
        pass
    else:
        raise AssertionError("an overlong message must be refused")
    assert messages.parse([A, I, 5]) is None                                # text with no leading 0 and no terminator


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    for t in TESTS:
        t()
        print("ok", t.__name__)
    print("%d tests passed" % len(TESTS))
