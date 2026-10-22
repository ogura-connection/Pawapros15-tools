"""Unit tests of the names, disc, reference and kit tools and of the command line (pp15/names, disc, reference, kit,
config.py, cli.py).

    python3 tests/test_names_disc_kit.py        (also collected by pytest)

They use small made-up inputs, so they need no game data and run in a few seconds. A few at the end read the checked-in
translation files (translation/names/*.tsv), which are part of the repository.
"""
import contextlib
import importlib.util
import io
import os
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np

from pp15 import cli, config
from pp15.disc import extract, extract_text, lz4_fallback, wii_format, xdelta
from pp15.kit import export_tm
from pp15.names import kyu, ppc_words, schools, table
from pp15.reference import mlb_assets, mlb_labels
from pp15.script import scan


def raises(exception, function, *args):
    """True if function(*args) raises `exception`."""
    try:
        function(*args)
    except exception:
        return True
    return False


class FakeRel:
    """Just enough of pp15.script.scan.Rel for the functions that only read sections and relocations."""

    def __init__(self, name, sections, relocs=(), mod_id=1, section_offsets=None, data=b"", exec_sections=()):
        self.name, self.mod_id, self.data = name, mod_id, data
        self._sections, self._relocs = sections, list(relocs)
        offsets = section_offsets or {}
        self.sections = [{"offset": offsets.get(i, 0), "size": len(s), "exec": i in exec_sections}
                         for i, s in enumerate(sections)]

    def sec_data(self, i):
        return self._sections[i]

    def relocs(self):
        return self._relocs


def fake_encode(text):
    """Stands in for the font encoder: one cell per two letters, the cell number is made of the two letter codes."""
    return [(ord(text[i]) << 4) + (ord(text[i + 1]) if i + 1 < len(text) else 0) for i in range(0, len(text), 2)]


# ── ppc_words ──────────────────────────────────────────────────────────────

def test_ppc_words_match_known_machine_code():
    assert ppc_words.li(3, 0x37B) == 0x3860037B             # the first word of the name builder in orepena.rel
    assert ppc_words.li(0, 0x4E6) == 0x380004E6
    assert ppc_words.li(4, 0) == 0x38800000
    assert ppc_words.addi(4, 4, 1) == 0x38840001
    assert ppc_words.add(3, 3, 6) == 0x7C633214
    assert ppc_words.lhzx(0, 3, 5) == 0x7C032A2E
    assert ppc_words.sthx(0, 22, 5) == 0x7C162B2E
    assert ppc_words.cmplwi(0, 0x1FFF) == 0x28001FFF
    assert ppc_words.cmpwi(4, 6) == 0x2C040006


def test_ppc_branches_use_relative_distance():
    assert ppc_words.beq(0x100, 0x110) == 0x41820010
    assert ppc_words.blt(0x100, 0x110) == 0x41800010
    assert ppc_words.branch(0x100, 0x108) == 0x48000008
    assert ppc_words.branch(0x100, 0xFC) == 0x4BFFFFFC       # backwards


def test_loop_words_gives_each_word_its_address():
    words = ppc_words.loop_words(0x1000, [ppc_words.NOP, lambda here: ppc_words.beq(here, 0x1010), ppc_words.BLR])
    assert words == [(0x1000, ppc_words.NOP), (0x1004, ppc_words.beq(0x1004, 0x1010)), (0x1008, ppc_words.BLR)]


# ── names.table ────────────────────────────────────────────────────────────

def test_plate_layout_examples_of_the_docstring():
    assert table.plate("Ito") == "   Ito"                  # cells "  " " I" "to"
    assert table.plate("Goto") == "  Goto"
    assert table.plate("Fujii") == " Fujii"
    assert table.plate("Takahashi") == " Takahashi"


def test_letters_ok():
    assert table.letters_ok("Takahashi")
    assert table.letters_ok("A" * 12)
    assert not table.letters_ok("A" * 13)
    assert not table.letters_ok("   ")
    assert not table.letters_ok("石井")
    assert not table.letters_ok("")


def test_short_form_uses_kunrei_spelling_only_when_needed():
    assert table.short_form("Nishida") == "Nishida"           # already short
    assert table.short_form("Takahashi") == "Takahasi"        # shi -> si
    assert table.short_form("Ogasawara") is None              # nothing to shorten
    assert table.short_form("Tsuchiya") == "Tsuchiya"         # 8 letters fit as they are


def test_surname_table_records():
    names = {i: (1000 + i, "Sato") for i in range(table.COUNT)}
    names[5] = (77, "Takahashi")
    data = table.table(names, fake_encode)
    assert len(data) == table.COUNT * table.STRIDE
    cells = struct.unpack_from(">8H", data, 5 * table.STRIDE)
    assert cells[6] == table.END and cells[7] == 77                 # end mark, call id
    assert cells[:5] == tuple(fake_encode(table.plate("Takahashi"))) and cells[5] == table.END   # padded with the end mark
    assert struct.unpack_from(">8H", data, 0)[7] == 1000


def test_surname_table_rejects_a_name_that_does_not_fit():
    names = {i: (i, "Sato") for i in range(table.COUNT)}
    names[3] = (3, "Abcdefghijklm")                                  # 13 letters
    assert raises(ValueError, table.table, names, fake_encode)


def test_short_table_keeps_call_ids_and_reports_kanji_names():
    old = bytearray()
    for i in range(table.COUNT):
        old += struct.pack(">5H", 0x300 + i, 0x301, 0, table.END, i)         # 3 cells, END at +6, call id at +8
    names = {i: (i, "Sato") for i in range(table.COUNT)}
    names[1] = (1, "Ogasawara")                                               # cannot be short
    data, kanji = table.short_table(names, fake_encode, bytes(old))
    assert kanji == ["Ogasawara"]
    assert data[1 * table.OLD_STRIDE:(1 + 1) * table.OLD_STRIDE] == bytes(old[1 * table.OLD_STRIDE:2 * table.OLD_STRIDE])
    assert struct.unpack_from(">4H", data, 0)[0] == fake_encode(table.plate("Sato"))[0]
    bad = bytearray(old)
    struct.pack_into(">H", bad, 8, 999)                                       # wrong call id in record 0
    assert raises(ValueError, table.short_table, names, fake_encode, bytes(bad))


def test_name_field_recognises_six_cell_names():
    assert table.name_field(struct.pack(">6H", 0x300, 0x301, 0, 0, 0, 0), 0) == (0x300, 0x301, 0, 0, 0, 0)
    assert table.name_field(struct.pack(">6H", 0, 0, 0, 0, 0, 0), 0) is None          # no glyph at all
    assert table.name_field(struct.pack(">6H", 0x300, 0x2000, 0, 0, 0, 0), 0) is None   # 0x2000 and up are flags, not name cells
    assert table.name_field(struct.pack(">6H", 0x10, 0x20, 0, 0, 0, 0), 0) is None       # control values only


def test_inplace_patches_write_padded_fields_and_catch_overlaps():
    data = struct.pack(">6H", 0x300, 0x301, 0x302, 0, 0, 0) * 2 + bytes(12)           # two name fields, one blank field
    rel = FakeRel("x.rel", [b"", data])
    out = table.inplace_patches(rel, [(1, 0, "Ito"), (1, 12, "Sato")], fake_encode)
    assert set(out) == {(1, 0), (1, 12)}
    assert out[(1, 0)] == struct.pack(">6H", *(fake_encode(table.plate("Ito")) + [0] * 4)[:6])
    assert raises(ValueError, table.inplace_patches, rel, [(1, 0, "Ito"), (1, 6, "Sato")], fake_encode)    # fields overlap
    assert raises(ValueError, table.inplace_patches, rel, [(1, 24, "Ito")], fake_encode)                  # not a name field
    assert raises(ValueError, table.inplace_patches, rel, [(1, 0, "A" * 13)], fake_encode)                # too long


def test_player_patches_tell_apart_players_with_the_same_kanji():
    kanji = (0x300, 0x301, 0, 0, 0, 0)
    record = lambda call: struct.pack(">6H", *kanji) + struct.pack(">3H", 1, 2, call)       # name, a, b, call id
    data = record(10) + record(20) + bytes(24)
    rel = FakeRel("main_prg.rel", [b"", b"", b"", b"", b"", data])
    saved = table.PLAYER_REGIONS
    table.PLAYER_REGIONS = [(0, 36, 2)]
    try:
        out = table.player_patches(rel, [(0, 10, "Aoki"), (18, 20, "Baba")], fake_encode)
    finally:
        table.PLAYER_REGIONS = saved
    assert out[0][:2] == struct.pack(">H", fake_encode(table.plate("Aoki"))[0])
    assert out[18][:2] == struct.pack(">H", fake_encode(table.plate("Baba"))[0])


def test_code_name_words_keep_the_shape_of_the_original_ten_words():
    original = table.CODE_NAME_ORIGINAL
    words = table.code_name_words("Okui", fake_encode)
    assert len(words) == len(original) == 10
    assert words[2] == original[2] and words[3] == original[3] and words[4] == original[4]       # the unchanged words
    assert raises(ValueError, table.code_name_words, "Abcdefgh", fake_encode)                    # more than three cells


def test_code_patches_on_a_made_up_module():
    """A module whose code is exactly what code_patches expects is accepted; a wrong instruction is refused."""
    spec = table.READERS["sct_main.rel"]
    code = bytearray(0xD000)
    for at in spec["mulli"]:
        struct.pack_into(">I", code, at, 7 << 26 | 3 << 21 | 4 << 16 | table.OLD_STRIDE)       # mulli r3, r4, 10
    for at in spec["keep"]:
        struct.pack_into(">I", code, at, 0x80810000)
    relocs = [(1, pos, 4 if i % 2 == 0 else 6, 5, table.HOST_SECTION, table.HOST_TABLE) for i, pos in enumerate(spec["relocs"])]
    relocs += [(1, at + 2, 1, 1, 5, 0) for at in spec["keep"]]
    rel = FakeRel("sct_main.rel", [b"", bytes(code)], relocs)
    patches = table.code_patches(rel, 5)
    first_mulli = spec["mulli"][0]
    assert patches[first_mulli][1] & 0xFFFF == table.STRIDE and patches[first_mulli][0] & 0xFFFF == table.OLD_STRIDE
    struct.pack_into(">I", code, first_mulli, 0)
    assert raises(ValueError, table.code_patches, FakeRel("sct_main.rel", [b"", bytes(code)], relocs), 5)


def test_append_table_pads_to_eight_bytes_and_remaps_the_old_table():
    host = FakeRel("scc_main.rel", [b"", b"", b"", b"", b"", bytes(21)])
    data, remap = table.append_table(host, b"\xAA" * 16)
    assert len(data) == 24 + 16 and data[24:] == b"\xAA" * 16
    assert remap.new_table == 24 and remap.growth == 3 + 16
    assert remap(table.HOST_TABLE) == 24 and remap(0x10) == 0x10


def test_checked_in_surname_files_are_valid():
    names = table.load_tsv()
    assert len(names) == table.COUNT
    bad = [(i, english) for i, (_, english) in names.items() if not table.letters_ok(english)]
    assert not bad, bad[:5]
    assert len(table.plates(names)) == table.COUNT


# ── names.kyu, names.schools ───────────────────────────────────────────────

def test_pitch_name_codes_round_trip():
    for text in ("SLIDER", "HARD SLIDER", "FORK-BALL", "A1"):
        if len(text) <= kyu.MAX_LETTERS:
            assert kyu.decode(kyu.encode(text)).replace("ー", "-") == text
    assert kyu.encode("slider") == kyu.encode("SLIDER")             # lower case is written in capitals
    assert raises(ValueError, kyu.encode, "DROP CURVE")             # ten letters
    assert raises(ValueError, kyu.encode, "SLIDER!")                # no punctuation in the font


def pitch_module(names):
    """A made-up module with a block of `names` (font codes) and the table of pointers to them."""
    blk = {"section": 1, "start": 0, "end": 40, "table": 40, "count": len(names)}
    block = bytearray(40)
    relocs, at = [], 0
    for i, name in enumerate(names):
        block[at:at + len(name) + 1] = name + bytes([kyu.END])
        relocs.append((1, 40 + 4 * i, kyu.R_ADDR32, 7, 1, at))
        at += len(name) + 1
    return FakeRel("gameplay.rel", [b"", bytes(block) + bytes(4 * len(names))], relocs, mod_id=7), blk


def test_pitch_block_layout_shares_the_end_of_another_name():
    names = [kyu.encode("SLIDER"), kyu.encode("CURVE")]
    rel, blk = pitch_module(names)
    assert kyu.originals(rel, blk) == names
    block, addends, reads = kyu.layout(rel, blk, {0: "H SLIDER", 1: "SLIDER"})
    assert len(block) == 40 and block.count(bytes([kyu.END])) == 1          # SLIDER shares the bytes of H SLIDER
    assert addends[44] == addends[40] + 2                                   # it starts two letters into the longer name
    assert all(block[a:a + len(s) + 1] == s + bytes([kyu.END]) for a, s in reads.items())


def test_pitch_block_too_big_is_refused():
    rel, blk = pitch_module([kyu.encode("AB")] * 3)
    blk = dict(blk, end=8)                                                     # a block of 8 bytes
    assert raises(ValueError, kyu.layout, rel, blk, {0: "ABCDEFGH", 1: "BCDEFGHI", 2: "CDEFGHIJ"})


def test_school_name_table_is_aligned_and_closed():
    data, where = schools.table({0x10: "Kita", 0x20: "Minami East"}, fake_encode)
    assert where[0x10] == 0 and where[0x20] % 4 == 0 and len(data) % 4 == 0
    assert struct.unpack_from(">3H", data, 0)[2] == schools.NAME_END
    assert raises(ValueError, schools.table, {0x10: "Kita"}, lambda text: [0xF123])     # a control code is not a letter
    assert raises(ValueError, schools.table, {0x10: "Kita"}, lambda text: [])


def relocatable_image():
    """A tiny module image: header word 0x28 = import table, one import entry for module 7, a stream with one pointer."""
    image = bytearray(0x300)
    struct.pack_into(">2I", image, 0x28, 0x100, 8)                  # import table at 0x100, one entry
    struct.pack_into(">II", image, 0x100, 7, 0x110)                 # module 7, its stream at 0x110
    stream = [(0, scan.R_SECTION, 5, 0), (4, schools.R_ADDR32, 5, 0x20), (8, schools.R_ADDR32, 5, 0x30), (0, scan.R_END, 0, 0)]
    for k, (delta, typ, section, addend) in enumerate(stream):
        struct.pack_into(">HBBI", image, 0x110 + 8 * k, delta, typ, section, addend)
    struct.pack_into(">I", image, 0x200 + 4, 0x20)                  # the data word at section 5 + 4 holds the offset 0x20
    return bytes(image)


def test_relocation_entries_agree_with_the_builds_reader():
    from pp15.build import rebuild
    image = relocatable_image()
    mine = schools.relocation_entries(image, 0x100, 8)
    assert mine == rebuild.parse_imports(image, 0x100, 8)
    assert mine[0][0] == 7 and [e[:5] for e in mine[0][2]] == [[5, 4, 1, 5, 0x20], [5, 12, 1, 5, 0x30]]


def test_patch_pointers_turns_the_relocation_into_a_no_op_and_writes_the_address():
    image = relocatable_image()
    rel = FakeRel("sct_main.rel", [b"", b"", b"", b"", b"", bytes(0x100)], mod_id=7, section_offsets={5: 0x200})
    new_image, written = schools.patch_pointers(rel, image, {4: 0x20}, lambda offset: 0x81460000 + offset)
    assert written == {(5, 4): struct.pack(">I", 0x81460020)}
    assert new_image[0x204:0x208] == struct.pack(">I", 0x81460020)
    remaining = schools.relocation_entries(new_image, 0x100, 8)[0][2]
    assert [e[1] for e in remaining] == [12]                         # only the second pointer is still a relocation
    assert raises(ValueError, schools.patch_pointers, rel, image, {4: 0x20, 99: 0x40}, lambda offset: offset)   # a pointer not in the stream


# ── disc ───────────────────────────────────────────────────────────────────

def test_lz4_fallback_decodes_literals_and_overlapping_matches():
    # one sequence: 3 literals "abc", then a match of length 9 at distance 3 (overlaps itself); last sequence: literal "x"
    block = bytes([0x35]) + b"abc" + bytes([3, 0]) + bytes([0x10]) + b"x"
    assert lz4_fallback.decompress_block(block) == b"abcabcabcabcx"
    long_literals = bytes([0xF0, 5]) + bytes(range(20))                 # a literal run of 15 + 5 = 20 bytes
    assert lz4_fallback.decompress_block(long_literals) == bytes(range(20))
    assert lz4_fallback.decompress_block(b"") == b""


def test_wii_format_constants_are_consistent():
    assert wii_format.CLUSTER_HASH_SIZE + wii_format.CLUSTER_DATA_SIZE == wii_format.CLUSTER_SIZE
    assert wii_format.read_u32(b"\x00\x00\x01\x02", 0) == 0x102


def make_fst():
    """A file table with  /a/b.rel  and  /c.bin  : root, directory a, file b.rel, file c.bin."""
    names = b"a\0b.rel\0c.bin\0"
    entries = [struct.pack(">BBHII", 1, 0, 0, 0, 4),                    # root: the last number is the entry count
               struct.pack(">BBHII", 1, 0, 0, 0, 3),                    # directory a: ends before entry 3
               struct.pack(">BBHII", 0, 0, 2, 0x10, 100),               # b.rel at 0x10 * 4, 100 bytes
               struct.pack(">BBHII", 0, 0, 8, 0x20, 200)]               # c.bin at 0x20 * 4, 200 bytes
    return b"".join(entries) + names


def test_both_disc_tools_read_a_file_table_the_same_way():
    fst = make_fst()
    files = extract.parse_fst(fst)
    assert files == [("a/b.rel", 0x40, 100), ("c.bin", 0x80, 200)]
    assert xdelta.fst_files(fst) == {"a/b.rel": 2, "c.bin": 3}


class XorAes:
    """Stands in for pycryptodome's AES: 'decrypts' by xor with the first key byte."""
    MODE_CBC = 2

    @staticmethod
    def new(key, mode, iv):
        class Cipher:
            @staticmethod
            def decrypt(data):
                return bytes(b ^ key[0] for b in data)
        return Cipher


def test_extract_reads_across_cluster_boundaries():
    key = bytes([0x5A]) * 16
    plain = bytes((i * 7) % 251 for i in range(wii_format.CLUSTER_DATA_SIZE * 2))
    clusters = b""
    for k in range(2):
        data = plain[k * wii_format.CLUSTER_DATA_SIZE:(k + 1) * wii_format.CLUSTER_DATA_SIZE]
        clusters += bytes(wii_format.CLUSTER_HASH_SIZE) + bytes(b ^ key[0] for b in data)
    original = extract._aes
    extract._aes = lambda: XorAes
    try:
        f = io.BytesIO(bytes(100) + clusters)
        start = wii_format.CLUSTER_DATA_SIZE - 5
        assert extract.read_decrypted(f, key, 100, start, 10) == plain[start:start + 10]
        assert extract.decrypt_cluster(f, key, 100, 5) == b"\x00" * wii_format.CLUSTER_DATA_SIZE    # past the end
    finally:
        extract._aes = original


def test_extract_names_the_missing_package():
    saved = sys.modules.get("Crypto")
    sys.modules["Crypto"] = None                                         # makes `import Crypto` fail
    try:
        try:
            extract._aes()
        except ModuleNotFoundError as e:
            assert "pycryptodome" in str(e)
        else:
            raise AssertionError("no error")
    finally:
        if saved is None:
            sys.modules.pop("Crypto", None)
        else:
            sys.modules["Crypto"] = saved


def test_glyph_to_char():
    assert extract_text.glyph_to_char(283) == "あ"
    assert extract_text.glyph_to_char(706) == "亜"                       # the first kanji of JIS X 0208
    assert extract_text.glyph_to_char(0) is None
    assert extract_text.glyph_to_char(extract_text.GLYPH_KANJI_LAST + 1) is None


def test_is_quality_text_rejects_noise():
    assert extract_text.is_quality_text("あいうえお")
    assert not extract_text.is_quality_text("あい")                       # too short
    assert not extract_text.is_quality_text("ABCDE")                     # no Japanese
    assert not extract_text.is_quality_text("あ∀∀∀")       # mostly symbols


def test_extract_dialogue_finds_a_run_after_the_header():
    glyphs_ = [283, 285, 287, 289, 291]                                  # あ い う え お
    section = bytes(extract_text.SKIP_HEADER_BYTES) + b"".join(struct.pack(">H", g) for g in glyphs_) + struct.pack(">H", 0) + bytes(8)
    found = extract_text.extract_dialogue_text(section, 0, len(section))
    assert found == [(extract_text.SKIP_HEADER_BYTES, "あいうえお", "label")]
    entries = [{"text": "a"}, {"text": "b"}, {"text": "a"}]
    assert extract_text.deduplicate_entries(entries) == [{"text": "a"}, {"text": "b"}]


def test_parse_rel_header_reads_section_offsets():
    header = bytearray(0x40)
    struct.pack_into(">I", header, 0x0C, 2)                             # two sections
    struct.pack_into(">I", header, 0x10, 0x20)                          # the section table
    struct.pack_into(">II", header, 0x20, 0x101, 50)                    # bit 0 marks an executable section
    struct.pack_into(">II", header, 0x28, 0x200, 60)
    assert extract_text.parse_rel_header(bytes(header)) == [(0x100, 50), (0x200, 60)]
    assert extract_text.parse_rel_header(b"short") == []


def test_extract_text_module_list_is_plain():
    assert len(set(extract_text.TEXT_MODULES)) == len(extract_text.TEXT_MODULES)
    assert all(name.endswith(".rel") for name in extract_text.TEXT_MODULES)


# ── reference ──────────────────────────────────────────────────────────────

def test_rgb5a3_pixel_and_array_agree():
    assert mlb_assets.rgb5a3_pixel(0xFFFF) == (255, 255, 255, 255)
    assert mlb_assets.rgb5a3_pixel(0x8000 | 31 << 10) == (255, 0, 0, 255)          # opaque red
    assert mlb_assets.rgb5a3_pixel(0x0000) == (0, 0, 0, 0)                         # transparent
    values = np.array([0x0000, 0xFFFF, 0x7ABC, 0x8421, 0x1234, 0xC3E0], dtype=np.uint16)
    array = mlb_assets.rgb5a3_array(values)
    assert [tuple(int(x) for x in row) for row in array] == [mlb_assets.rgb5a3_pixel(int(v)) for v in values]


def test_undo_gx_blocks_restores_row_order():
    a = np.arange(32)                                       # 4 rows x 8 columns stored in 2 x 4 blocks
    rows = mlb_assets.undo_gx_blocks(a, 4, 8, 2, 4)
    assert rows[0].tolist() == [0, 1, 2, 3, 8, 9, 10, 11]
    assert rows[1].tolist() == [4, 5, 6, 7, 12, 13, 14, 15]
    assert rows[2].tolist() == [16, 17, 18, 19, 24, 25, 26, 27]


def make_pack(fmt, height, width, pixels):
    """A made-up .pack: one texture header at offset 0 whose pixels start at 0x40 (no palette of its own)."""
    header = struct.pack(">HHII", height, width, fmt, 0x40000000 + 0x40)
    return header + bytes(0x40 - len(header)) + pixels


def test_both_picture_decoders_agree_on_c8_and_c4():
    c8 = make_pack(mlb_assets.GX_C8, 8, 8, bytes(range(64)))
    from_python = mlb_assets.decode_c4_c8(c8)
    from_numpy = mlb_assets.decode_all(c8)
    assert len(from_python) == len(from_numpy) == 1
    image = from_python[0][1]
    assert image.getpixel((3, 1)) == (11, 11, 11, 255)              # index 1 * 8 + 3 on the grey fall-back palette
    assert np.array_equal(np.array(image), np.array(from_numpy[0][2]))
    nibbles = bytes((k % 16) << 4 | (k + 1) % 16 for k in range(0, 64, 2))        # 8 x 8 pixels, index = position mod 16
    c4 = make_pack(mlb_assets.GX_C4, 8, 8, nibbles)
    assert np.array_equal(np.array(mlb_assets.decode_c4_c8(c4)[0][1]), np.array(mlb_assets.decode_all(c4)[0][2]))
    assert mlb_assets.decode_all(bytes(200)) == []


def test_glyph_strings_finds_latin_text():
    table_ = [chr(0x4E00 + i) for i in range(mlb_assets.GLYPH_COUNT)]
    table_[0] = " "
    table_[220], table_[221], table_[222] = "A", "B", "C"
    data = struct.pack(">6H", 7, 220, 221, 222, 0xFFFF, 0)
    assert mlb_assets.glyph_strings(data, table_) == [(0, chr(0x4E00 + 7) + "ABC")]
    assert mlb_assets.glyph_strings(struct.pack(">3H", 220, 221, 0xFFFF), table_, min_letters=3) == []


def test_project_reads_a_made_up_archive():
    data = bytearray(0x1000)
    header = [0] * 16
    header[3], header[5], header[10], header[11], header[13] = 3, 0x900, 0xA00, 0xA10, 4
    struct.pack_into(">16I", data, 0, *header)
    struct.pack_into(">3I", data, 0x800, 0, 0, 0)                      # record offsets, indexed by id + 1
    struct.pack_into(">7I", data, 0x900, 0, 1, 2, 0x800, 0, 0, 1234)   # name offset 1, size 1234
    struct.pack_into(">II", data, 0xA00, 1, 5)                         # id 1 starts at sector 5
    data[0xA10:0xA20] = b"\0/a.pack\0"
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(bytes(data))
        f.flush()
        project = mlb_assets.Project(f.name)
    assert project.files == {"/a.pack": (4 + 5 * 0x800, 1234)}


def test_sheets_have_the_expected_size():
    from PIL import Image
    images = [Image.new("RGBA", (10, 6), (255, 0, 0, 255)) for _ in range(5)]
    with tempfile.TemporaryDirectory() as folder:
        mlb_assets.contact_sheet(images, os.path.join(folder, "a.png"), columns=2)
        assert Image.open(os.path.join(folder, "a.png")).size == (20, 18)
        mlb_assets.pack_sheet(images, os.path.join(folder, "b.png"), width=30)
        assert Image.open(os.path.join(folder, "b.png")).size == (30, 22)
        mlb_assets.contact_sheet([], os.path.join(folder, "none.png"))
        assert not os.path.exists(os.path.join(folder, "none.png"))


def test_mlb_labels_grey_levels():
    indices = np.array([[0, 1], [8, 15]])
    out = mlb_labels.grey(indices, mlb_labels.GX_C4)
    assert out[1, 1].tolist() == [255, 255, 255, 255] and out[0, 0, 3] == 0
    transparent_palette = np.zeros((16, 4), np.uint8)
    assert np.array_equal(mlb_labels.rgba(indices, transparent_palette, 8), out)
    palette = np.full((16, 4), 255, np.uint8)
    assert mlb_labels.rgba(indices, palette, 8).shape == (2, 2, 4)


# ── kit ────────────────────────────────────────────────────────────────────

def test_translation_memory_helpers():
    assert export_tm.hash4("abc") == "a999"                              # first four digits of sha1("abc")
    assert export_tm.flatten("a\tb\r\nc") == "a b \\nc"
    with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False, encoding="utf-8") as f:
        f.write("# comment\n1:2\t0\ta999\tHello\n3\t4\tbeef\n\n")
    try:
        found = export_tm.read_translation_tsv(f.name, 2)
        assert found == {("1:2", "0"): ("a999", "Hello"), ("3", "4"): ("beef", "")}
        assert export_tm.read_translation_tsv(f.name + ".missing", 2) == {}
    finally:
        os.remove(f.name)


# ── config and command line ────────────────────────────────────────────────

def test_config_paths_follow_the_environment():
    code = "from pp15 import config; print(config.ROOT, config.DATA_FILES, config.KIT_TM_DIR)"
    env = dict(os.environ, PP15_ROOT="/somewhere/repo", PP15_KIT="/somewhere/kit", PYTHONPATH=ROOT)
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == "/somewhere/repo" and out[1] == "/somewhere/repo/DATA/files"
    assert out[2] == "/somewhere/kit/pawapuro15-wii/tm"


def test_every_command_names_a_module_that_exists_and_has_main():
    for name, (command, module, prefix, summary, usage) in cli.BY_NAME.items():
        if module == "golden":
            assert os.path.exists(os.path.join(config.TESTS_DIR, "golden.py"))
            continue
        assert importlib.util.find_spec(module) is not None, (name, module)
    for name in cli.NATIVE_HELP:
        assert name in cli.BY_NAME, name


def test_cli_overview_unknown_command_and_native_help():
    assert all(name in cli.overview() for name in cli.BY_NAME)
    with contextlib.redirect_stderr(io.StringIO()):
        assert cli.main(["no-such-command"]) == 2
    for command in ("names", "kyu-names", "extract-iso", "ram-scan", "release", "export-tm", "mlb-assets", "mlb-labels", "extract-text"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            try:
                cli.main([command, "--help"])
            except SystemExit as e:
                assert e.code == 0
        assert "usage: pp15 " + command in out.getvalue(), command


def test_names_subcommands_exist():
    from pp15.names import commands
    parser = commands.build_parser()
    for command in ("export", "check", "export-given", "export-draft", "export-holders", "export-foreign"):
        assert parser.parse_args([command]).command == command


if __name__ == "__main__":
    tests = [(name, function) for name, function in sorted(globals().items()) if name.startswith("test_") and callable(function)]
    for name, function in tests:
        function()
    print("all %d tests passed" % len(tests))
