"""Unit tests of the picture-lettering tools (pp15/art), using small made-up inputs: no game files are needed.

    python3 tests/test_art.py        (also collected by pytest; takes a few seconds)

They cover the pure functions: pixel masks, the tag font and the styles, packing labels into free areas, decoding and
encoding texture pages (raw and packed), reading the symbols of an .arc (a tiny ELF file is built in memory), laying a
label out on a page again, painting a "paint" entry of a spec, and the command-line parsers.
The 25,575 named styles are checked by tests/test_registry.py instead.
"""
import contextlib
import io
import os
import struct
import subprocess
import sys
import tempfile

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pp15.art import (arc_banks, labels, lettering_fonts, lettering_styles, original_arc, page_codec, pixel_ops,  # noqa: E402
                      repack, sheet, spec_cli, spec_io, spec_render, strips, textures, typeset)


# ── Helpers: a tiny .arc file ────────────────────────────────────────────────────────────

def rgb5a3_word(r, g, b):
    """An opaque RGB5A3 colour from 5-bit r, g, b."""
    return 0x8000 | r << 10 | g << 5 | b


def make_arc(page_indices=None, parts=((0, 0, 0, 0, 0, 0, 16, 32),), palette_words=None):
    """Bytes of a minimal ELF object with one bank "t": one sprite opd_t_00, one raw 4-bit page tex_t00 and the
    palette pal_t. `parts` = (page, palette, y, x, y0, x0, y1, x1) per sprite part."""
    if page_indices is None:
        page_indices = np.zeros((128, 128), np.uint8)
    palette_words = palette_words or [rgb5a3_word(i * 2, i * 2, i * 2) for i in range(16)]
    data = bytearray()
    syms = []                                       # (name, offset in .data, size)
    sprite = bytes([len(parts)]) + bytes(9) + b"".join(
        arc_banks.pack_part(p[0], 0, *p[1:]) for p in parts)
    syms.append(("opd_t_00", len(data), len(sprite)))
    data += sprite
    page = page_codec.encode_indices(page_indices, 8192)
    syms.append(("tex_t00", len(data), len(page)))
    data += page
    pal = b"".join(struct.pack(">H", w) for w in palette_words)
    syms.append(("pal_t", len(data), len(pal)))
    data += pal
    strtab = bytearray(b"\0")
    entries = bytearray(16)                         # symbol 0 is empty
    for name, off, size in syms:
        entries += struct.pack(">IIIBBH", len(strtab), 0x1000 + off, size, 0, 0, 1)
        strtab += name.encode() + b"\0"
    ehsize = 0x34
    data_off = ehsize
    sym_off = data_off + len(data)
    str_off = sym_off + len(entries)
    sh_off = str_off + len(strtab)
    headers = [bytes(40),
               struct.pack(">10I", 0, 1, 0, 0x1000, data_off, len(data), 0, 0, 1, 0),
               struct.pack(">10I", 0, 2, 0, 0, sym_off, len(entries), 3, 0, 4, 16),
               struct.pack(">10I", 0, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0)]
    head = bytearray(ehsize)
    head[:4] = b"\x7fELF"
    struct.pack_into(">I", head, 0x20, sh_off)
    struct.pack_into(">HHH", head, 0x2E, 40, len(headers), 0)
    return bytes(head) + bytes(data) + bytes(entries) + bytes(strtab) + b"".join(headers)


# ── Pixel masks ──────────────────────────────────────────────────────────────────────────

def test_grow_eight_and_four_directions():
    mask = np.zeros((5, 5), bool)
    mask[2, 2] = True
    assert pixel_ops.grow(mask).sum() == 9                      # the pixel and its 8 neighbours
    assert pixel_ops.grow(mask, diagonal=False).sum() == 5      # a plus shape
    assert pixel_ops.grow(mask, 2).sum() == 25
    assert pixel_ops.grow(np.zeros((3, 3), bool), edge=True)[0, 0]      # edge=True treats the outside as set


def test_shift_moves_and_drops_what_leaves():
    mask = np.zeros((4, 4), bool)
    mask[3, 3] = True
    assert pixel_ops.shift(mask, 1, 1).sum() == 0
    moved = pixel_ops.shift(np.eye(4, dtype=bool), 1, 0)
    assert moved[1, 0] and moved[2, 1] and not moved[0, 0]


# ── Fonts and styles ─────────────────────────────────────────────────────────────────────

def test_tag_font_sets_letters_with_baseline():
    ink, base = typeset.typeset("Hi", "tag")
    assert ink.max() == 6 and ink.min() == 0
    assert ink.shape[0] == 11 and base == 11                    # capitals are 11 rows high, nothing hangs below
    spaced, _ = typeset.typeset("H i", "tag")
    assert spaced.shape[1] == ink.shape[1] + lettering_fonts.tag_font()["space"]


def test_descender_hangs_below_baseline():
    ink, base = typeset.typeset("g", "tag")
    assert ink.shape[0] == base + 3                             # TAG_DROP["g"]


def test_stacked_lines_are_centred_and_three_rows_apart():
    one, _ = typeset.typeset("HH", "tag")
    ink, base = typeset.typeset("HH\nH", "tag")
    assert ink.shape[1] == one.shape[1]
    assert ink.shape[0] == 11 + 3 + 11 and base == ink.shape[0]


def test_slanted_tag_font_is_wider_than_plain():
    plain, base = typeset.typeset("HH", "tag")
    slanted, base2 = typeset.typeset("HH", "tagi")
    assert base == base2 and slanted.shape[1] > plain.shape[1] and slanted.shape[0] == plain.shape[0]


def test_segment_cuts_at_thinnest_column():
    ink = np.zeros((6, 11), int)
    ink[:, 0:4] = 6
    ink[2, 4] = 1                                               # a thin bridge
    ink[:, 5:9] = 6
    assert lettering_fonts.segment(ink, 2) == [(0, 4), (5, 9)]


def test_clean_drops_specks_and_faint_pieces():
    ink = np.zeros((10, 10), int)
    ink[2:6, 2:6] = 6
    ink[8, 8] = 6                                               # a single pixel
    ink[0:3, 8:10] = 2                                          # a piece that never reaches level 4
    out = lettering_fonts.clean(ink)
    assert out[8, 8] == 0 and out[1, 9] == 0 and out[3, 3] == 6


def test_outlined_style_draws_ring_around_letters():
    ink = np.zeros((3, 3), int)
    ink[1, 1] = 6
    art, base = lettering_styles.outlined([0, 1, 2, 3, 4, 5, 9], 7, 8)(ink, 2)
    assert art.shape == (5, 5) and base == 3
    assert art[2, 2] == 9 and art[1, 2] == 7 and art[1, 1] == 8     # letter, side ring, diagonal ring


def test_boxed_style_cuts_the_corners():
    ink = np.full((4, 6), 6, int)
    art, base = lettering_styles.boxed([1, 2, 3, 4, 5, 6, 7], (2, 2))(ink, 4)
    assert art[0, 0] == 0 and art[0, -1] == 0 and art[-1, 0] == 0 and art[-1, -1] == 0
    assert art[art.shape[0] // 2, 0] == 1


def test_command_style_uses_plate_colour_8():
    ink = np.zeros((5, 5), int)
    ink[2, 2] = 6
    art, base = lettering_styles.style_command(ink, 4)
    assert (art == 8).any() and art.shape == (5 + 8, 5 + 8) and base == 8


def test_style_tables_load_only_when_read():
    code = ("import sys\n"
            "from pp15.art import typeset\n"
            "assert 'pp15.art.styles.match' not in sys.modules\n"
            "assert 'plate' in typeset.RENDER\n"          # a base style: but reading loads everything
            "assert 'pp15.art.styles.match' in sys.modules\n"
            "assert len(typeset.RENDER) >= 25575 and 'rounded' in typeset.TTF and 'command' in typeset.FONTS\n")
    run = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr[-1500:]


# ── Packing ──────────────────────────────────────────────────────────────────────────────

def test_shelf_pack_puts_boxes_side_by_side_and_below():
    placed = repack.shelf_pack([(10, 4), (10, 4), (20, 6)], [(0, 0, 0, 25, 20)], gap=(1, 1))
    assert placed[2] == (0, 0, 0)                               # tallest first
    assert placed[0] == (0, 0, 7) and placed[1] == (0, 11, 7)   # next shelf, one pixel gap across and down


def test_shelf_pack_raises_when_full():
    try:
        repack.shelf_pack([(30, 5)], [(0, 0, 0, 20, 20)])
    except ValueError as e:
        assert "no room" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_ribbon_pack_cuts_a_wide_line_over_rows():
    where, empty = repack.ribbon_pack([30, 10], 4, [(0, 0, 0, 20, 14)], gap=1, empty=4)
    cuts = where[0]
    assert sum(c1 - c0 for _, _, _, c0, c1 in cuts) == 30 and len(cuts) >= 2
    assert len(where[1]) == 1 and empty[0] == 0


def test_art_box_is_bounding_box_of_pixels():
    page = np.zeros((20, 20), np.uint8)
    page[5, 7] = 1
    page[8, 9] = 2
    assert repack.art_box(page, (0, 0, 20, 20)) == (7, 5, 10, 9)


# ── Texture pages ────────────────────────────────────────────────────────────────────────

def test_raw_4bit_page_round_trip():
    rng = np.random.default_rng(1)
    idx = rng.integers(0, 16, (128, 128)).astype(np.uint8)
    raw = page_codec.encode_indices(idx, 8192)
    assert len(raw) == 8192
    assert np.array_equal(page_codec.decode_indices(raw, 0, 8192), idx)


def test_raw_8bit_page_round_trip():
    rng = np.random.default_rng(2)
    idx = rng.integers(0, 256, (128, 128)).astype(np.uint8)
    raw = page_codec.encode_indices(idx, 16384)
    assert np.array_equal(page_codec.decode_indices(raw, 0, 16384), idx)


def test_packed_page_round_trip_for_4bit_and_8bit():
    idx = np.zeros((128, 128), np.uint8)
    idx[10:30, 20:60] = 5
    idx[50, 50] = 9
    for bits, raw_bytes in ((4, None), (8, None)):
        size = 4000
        packed = page_codec.encode_indices(idx, size, bits)
        assert len(packed) == size and page_codec.is_compressed(size)
        assert page_codec.page_bits(packed, 0, size) == bits
        assert np.array_equal(page_codec.decode_indices(packed, 0, size), idx)


def test_packed_page_that_does_not_fit_raises():
    noise = np.random.default_rng(3).integers(0, 16, (128, 128)).astype(np.uint8)
    try:
        page_codec.encode_indices(noise, 2000, 4)
    except ValueError as e:
        assert "needs" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_raw_size_and_page_bits():
    raw4 = bytes(8192)
    assert page_codec.page_bits(raw4, 0, 8192) == 4 and page_codec.raw_size(raw4, 0, 8192) == 8192
    raw8 = bytes(16384)
    assert page_codec.page_bits(raw8, 0, 16384) == 8 and page_codec.raw_size(raw8, 0, 16384) == 16384


# ── An .arc file ─────────────────────────────────────────────────────────────────────────

def test_elf_symbols_and_banks():
    page = np.zeros((128, 128), np.uint8)
    page[3:7, 5:9] = 4
    d = make_arc(page, parts=((0, 2, 10, 20, 3, 5, 7, 9), (0, 3, -4, 6, 0, 0, 8, 8)))
    syms = arc_banks.elf_symbols(d)
    assert set(syms) == {"opd_t_00", "tex_t00", "pal_t"}
    assert syms["tex_t00"][1] == 8192
    found = arc_banks.banks(d, syms)
    assert [b["name"] for b in found] == ["t"] and len(found[0]["pages"]) == 1
    first, second = found[0]["sprites"]["opd_t_00"]
    assert (first.page, first.palette, first.y, first.x) == (0, 2, 10, 20)
    assert (first.y0, first.x0, first.y1, first.x1) == (3, 5, 7, 9)
    assert second.y == -4
    assert d[first.offset:first.offset + 10] == arc_banks.pack_part(0, 0, 2, 10, 20, 3, 5, 7, 9)
    assert arc_banks.bank_named(found, "t") is found[0] and arc_banks.bank_named(found, "t#0") is found[0]
    assert arc_banks.elf_symbols(b"not an elf") == {}


def test_palette_colours_decode_rgb5a3():
    d = make_arc(palette_words=[rgb5a3_word(31, 0, 0)] + [0] * 15)
    bank = arc_banks.banks(d, arc_banks.elf_symbols(d))[0]
    colours = arc_banks.palette_colours(d, bank["pal"])
    assert colours.shape == (16, 4) and tuple(colours[0]) == (255, 0, 0, 255)


def test_page_colours_and_quantise_and_import_round_trip():
    page = np.zeros((128, 128), np.uint8)
    page[10:20, 10:20] = 3
    d = make_arc(page)
    bank = textures.banks(d, textures.elf_symbols(d))[0]
    off, size = bank["pages"][0]
    colours = textures.page_colours(textures.palette_colours(d, bank["pal"]), 0, size)
    assert colours.shape == (16, 4)
    image = textures.page_image(d, off, size, textures.palette_colours(d, bank["pal"]), 0)
    assert image.size == (128, 128)
    assert textures.import_page(d, off, size, image, colours) == d      # an unchanged page re-encodes byte for byte
    edited = image.copy()
    edited.putpixel((0, 0), tuple(colours[5]))
    assert textures.decode_indices(textures.import_page(d, off, size, edited, colours), off, size)[0, 0] == 5


def test_sprite_image_draws_parts_at_their_offsets():
    page = np.zeros((128, 128), np.uint8)
    page[0:4, 0:4] = 7
    d = make_arc(page, parts=((0, 0, 0, 0, 0, 0, 4, 4), (0, 0, 0, 6, 0, 0, 4, 4)))
    bank = textures.banks(d, textures.elf_symbols(d))[0]
    image = textures.sprite_image(d, bank, bank["sprites"]["opd_t_00"], bg=(0, 0, 0, 0))
    assert image.size == (10, 4)
    assert image.getpixel((1, 1))[3] == 255 and image.getpixel((5, 1))[3] == 0 and image.getpixel((7, 1))[3] == 255


def test_original_arc_bank_index_image():
    page = np.zeros((128, 128), np.uint8)
    page[0:2, 0:2] = 4
    d = make_arc(page, parts=((0, 0, 3, 5, 0, 0, 2, 2),))

    class StubArc:
        data = d
    bank = original_arc.Bank(StubArc, textures.banks(d, textures.elf_symbols(d))[0])
    img, x0, y0 = bank.index_image("00", pad=1)
    assert (x0, y0) == (4, 2) and img.shape == (4, 4) and (img[1:3, 1:3] == 4).all() and img.sum() == 16


def test_write_sprite_parts_checks_count_and_rectangle():
    d = make_arc(parts=((0, 0, 0, 0, 0, 0, 4, 4), (0, 0, 0, 0, 0, 0, 4, 4)))
    entry = {"symbol": "opd_t_00", "parts": [[1, 2, 3, 4, 0, 0, 8, 8], [0, 0, 0, 0, 1, 1, 9, 9]]}
    patches = strips.write_sprite_parts([entry], d)
    off = textures.elf_symbols(d)["opd_t_00"][0]
    assert patches[0] == (off + 10, struct.pack(">BBhhBBBB", 1, 2, 4, 3, 0, 0, 8, 8))
    for bad in ({"symbol": "opd_t_00", "parts": [[0, 0, 0, 0, 0, 0, 4, 4]]},
                {"symbol": "opd_t_00", "parts": [[0, 0, 0, 0, 0, 0, 4, 4], [0, 0, 0, 0, 0, 0, 200, 4]]}):
        try:
            strips.write_sprite_parts([bad], d)
        except ValueError:
            continue
        raise AssertionError("expected ValueError")


# ── MLB label art ────────────────────────────────────────────────────────────────────────

def test_runs_join_stretches_closer_than_gap():
    flags = np.array([0, 1, 1, 0, 1, 0, 0, 0, 0, 1], bool)
    assert labels.runs(flags, 1) == [(1, 5), (9, 10)]
    assert labels.runs(flags, 0) == [(1, 3), (4, 5), (9, 10)]


def test_find_boxes_reads_rows_then_columns():
    idx = np.zeros((30, 60), np.uint8)
    idx[5:10, 5:15] = 3
    idx[5:10, 30:40] = 3
    idx[20:25, 5:15] = 3
    boxes = labels.find_boxes(idx, 1, gap=4, halo=1)
    assert boxes == [(4, 4, 16, 11), (29, 4, 41, 11), (4, 19, 16, 26)]


def test_despeckle_removes_lone_pixel_but_keeps_thin_strokes():
    grid = np.zeros((7, 7), int)
    grid[3, 3] = 1                                              # no neighbour agrees: noise
    assert labels.despeckle(grid).sum() == 0
    line = np.zeros((7, 7), int)
    line[:, 3] = 1                                              # a one-pixel stroke keeps its neighbours
    assert np.array_equal(labels.despeckle(line), line)


def test_carve_axis_removes_columns_but_keeps_original_pixels():
    grid = np.array([[1, 1, 1, 2, 3, 3, 3, 4]] * 3)
    out = labels.carve_axis(grid, 5, 1)
    assert out.shape == (3, 5)
    assert set(out.ravel()) <= {1, 2, 3, 4} and {1, 2, 3, 4} <= set(out.ravel())      # every colour survives
    assert labels.carve_axis(grid, 3, 0).shape == (3, 8)                                # already short enough


def test_fit_carves_to_size_and_maps_roles_to_indices():
    mask = np.ones((4, 8), bool)
    cls = np.array([["fill"] * 4 + ["ring"] * 4] * 4)
    out = labels.fit(mask, cls, {"fill": 5, "ring": 9}, 4, 4)
    assert out.shape == (4, 4) and set(out.ravel()) == {5, 9}
    gradient = labels.fit(mask, cls, {"fill": [2, 6], "ring": 9}, 8, 4)
    assert gradient[0, 0] == 2 and gradient[3, 0] == 6


def test_split_words_cuts_at_the_widest_gap():
    mask = np.zeros((3, 12), bool)
    mask[:, 0:3] = True
    mask[:, 8:12] = True
    cls = np.full(mask.shape, "fill")
    words = labels.split_words(mask, cls, 2)
    assert [w[0].shape[1] for w in words] == [3, 4]


def test_draw_and_halo_on_a_page():
    page = np.zeros((20, 20), np.uint8)
    label = np.full((2, 2), 3, np.uint8)
    labels.draw(page, (0, 0, 20, 20), (4, 4, 10, 10), label)
    assert page[6:8, 6:8].sum() == 12 and page.sum() == 12
    labels.add_halo(page, (0, 0, 20, 20), (7,))
    assert page[5, 5] == 7 and page[8, 8] == 7 and page[4, 4] == 0


def test_moved_names_still_reachable_from_labels():
    assert labels.render is spec_render.render and labels.load_spec is spec_io.load_spec
    assert labels.bank_of is spec_io.bank_of and labels.main is spec_cli.main
    try:
        labels.no_such_name
    except AttributeError:
        pass
    else:
        raise AssertionError("expected AttributeError")


# ── Repack and spec rendering on a made-up file ──────────────────────────────────────────

def japanese_page():
    page = np.zeros((128, 128), np.uint8)
    page[4:12, 4:20] = 6                                        # the "Japanese" label
    return page


def test_repack_moves_a_label_and_repoints_its_sprite_part():
    d = make_arc(japanese_page(), parts=((0, 0, 0, 0, 4, 4, 12, 20),))
    bank = textures.banks(d, textures.elf_symbols(d))[0]
    group = {"bank": "t", "style": "tag", "font": "tag", "areas": [[0, 40, 40, 120, 80]],
             "labels": [{"from": [0, 4, 4, 20, 12], "text": "Hi"}]}
    pages, patches = {}, []
    rows = repack.repack(group, d, bank, pages, patches, None)
    page = pages[0]
    assert page[4:12, 4:20].sum() == 0                          # the old label is cleared
    assert page[40:80, 40:120].any()                            # the English is in the area
    assert rows[0][0] == "Hi" and len(patches) == 1
    off, data = patches[0]
    assert off == bank["sprites"]["opd_t_00"][0].offset and len(data) == 10
    new_y0, new_x0, new_y1, new_x1 = data[6], data[7], data[8], data[9]
    assert page[new_y0:new_y1, new_x0:new_x1].any()             # the part now shows the new art


def test_repack_refuses_to_clear_a_rectangle_another_sprite_uses():
    d = make_arc(japanese_page(), parts=((0, 0, 0, 0, 4, 4, 12, 20),))
    bank = textures.banks(d, textures.elf_symbols(d))[0]
    other = bank["sprites"]["opd_t_00"][0]._replace(sprite="opd_t_01", x0=10, x1=30)     # overlaps the cleared area
    bank["sprites"]["opd_t_01"] = [other]
    group = {"bank": "t", "style": "tag", "font": "tag", "areas": [[0, 40, 40, 120, 80]],
             "labels": [{"from": [0, 4, 4, 20, 12], "text": "Hi"}]}
    try:
        repack.repack(group, d, bank, {}, [], None)
    except ValueError as e:
        assert "which this group clears" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_render_spec_paint_entry_draws_text_in_a_ramp():
    d = make_arc()
    spec = {"paint": [{"bank": "t", "page": 0, "rect": [0, 0, 40, 16], "text": "Hi", "font": "tag",
                       "ramp": [1, 2, 3, 4, 5, 6, 7]}]}
    banks = textures.banks(d, textures.elf_symbols(d))
    result = spec_render.render_spec(spec, d, banks)
    page = result.pages[("t", 0)]
    assert page[0, 0] == 1 and page.max() == 7                  # plate colour everywhere, full ink = ramp[6]
    assert result.repacked[0][1:3] == ("Hi", "painted")
    pages = spec_render.render(spec, d, banks)                  # the older interface returns the pages ...
    assert np.array_equal(pages[("t", 0)], page) and spec_render.render.patches == []     # ... and keeps patches here


def test_load_spec_finds_arc_and_saved_original():
    with tempfile.TemporaryDirectory() as folder:
        arc = os.path.join(folder, "x.arc")
        open(arc, "wb").write(b"1")
        path = os.path.join(folder, "x.json")
        open(path, "w").write('{"arc": %s}' % repr(arc).replace("'", '"'))
        spec = spec_io.load_spec(path)
        assert spec["arc"] == arc and spec["source"] == arc


def test_bank_of_selects_sprites_by_prefix():
    bank = {"name": "a", "sprites": {"opd_x_00": [1], "opd_y_00": [2]}, "pages": []}
    chosen = spec_io.bank_of([bank], {"bank": "a", "sprite_prefix": "x"})
    assert list(chosen["sprites"]) == ["opd_x_00"]


# ── Sheets ───────────────────────────────────────────────────────────────────────────────

def test_sheet_helpers():
    assert list(sheet.hex_to_rgb("#ff8000")) == [255, 128, 0]
    colours = np.array([[0, 0, 0], [255, 0, 0], [0, 255, 0]], float)
    to_index = sheet.nearest(colours, [1, 2])
    assert to_index(np.array([[[250, 10, 0], [0, 200, 10]]], float)).tolist() == [[1, 2]]
    d = make_arc(japanese_page())
    bank = textures.banks(d, textures.elf_symbols(d))[0]
    assert sheet.canvas(d, bank, 1).shape == (128, 128) and sheet.bank_by_pages([bank], "tex_t") is bank


# ── Command lines ────────────────────────────────────────────────────────────────────────

def test_command_line_parsers_accept_the_documented_commands():
    art = spec_cli.build_parser()
    assert art.parse_args(["boxes", "ScsComMain", "0"]).min_index == 1
    assert art.parse_args(["apply", "specs/x.json"]).spec == "specs/x.json"
    assert art.parse_args(["restore", "x.arc"]).arc == "x.arc"
    tex = textures.build_parser()
    assert tex.parse_args(["page", "x.arc", "bank", "3", "out.png", "7"]).palette == 7
    assert tex.parse_args(["parts", "x.arc"]).page is None
    assert tex.parse_args(["check", "a.arc", "b.arc"]).arcs == ["a.arc", "b.arc"]


def test_help_exits_cleanly():
    for parser in (spec_cli.build_parser(), textures.build_parser()):
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            try:
                parser.parse_args(["--help"])
            except SystemExit as e:
                assert e.code == 0
            else:
                raise AssertionError("--help should exit")
        assert "usage:" in shown.getvalue()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = []
    for name, func in tests:
        try:
            func()
        except Exception:
            import traceback
            print("FAILED", name)
            traceback.print_exc()
            failed.append(name)
    if failed:
        sys.exit("%d of %d art tests failed" % (len(failed), len(tests)))
    print("%d art tests passed" % len(tests))
