"""Read the MLB Power Pros (Wii) discs as a reference: list their files, decode their pictures, find their English text.

Why: MLB Power Pros is the American release of the same game series, so its English menus and lettering show how the
series itself words and draws things. The extracted discs are game data: keep them outside this repository.

    pp15 mlb-assets list PROJECT.BIN [TEXT]          file names and sizes (only those containing TEXT)
    pp15 mlb-assets sheet PROJECT.BIN NAME OUT.png   contact sheet of the pictures in one .pack file
    pp15 mlb-assets textures DISC_FILES_DIR OUT_DIR  one sheet per UI .pack in OUT_DIR/tex, and textures.tsv
    pp15 mlb-assets text DISC_FILES_DIR OUT_DIR      every English string of the disc to OUT_DIR/text.tsv

File formats in simple words
- project.bin is the disc's archive of ~2,000 files. It starts with 16 big-endian 32-bit header words (word 3 = number
  of records, 5 = record table, 10 = index table, 11 = name table, 13 = where the data starts); the sector size is
  0x800. The index table holds (id, start sector) pairs; the record of id + 1 is 7 words: 0, name offset, sectors,
  0x800, 0, 0, size in bytes.
- A .pack file starts with "PACKWII " and holds pictures ("textures") for the Wii's graphics chip (GX). A texture has
  a header of height and width (16 bits each), the GX pixel format (32 bits) and a pointer (0x40000000 + file offset)
  to its pixels; a palette (RGB5A3 colours, see rgb5a3_pixel) sits just before the pixels when the texture has its own.
  Pixels are stored in small blocks, not row by row. Formats seen in the UI: 8 (C4: 4-bit palette index) and
  9 (C8: 8-bit palette index); decode_all also reads the other uncompressed ones.
- English text in the disc is stored as 16-bit glyph strings with the glyph numbers of Pawapuro 15 (0 = space,
  220 = A, 252 = a), each closed by 0xFFFF.

Public: Project (the archive), rgb5a3_pixel / rgb5a3_array (colours), decode_c4_c8 / decode_all (pictures), contact_sheet /
pack_sheet (save pictures on one sheet), glyph_strings / extract_text / extract_textures (whole-disc scans), main.
"""
import argparse
import bisect
import collections
import os
import struct
import sys
import unicodedata
from typing import Dict, List, Optional, Tuple

import numpy as np
from PIL import Image

from pp15 import glyphs

SECTOR_SIZE = 0x800
HEADER_READ_BYTES = 0x100000            # the archive's tables lie within the first MB
FILE_OFFSETS_AT = 0x800                 # table of the offset of each record, right after the header sector
PACK_MAGIC = b"PACKWII"
GX_POINTER_TAG = 4                      # the top four bits of a texture's pixel pointer (0x4...): "offset in this file"
MAX_HEADER_TO_PIXELS = 64 + 512         # a texture's palette and header lie within this many bytes before its pixels
# GX texture formats this module knows (the number stored in the texture header)
GX_I4, GX_I8, GX_IA4, GX_IA8, GX_RGB565, GX_RGB5A3, GX_RGBA32, GX_C4, GX_C8 = 0, 1, 2, 3, 4, 5, 6, 8, 9
GX_CMPR = 14                            # compressed; skipped
GLYPH_COUNT = 282                       # glyph numbers 0..281 are the English font (space, digits, letters, symbols)
LATIN_GLYPH_FIRST, LATIN_GLYPH_LAST = 220, 277      # A-Z, a-z and a few more
CONTROL_CODE_MIN = 0xF000               # glyph values from here are control codes, written as {XXXX}
GLYPH_END = 0xFFFF
DEFAULT_SHEET_COLUMNS = 4
SKIPPED_PACK_PREFIXES = ('PWM_', 'stadium', 'model', 'debug', 'test', 'pw_mdl')    # 3D models and debug data: no UI lettering


class Project:
    """The archive project.bin: `files` maps a file name to (offset in project.bin, size)."""

    def __init__(self, path: str):
        self.file = open(path, 'rb')
        data = self.file.read(HEADER_READ_BYTES)
        header = struct.unpack_from('>16I', data, 0)
        record_count, records_at, index_at, names_at, self.data_start = header[3], header[5], header[10], header[11], header[13]
        record_offsets = struct.unpack_from('>%dI' % record_count, data, FILE_OFFSETS_AT)
        self.files: Dict[str, Tuple[int, int]] = {}
        for k in range((names_at - index_at) // 8):
            file_id, start_sector = struct.unpack_from('>II', data, index_at + k * 8)
            if not file_id:
                continue
            record = struct.unpack_from('>7I', data, records_at + record_offsets[file_id + 1])
            name_end = data.index(b'\0', names_at + record[1])
            name = data[names_at + record[1]:name_end].decode('latin1')
            self.files[name] = (self.data_start + start_sector * SECTOR_SIZE, record[6])

    def read(self, name: str) -> bytes:
        """The bytes of the file `name`."""
        offset, size = self.files[name]
        self.file.seek(offset)
        return self.file.read(size)


# ── Colours and pictures ───────────────────────────────────────────────────

def rgb5a3_pixel(value: int) -> Tuple[int, int, int, int]:
    """One RGB5A3 colour (the Wii's 16-bit palette format) as (red, green, blue, alpha), each 0-255.
    Top bit set: opaque, 5 bits per colour. Top bit clear: 3-bit alpha and 4 bits per colour."""
    if value & 0x8000:
        return ((value >> 10 & 31) * 255 // 31, (value >> 5 & 31) * 255 // 31, (value & 31) * 255 // 31, 255)
    return ((value >> 8 & 15) * 17, (value >> 4 & 15) * 17, (value & 15) * 17, (value >> 12 & 7) * 255 // 7)


def decode_c4_c8(data: bytes) -> List[Tuple[int, Image.Image]]:
    """The C4 and C8 textures of a PACKWII file, decoded pixel by pixel in plain Python.

    Returns [(offset of the texture header, RGBA image)]. A texture without a palette of its own reuses the previous
    palette of the same format, or falls back to grey levels."""
    out, last_palette = [], {}
    for offset in range(0, len(data) - 44, 4):
        height, width, fmt, pointer = struct.unpack_from('>HHII', data, offset)
        pixels_at = pointer & 0xFFFFFFF
        if not (fmt in (GX_C4, GX_C8) and 8 <= width <= 1024 and 8 <= height <= 1024 and width % 8 == 0 and height % 4 == 0
                and pointer >> 28 == GX_POINTER_TAG and offset < pixels_at < len(data)
                and pixels_at - offset <= MAX_HEADER_TO_PIXELS):
            continue
        palette_size = {GX_C4: 16, GX_C8: 256}[fmt]
        if pixels_at - offset >= 64 + palette_size * 2:
            last_palette[fmt] = [rgb5a3_pixel(x) for x in struct.unpack_from('>%dH' % palette_size, data, pixels_at - palette_size * 2)]
        palette = last_palette.get(fmt) or [(i * 255 // (palette_size - 1),) * 3 + (255,) for i in range(palette_size)]
        image = Image.new('RGBA', (width, height))
        px = image.load()
        i = pixels_at
        try:
            if fmt == GX_C8:                    # blocks of 8 x 4 pixels, one byte each
                for block_y in range(0, height, 4):
                    for block_x in range(0, width, 8):
                        for y in range(4):
                            for x in range(8):
                                px[block_x + x, block_y + y] = palette[data[i]]
                                i += 1
            else:                               # C4: blocks of 8 x 8 pixels, two pixels per byte, high nibble first
                nibble = pixels_at * 2
                for block_y in range(0, height, 8):
                    for block_x in range(0, width, 8):
                        for y in range(8):
                            for x in range(8):
                                px[block_x + x, block_y + y] = palette[(data[nibble // 2] >> (4 if nibble % 2 == 0 else 0)) & 15]
                                nibble += 1
        except IndexError:
            continue
        out.append((offset, image))
    return out


def contact_sheet(images: List[Image.Image], path: str, columns: int = DEFAULT_SHEET_COLUMNS,
                  background: Tuple[int, int, int, int] = (60, 60, 60, 255)) -> None:
    """Save the images in a grid (cells as big as the biggest image) as a PNG. Writes nothing for an empty list."""
    if not images:
        return
    cell_width = max(im.width for im in images)
    cell_height = max(im.height for im in images)
    rows = (len(images) + columns - 1) // columns
    sheet = Image.new('RGBA', (cell_width * columns, cell_height * rows), background)
    for k, image in enumerate(images):
        sheet.alpha_composite(image, ((k % columns) * cell_width, (k // columns) * cell_height))
    sheet.convert('RGB').save(path)


def glyph_strings(data: bytes, table: List[str], min_letters: int = 2) -> List[Tuple[int, str]]:
    """Find English text in a binary: runs of 16-bit glyph numbers closed by 0xFFFF that read as Latin text.

    Arguments: `data` the file bytes, `table` the character of each glyph number 0..281, `min_letters` the fewest Latin
    letters a run must have. Returns [(byte offset, text)]. Control codes (0xF000 and up) are written as {XXXX}."""
    halfwords = np.frombuffer(data[:len(data) // 2 * 2], dtype='>u2')
    valid = (halfwords <= GLYPH_COUNT - 1) | ((halfwords >= CONTROL_CODE_MIN) & (halfwords != GLYPH_END))
    edges = np.flatnonzero(np.diff(np.r_[False, valid, False].astype(np.int8)))
    out = []
    for start, end in zip(edges[::2], edges[1::2]):
        if end >= len(halfwords) or halfwords[end] != GLYPH_END or end - start < 2:
            continue
        run = halfwords[start:end]
        letters = int(((run >= LATIN_GLYPH_FIRST) & (run <= LATIN_GLYPH_LAST)).sum())
        glyph_count = int((run <= GLYPH_COUNT - 1).sum())
        if letters < min_letters or letters * 2 < glyph_count - int((run == 0).sum()):
            continue
        text = ''.join(table[x] if x <= GLYPH_COUNT - 1 else '{%04X}' % x for x in run)
        out.append((int(start) * 2, unicodedata.normalize('NFKC', text).strip()))
    return out


def extract_text(disc: str, out_dir: str) -> List[Tuple[str, int, str]]:
    """Write every English string of a disc to OUT_DIR/text.tsv (file, offset, text); returns the rows.

    `disc` is the folder with project.bin and ovl_main.rel. Strings found inside project.bin are given as the name of
    the archived file they lie in and the offset inside it."""
    table = [glyphs.glyph_to_char(i) for i in range(GLYPH_COUNT)]
    table[0] = ' '
    os.makedirs(out_dir, exist_ok=True)
    project = Project(os.path.join(disc, 'project.bin'))
    starts = sorted((offset, name) for name, (offset, size) in project.files.items())
    rows = []
    for filename in ('ovl_main.rel', 'project.bin'):
        with open(os.path.join(disc, filename), 'rb') as f:
            data = f.read()
        for offset, text in glyph_strings(data, table):
            name = filename
            if filename == 'project.bin':
                k = bisect.bisect_right(starts, (offset, '~')) - 1
                name = starts[k][1] if k >= 0 else filename
                offset -= starts[k][0] if k >= 0 else 0
            rows.append((name, offset, text))
    with open(os.path.join(out_dir, 'text.tsv'), 'w', encoding='utf-8') as f:
        for row in rows:
            f.write('%s\t%d\t%s\n' % row)
    return rows


# ── All GX formats, with numpy ─────────────────────────────────────────────

def undo_gx_blocks(a, h, w, bh, bw):
    """Undo the GX block order: `a` holds h*w items stored in blocks of bh rows x bw columns, block after block.
    Returns them in normal row order (h, w, ...)."""
    return a.reshape(h // bh, w // bw, bh, bw, *a.shape[1:]).swapaxes(1, 2).reshape(h, w, *a.shape[1:])


def rgb5a3_array(v):
    """An array of RGB5A3 colours (the Wii's 16-bit format) as an array (..., 4) of red, green, blue, alpha, 0-255."""
    v = v.astype(np.uint32)
    opaque = (v & 0x8000) != 0
    r = np.where(opaque, (v >> 10 & 31) * 255 // 31, (v >> 8 & 15) * 17)
    g = np.where(opaque, (v >> 5 & 31) * 255 // 31, (v >> 4 & 15) * 17)
    b = np.where(opaque, (v & 31) * 255 // 31, (v & 15) * 17)
    alpha = np.where(opaque, 255, (v >> 12 & 7) * 255 // 7)
    return np.stack([r, g, b, alpha], -1).astype(np.uint8)


# pp15/art/labels.py and pp15/art/textures.py still call these two helpers by their old private names; remove the
# aliases once those modules use undo_gx_blocks and rgb5a3_array.
_blocks = undo_gx_blocks
_rgb5a3 = rgb5a3_array

# Bytes of pixel data per texture, by GX format
_PIXEL_BYTES = {GX_I4: lambda w, h: w * h // 2, GX_C4: lambda w, h: w * h // 2, GX_I8: lambda w, h: w * h,
                GX_IA4: lambda w, h: w * h, GX_C8: lambda w, h: w * h, GX_IA8: lambda w, h: w * h * 2,
                GX_RGB565: lambda w, h: w * h * 2, GX_RGB5A3: lambda w, h: w * h * 2, GX_RGBA32: lambda w, h: w * h * 4}


def decode_all(data: bytes) -> List[Tuple[int, int, Image.Image]]:
    """Every texture header found in a .pack, decoded: [(offset of the header, GX format, RGBA image)].

    Handles I4, I8, IA4, IA8, C4, C8, RGB565, RGB5A3 and RGBA32; CMPR (compressed) is skipped. A texture without a
    palette of its own reuses the previous palette of its format, or falls back to grey levels."""
    word_count = len(data) // 4
    words = np.frombuffer(data[:word_count * 4], dtype='>u4')
    # a texture header is (height << 16 | width), format, pointer: look at every word as a possible start
    heights, widths = (words >> 16).astype(np.int64), (words & 0xFFFF).astype(np.int64)
    formats, pointers = np.r_[words[1:], 0], np.r_[words[2:], 0, 0]
    offsets = np.arange(word_count, dtype=np.int64) * 4
    pixels_at = (pointers & 0x0FFFFFFF).astype(np.int64)
    candidates = (np.isin(formats, (GX_I4, GX_I8, GX_IA4, GX_IA8, GX_RGB565, GX_RGB5A3, GX_RGBA32, GX_C4, GX_C8))
                  & (pointers >> 28 == GX_POINTER_TAG) & (pixels_at > offsets) & (pixels_at - offsets <= 0x400)
                  & (heights >= 8) & (heights <= 1024) & (widths >= 8) & (widths <= 1024)
                  & (heights % 4 == 0) & (widths % 8 == 0))
    out, last_palette = [], {}
    for i in np.flatnonzero(candidates):
        h, w, fmt, q, o = int(heights[i]), int(widths[i]), int(formats[i]), int(pixels_at[i]), int(offsets[i])
        size = _PIXEL_BYTES[fmt](w, h)
        if q + size > len(data) or (fmt in (GX_I4, GX_C4) and h % 8):
            continue
        raw = np.frombuffer(data, dtype=np.uint8, count=size, offset=q)
        if fmt in (GX_C4, GX_C8):
            n = 16 if fmt == GX_C4 else 256
            if q - o >= 64 + n * 2:
                last_palette[fmt] = rgb5a3_array(np.frombuffer(data, dtype='>u2', count=n, offset=q - n * 2))
            palette = last_palette.get(fmt)
            if palette is None:
                grey = (np.arange(n) * 255 // (n - 1)).astype(np.uint8)
                palette = np.stack([grey, grey, grey, np.full(n, 255, np.uint8)], -1)
        if fmt in (GX_I4, GX_C4):
            nibbles = np.stack([raw >> 4, raw & 15], -1).reshape(-1)
            index = undo_gx_blocks(nibbles, h, w, 8, 8)
            img = palette[index] if fmt == GX_C4 else np.stack([index * 17] * 3 + [np.full_like(index, 255)], -1)
        elif fmt in (GX_I8, GX_C8):
            index = undo_gx_blocks(raw, h, w, 4, 8)
            img = palette[index] if fmt == GX_C8 else np.stack([index] * 3 + [np.full_like(index, 255)], -1)
        elif fmt == GX_IA4:
            v = undo_gx_blocks(raw, h, w, 4, 8)
            img = np.stack([(v & 15) * 17] * 3 + [(v >> 4) * 17], -1)
        elif fmt == GX_IA8:
            v = undo_gx_blocks(raw.reshape(-1, 2), h, w, 4, 4)
            img = np.stack([v[..., 1]] * 3 + [v[..., 0]], -1)
        elif fmt in (GX_RGB565, GX_RGB5A3):
            v = undo_gx_blocks(np.frombuffer(data, dtype='>u2', count=w * h, offset=q), h, w, 4, 4)
            if fmt == GX_RGB5A3:
                img = rgb5a3_array(v)
            else:
                v = v.astype(np.uint32)
                img = np.stack([(v >> 11) * 255 // 31, (v >> 5 & 63) * 255 // 63, (v & 31) * 255 // 31,
                                np.full_like(v, 255)], -1)
        else:                                   # RGBA32: 4 x 4 blocks of 16 alpha/red pairs then 16 green/blue pairs
            alpha_red = raw.reshape(h // 4, w // 4, 64)[:, :, :32].reshape(h // 4, w // 4, 4, 4, 2)
            green_blue = raw.reshape(h // 4, w // 4, 64)[:, :, 32:].reshape(h // 4, w // 4, 4, 4, 2)
            img = np.concatenate([alpha_red[..., 1:2], green_blue, alpha_red[..., 0:1]], -1).swapaxes(1, 2).reshape(h, w, 4)
        out.append((o, fmt, Image.fromarray(np.ascontiguousarray(img).astype(np.uint8), 'RGBA')))
    return out


def pack_sheet(images: List[Image.Image], path: str, width: int = 1024,
               background: Tuple[int, int, int, int] = (70, 70, 70, 255)) -> None:
    """Save the images on one sheet, shelf by shelf (a new row when the next image does not fit `width`)."""
    x = y = row_height = 0
    positions = []
    for image in images:
        if x + image.width > width and x:
            x, y, row_height = 0, y + row_height + 2, 0
        positions.append((x, y))
        x += image.width + 2
        row_height = max(row_height, image.height)
    sheet = Image.new('RGBA', (width, y + row_height), background)
    for image, xy in zip(images, positions):
        sheet.alpha_composite(image, xy)
    sheet.convert('RGB').save(path)


def extract_textures(disc: str, out_dir: str, skip: Tuple[str, ...] = SKIPPED_PACK_PREFIXES) -> list:
    """One sheet per .pack in OUT_DIR/tex, and OUT_DIR/textures.tsv: pack, textures, formats, CMPR count, pixels.

    `disc` is the folder with project.bin; packs whose name starts with one of `skip` are left out. Returns the rows."""
    project = Project(os.path.join(disc, 'project.bin'))
    os.makedirs(os.path.join(out_dir, 'tex'), exist_ok=True)
    rows = []
    for name in sorted(project.files):
        base = name.lstrip('/')
        if not base.endswith('.pack') or base.startswith(skip):
            continue
        data = project.read(name)
        if data[:7] != PACK_MAGIC:
            continue
        textures = decode_all(data)
        compressed = data.count(b'\x00\x00\x00\x0e\x40')          # header words of CMPR textures (format 14, tag 4)
        if textures:
            pack_sheet([im for _, _, im in textures], os.path.join(out_dir, 'tex', base[:-5] + '.png'))
        format_counts = collections.Counter(fmt for _, fmt, _ in textures)
        rows.append((base, len(textures), ' '.join('%d:%d' % kv for kv in sorted(format_counts.items())), compressed,
                     sum(im.width * im.height for _, _, im in textures)))
    with open(os.path.join(out_dir, 'textures.tsv'), 'w') as f:
        for row in rows:
            f.write('%s\t%d\t%s\t%d\t%d\n' % row)
    return rows


# ── Command line ───────────────────────────────────────────────────────────

def _command_list(args: argparse.Namespace) -> None:
    for name, (offset, size) in sorted(Project(args.project).files.items()):
        if args.text is None or args.text.lower() in name.lower():
            print('%9d  %s' % (size, name))


def _command_sheet(args: argparse.Namespace) -> None:
    contact_sheet([im for _, im in decode_c4_c8(Project(args.project).read(args.name))], args.out)


def _command_text(args: argparse.Namespace) -> None:
    print(len(extract_text(args.disc, args.out_dir)), 'strings')


def _command_textures(args: argparse.Namespace) -> None:
    rows = extract_textures(args.disc, args.out_dir)
    print(len(rows), 'packs,', sum(r[1] for r in rows), 'textures')


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 mlb-assets COMMAND ...`. `argv` defaults to sys.argv[1:]; with no command the help is printed."""
    parser = argparse.ArgumentParser(prog="pp15 mlb-assets", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    p = sub.add_parser("list", help="file names and sizes of project.bin")
    p.add_argument("project", metavar="PROJECT.BIN")
    p.add_argument("text", nargs="?", help="only names that contain this text")
    p.set_defaults(function=_command_list)
    p = sub.add_parser("sheet", help="contact sheet of the pictures in one .pack file")
    p.add_argument("project", metavar="PROJECT.BIN")
    p.add_argument("name", help="the .pack file name inside project.bin")
    p.add_argument("out", metavar="OUT.png")
    p.set_defaults(function=_command_sheet)
    p = sub.add_parser("text", help="every English string of the disc to OUT_DIR/text.tsv")
    p.add_argument("disc", metavar="DISC_FILES_DIR", help="folder with project.bin and ovl_main.rel")
    p.add_argument("out_dir", metavar="OUT_DIR")
    p.set_defaults(function=_command_text)
    p = sub.add_parser("textures", help="one sheet per UI .pack in OUT_DIR/tex, and textures.tsv")
    p.add_argument("disc", metavar="DISC_FILES_DIR", help="folder with project.bin")
    p.add_argument("out_dir", metavar="OUT_DIR")
    p.set_defaults(function=_command_textures)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.command is None:
        parser.print_help()
        return
    args.function(args)


if __name__ == '__main__':
    main()
