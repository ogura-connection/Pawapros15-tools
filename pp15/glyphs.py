"""The game's character table: which picture ("glyph") stands for which letter, and how the font pictures are stored.

The game does not store text as letters. Every character on screen is a number, the "glyph number", that selects one
picture in the font file `fonttex2.rel` (see docs/GLOSSARY.md, "Glyph"). The 3,744 pictures follow the order of the
Japanese industrial standard character table JIS X 0208: symbols, digits, Latin letters, hiragana, katakana (the two
Japanese syllable alphabets), Greek and Cyrillic first, then about 3,000 kanji (Chinese-derived characters).

Two kinds of text are kept in plain 16-bit form in the game's code modules:
  * glyph strings: big-endian 16-bit numbers whose low 13 bits are the glyph number and whose top 3 bits are flags,
    ended by 0x1FFF (or 0x0000). The menu text of scs_main.rel section 5 is of this kind.
  * Shift-JIS strings: ordinary text used by debug messages inside the program code.
The story dialogue uses a third, packed form that is read by pp15/script/packed_text.py.

The font pictures are 11 bytes wide and 28 rows high with 4-bit grey levels, compressed by a bit-level scheme in which
each column remembers the value above it (`decompress_glyph`).

Public names:
  glyph_to_char(g), char_to_glyph(ch)       glyph number <-> Unicode character (None when the font has no such glyph)
  jis_to_char(row, col), char_to_jis(ch)    JIS X 0208 row/column <-> character
  decode_glyph_string(values)               a list of 16-bit values -> readable text
  parse_rel_header(path), read_section_data(path, section)   minimal REL module reader (pp15/script/rel.py is the full one)
  extract_glyph_strings(data), extract_sjis_strings(data), is_clean_text(text)   find text inside raw bytes
  BitReader, decompress_glyph(data), load_glyph_data(index)   read one font picture
The command line tools that use these are in pp15/glyph_cli.py (`python3 -m pp15 glyphs --help`).
"""
import os
import struct
from typing import List, Optional, Sequence, Tuple

from pp15 import config

FONTTEX2_PATH = os.path.join(config.DATA_FILES, "fonttex2.rel")

MAX_GLYPH = 3743            # the font holds glyphs 0..3743
GLYPH_MASK = 0x1FFF         # low 13 bits of a 16-bit text value are the glyph number
FLAGS_SHIFT = 13            # the top 3 bits are flags (their meaning is not known)
STRING_END = 0x1FFF         # closes a glyph string
NULL = 0x0000               # also closes a glyph string (and separates strings)

# The font table is JIS X 0208 laid out row after row, 94 characters per row.
JIS_ROW_SIZE = 94
JIS_FIRST_COL = 0x21        # the first usable column code of a JIS row
JIS_FIRST_ROW = 0x21        # JIS row 1 (symbols)
LAST_FULL_ROW_GLYPH = 657   # glyphs 0..657: JIS rows 1-7, seven full rows of 94
ROW8_FIRST_GLYPH = 658      # glyphs 658..705: the first 48 columns of JIS row 8
ROW8_SIZE = 48
KANJI_FIRST_GLYPH = 706     # glyphs 706..3743: kanji, JIS rows 0x30 and up
KANJI_FIRST_ROW = 0x30
ROW8 = 0x28

# Font file layout (fonttex2.rel)
FONT_SECTION_OFFSET = 0x2A0     # file offset of the section that holds the font
GLYPH_BYTES_W, GLYPH_ROWS = 11, 28
GLYPH_ROW_PITCH = 16            # each output row is 11 pixel bytes plus 5 padding bytes
GLYPH_OUTPUT_SIZE = 512         # 28 rows of 16 bytes, then 64 bytes of 0xFF


# ── Glyph number <-> character ────────────────────────────────────────────

def jis_to_char(j1: int, j2: int) -> str:
    """The character at JIS X 0208 row j1, column j2 (both 0x21-0x7E), or U+FFFD when it has none.

    The row and column are first turned into the two Shift-JIS bytes, which Python can decode."""
    if j1 % 2 == 1:
        s1 = (j1 + 1) // 2 + 0x70
        if s1 > 0x9F:
            s1 += 0x40
        s2 = j2 + 0x1F if j2 <= 0x5F else j2 + 0x20
    else:
        s1 = j1 // 2 + 0x70
        if s1 > 0x9F:
            s1 += 0x40
        s2 = j2 + 0x7E
    try:
        return bytes([s1, s2]).decode('shift_jis')
    except Exception:           # not a valid byte pair
        return '�'


def char_to_jis(ch: str) -> Tuple[Optional[int], Optional[int]]:
    """JIS X 0208 (row, column) of a two-byte Shift-JIS character, or (None, None) for any other character."""
    try:
        sjis = ch.encode('shift_jis')
        if len(sjis) != 2:
            return None, None
        s1, s2 = sjis
        if s1 >= 0xE0:
            s1 -= 0x40
        j1_base = (s1 - 0x70) * 2
        if s2 >= 0x9F:
            j1 = j1_base
            j2 = s2 - 0x7E
        else:
            j1 = j1_base - 1
            j2 = s2 - 0x1F if s2 <= 0x7E else s2 - 0x20
        return j1, j2
    except Exception:           # not encodable in Shift-JIS
        return None, None


def glyph_to_char(g: int) -> Optional[str]:
    """The character that glyph number g (0..3743) draws, or None when g is outside the font.

    Font layout (JIS X 0208 based, 94 characters per row, rows counted from 1):
      Glyphs 0-93, 94-187   rows 1 and 2: symbols and punctuation
      Glyphs 188-281        row 3: digits and Latin letters (the gaps between them have no character)
      Glyphs 282-375        row 4: hiragana
      Glyphs 376-469        row 5: katakana
      Glyphs 470-563        row 6: Greek letters
      Glyphs 564-657        row 7: Cyrillic letters
      Glyphs 658-705        the first 48 slots of row 8: line drawing
      Glyphs 706-3743       kanji (JIS rows 0x30 and up, 3,038 characters)
    """
    if g < 0 or g > MAX_GLYPH:
        return None
    if g <= LAST_FULL_ROW_GLYPH:
        return jis_to_char((g // JIS_ROW_SIZE) + JIS_FIRST_ROW, (g % JIS_ROW_SIZE) + JIS_FIRST_COL)
    elif g < KANJI_FIRST_GLYPH:
        return jis_to_char(ROW8, (g - ROW8_FIRST_GLYPH) + JIS_FIRST_COL)
    else:
        k = g - KANJI_FIRST_GLYPH
        return jis_to_char((k // JIS_ROW_SIZE) + KANJI_FIRST_ROW, (k % JIS_ROW_SIZE) + JIS_FIRST_COL)


def char_to_glyph(ch: str) -> Optional[int]:
    """The glyph number that draws character ch, or None when the font has no glyph for it."""
    j1, j2 = char_to_jis(ch)
    if j1 is None:
        return None

    if JIS_FIRST_ROW <= j1 <= 0x27:
        row = j1 - JIS_FIRST_ROW
        col = j2 - JIS_FIRST_COL
        if 0 <= col < JIS_ROW_SIZE:
            return row * JIS_ROW_SIZE + col
    elif j1 == ROW8:
        col = j2 - JIS_FIRST_COL
        if 0 <= col < ROW8_SIZE:
            return ROW8_FIRST_GLYPH + col
    elif j1 >= KANJI_FIRST_ROW:
        row = j1 - KANJI_FIRST_ROW
        col = j2 - JIS_FIRST_COL
        if 0 <= col < JIS_ROW_SIZE:
            g = KANJI_FIRST_GLYPH + row * JIS_ROW_SIZE + col
            if g <= MAX_GLYPH:
                return g
    return None


def decode_glyph_string(values: Sequence[int]) -> str:
    """Text of a list of 16-bit values: glyph numbers become characters, reading stops at 0x1FFF or 0.

    A value that is not a glyph is shown as [0xVVVV], a glyph with no character as [gN]. The flag bits (the top three)
    are ignored."""
    chars = []
    for v in values:
        glyph = v & GLYPH_MASK
        if v == STRING_END or v == NULL:
            break
        if 0 < glyph <= MAX_GLYPH:
            ch = glyph_to_char(glyph)
            chars.append(ch if ch else f'[g{glyph}]')
        else:
            chars.append(f'[0x{v:04X}]')
    return ''.join(chars)


# ── REL module header ─────────────────────────────────────────────────────

def parse_rel_header(filepath: str) -> Optional[dict]:
    """Section table of a REL module (a code-and-data file the game loads at run time).

    Returns {'mod_id', 'sections': [{'index', 'offset', 'size', 'bss'}], 'path'} or None for a file too short to
    hold a header. 'bss' is true for a section that is only reserved memory (nothing stored in the file)."""
    with open(filepath, "rb") as f:
        header = f.read(0x40)
        if len(header) < 0x40:
            return None

        mod_id = struct.unpack_from(">I", header, 0)[0]
        num_sections = struct.unpack_from(">I", header, 0x0C)[0]
        sec_table_off = struct.unpack_from(">I", header, 0x10)[0]

        f.seek(sec_table_off)
        sections = []
        for s in range(min(num_sections, 30)):
            raw_off = struct.unpack_from(">I", f.read(4), 0)[0]
            sec_size = struct.unpack_from(">I", f.read(4), 0)[0]
            is_bss = (raw_off & 1) != 0
            actual_off = raw_off & ~3
            sections.append({
                'index': s,
                'offset': actual_off,
                'size': sec_size,
                'bss': is_bss,
            })

    return {'mod_id': mod_id, 'sections': sections, 'path': filepath}


def read_section_data(filepath: str, section_info: dict) -> bytes:
    """The stored bytes of one section from parse_rel_header (empty for a reserved-memory section)."""
    if section_info['bss'] or section_info['size'] == 0:
        return b''
    with open(filepath, 'rb') as f:
        f.seek(section_info['offset'])
        return f.read(section_info['size'])


# ── Finding text in raw bytes ─────────────────────────────────────────────

def extract_glyph_strings(data: bytes, min_len: int = 3, terminator: int = STRING_END) -> List[dict]:
    """Every run of at least min_len valid glyph numbers in data (16-bit big-endian), ended by terminator or 0.

    Returns dicts {'offset', 'text', 'glyphs', 'length'}. Most hits in binary data are noise; filter with
    is_clean_text."""
    strings = []
    i = 0
    while i < len(data) - 1:
        val = struct.unpack_from(">H", data, i)[0]
        if 0 < val <= MAX_GLYPH:
            start = i
            glyphs = []
            j = i
            while j < len(data) - 1:
                v = struct.unpack_from(">H", data, j)[0]
                if 0 < v <= MAX_GLYPH:
                    glyphs.append(v)
                    j += 2
                elif v == terminator:
                    j += 2
                    break
                elif v == NULL:
                    j += 2
                    break
                else:
                    break

            if len(glyphs) >= min_len:
                text = ''.join(glyph_to_char(g) or '?' for g in glyphs)
                strings.append({
                    'offset': start,
                    'text': text,
                    'glyphs': glyphs,
                    'length': len(glyphs),
                })
            i = j
        else:
            i += 2
    return strings


def extract_sjis_strings(data: bytes, min_len: int = 6) -> List[dict]:
    """Shift-JIS text in data: runs of at least min_len characters with at least two Japanese ones.

    Returns dicts {'offset', 'text', 'length', 'encoding'}."""
    strings = []
    i = 0
    while i < len(data):
        chars = []
        start = i
        j = i
        while j < len(data):
            b1 = data[j]
            if (0x81 <= b1 <= 0x9F or 0xE0 <= b1 <= 0xEF) and j + 1 < len(data):
                b2 = data[j + 1]
                if 0x40 <= b2 <= 0xFC and b2 != 0x7F:
                    try:
                        ch = bytes([b1, b2]).decode('shift_jis')
                        chars.append(ch)
                        j += 2
                        continue
                    except UnicodeDecodeError:
                        break
                else:
                    break
            elif 0x20 <= b1 <= 0x7E:
                chars.append(chr(b1))
                j += 1
                continue
            elif b1 == 0x0A:
                chars.append('\n')
                j += 1
                continue
            else:
                break

        text = ''.join(chars)
        jp_count = sum(1 for c in text if ord(c) > 0x7F)
        if len(text) >= min_len and jp_count >= 2:
            strings.append({
                'offset': start,
                'text': text,
                'length': len(text),
                'encoding': 'sjis',
            })
        i = max(j, i + 1)
    return strings


def is_clean_text(text: str, min_readable: float = 0.5) -> bool:
    """True when text looks like real Japanese (kana, kanji, full-width characters, common punctuation) and not like
    program bytes that happen to decode: at least min_readable of the characters, two of them kana or kanji."""
    hiragana = sum(1 for c in text if '぀' <= c <= 'ゟ')
    katakana = sum(1 for c in text if '゠' <= c <= 'ヿ')
    kanji = sum(1 for c in text if '一' <= c <= '鿿')
    fullwidth = sum(1 for c in text if '！' <= c <= '～')
    punct = sum(1 for c in text if c in '。、！？「」『』（）・…ーゝゞ〜')

    total = len(text)
    if total == 0:
        return False
    readable = hiragana + katakana + kanji + fullwidth + punct
    return (readable / total >= min_readable and
            (hiragana + katakana + kanji) >= 2 and
            len(text) >= 3)


# ── Font pictures ─────────────────────────────────────────────────────────

class BitReader:
    """Reads single bits, most significant bit first, from a byte string; past the end it returns 0."""

    def __init__(self, data: bytes):
        self.data = data
        self.byte_idx = 0
        self.bit_idx = 0
        self.masks = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

    def read_bit(self) -> int:
        if self.byte_idx >= len(self.data):
            return 0
        bit = 1 if (self.data[self.byte_idx] & self.masks[self.bit_idx]) else 0
        self.bit_idx += 1
        if self.bit_idx > 7:
            self.bit_idx = 0
            self.byte_idx += 1
        return bit

    def read_varlen(self) -> int:
        """A small count (1-19): two bits; if they are 00, four more bits follow and the count is 4 + those."""
        a = self.read_bit()
        b = self.read_bit()
        value = a * 2 + b
        if value != 0:
            return value
        c = self.read_bit()
        d = self.read_bit()
        e = self.read_bit()
        f = self.read_bit()
        return 4 + (c * 8 + d * 4 + e * 2 + f)


def decompress_glyph(data: bytes, prev_values: Optional[Sequence[int]] = None) -> Tuple[List[int], List[int]]:
    """Decompress the stored form of one font picture.

    The stored form is: a count byte n, n bytes of control bits, then literal pixel bytes. For each of the 11
    columns the decoder either takes a literal byte or starts a run in which the same byte repeats down the
    following rows (for one or several neighbouring columns). prev_values lets a run start from the previous
    picture's values.

    Returns (pixels, values): pixels = 512 bytes (28 rows of 16 bytes: 11 pixel bytes and 5 padding bytes of 0xFF,
    then 64 bytes of 0xFF); values = the per-column state to pass in for a following picture."""
    if len(data) < 2:
        return [0xFF] * GLYPH_OUTPUT_SIZE, [0] * GLYPH_BYTES_W

    flag_count = data[0]
    bitstream = data[1:1 + flag_count]
    literals = data[1 + flag_count:]

    bits = BitReader(bitstream)
    lit_idx = 0

    def read_literal():
        nonlocal lit_idx
        if lit_idx >= len(literals):
            return 0xFF
        val = literals[lit_idx]
        lit_idx += 1
        return val

    counts = [0] * GLYPH_BYTES_W        # rows still to repeat, per column
    values = list(prev_values) if prev_values else [0] * GLYPH_BYTES_W
    output = []

    for row in range(GLYPH_ROWS):
        for slot in range(GLYPH_BYTES_W):
            if counts[slot] != 0:
                counts[slot] -= 1
                output.append(values[slot])
            else:
                bit1 = bits.read_bit()
                if bit1 == 0:
                    val = read_literal()
                    output.append(val)
                else:
                    fill_count = bits.read_varlen()         # how many neighbouring columns share the run
                    repeat_count = bits.read_varlen()       # how many rows it lasts
                    literal_byte = read_literal()
                    for i in range(fill_count):
                        target_slot = slot + i
                        if target_slot >= GLYPH_BYTES_W:
                            break
                        counts[target_slot] = repeat_count
                        values[target_slot] = literal_byte
                    counts[slot] -= 1
                    output.append(values[slot])
        output.extend([0xFF] * (GLYPH_ROW_PITCH - GLYPH_BYTES_W))

    output.extend([0xFF] * 64)
    return output, values


def load_glyph_data(glyph_index: int, font_offset: int = 0) -> Optional[bytes]:
    """The stored (compressed) bytes of font picture glyph_index from fonttex2.rel, or None past the last glyph.

    The section starts with two bytes of padding, a 16-bit glyph count, then one 32-bit offset per glyph."""
    with open(FONTTEX2_PATH, "rb") as f:
        font_base = FONT_SECTION_OFFSET + font_offset

        f.seek(font_base + 2)
        glyph_count = struct.unpack("<H", f.read(2))[0]

        if glyph_index >= glyph_count:
            return None

        offset_table_start = font_base + 4
        f.seek(offset_table_start + glyph_index * 4)
        offset = struct.unpack("<I", f.read(4))[0]

        if glyph_index + 1 < glyph_count:
            next_offset = struct.unpack("<I", f.read(4))[0]
        else:
            next_offset = offset + 256      # the last picture has no successor: read a generous 256 bytes

        glyph_data_base = offset_table_start + glyph_count * 4
        f.seek(glyph_data_base + offset)
        size = next_offset - offset
        return f.read(size)
