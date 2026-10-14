#!/usr/bin/env python3
"""
Text insertion tool for Jikkyou Powerful Pro Yakyuu 15 fan translation.

Reads English translations from translation_english.json and writes them to game REL files.
Handles:
  - ASCII to glyph index mapping (JIS row 0x23 full-width ASCII area)
  - Text encoding as 16-bit big-endian halfwords
  - Fixed-size entries (40-byte menus, 10-byte names)
  - Variable-length dialogue (0xFFFF terminator)
  - REL file format preservation
  - Font injection
"""

import json
import struct
import os
import sys
from pathlib import Path


# ==============================================================================
# GLYPH MAPPING: ASCII → JIS X 0208 → Glyph Index
# ==============================================================================

def get_jis_glyph_index(j1, j2):
    """Convert JIS (j1, j2) to glyph index.

    Glyphs 0-657:   JIS rows 0x21-0x27 (7 rows × 94 = 658)
    Glyphs 658-705: JIS row 0x28 (48 slots)
    Glyphs 706+:    Kanji (rows 0x30+)
    """
    if 0x21 <= j1 <= 0x27:
        return (j1 - 0x21) * 94 + (j2 - 0x21)
    elif j1 == 0x28:
        return 658 + (j2 - 0x21)
    elif j1 >= 0x30:
        return 706 + ((j1 - 0x30) * 94) + (j2 - 0x21)
    else:
        return 0  # Invalid


def ascii_to_glyph(char):
    """Map ASCII character to glyph index.

    Full-width ASCII equivalents are in JIS row 0x23, where the JIS column
    byte matches the ASCII code directly (e.g., 'T' = 0x54 → JIS 0x2354).
    ASCII 0x21 '!' → JIS 0x2321 → glyph_index = (2) * 94 + 0 = 188
    ASCII 0x22 '"' → JIS 0x2322 → glyph_index = (2) * 94 + 1 = 189
    ...
    ASCII 0x7E '~' → JIS 0x237E → glyph_index = (2) * 94 + 93 = 281
    ASCII 0x20 (space) has no JIS column (0x20 < 0x21), so we place it at
    glyph 187 (just before JIS row 0x23, i.e., the last slot of row 0x22).
    """
    char_code = ord(char)
    if char_code == 0x20:
        # Space: no JIS column for 0x20, use glyph slot 187 (row 0x22 tail)
        return 187
    elif 0x21 <= char_code <= 0x7E:
        return get_jis_glyph_index(0x23, char_code)
    else:
        return 0  # Invalid ASCII


def text_to_halfwords(text, terminator=0xFFFF, max_halfwords=None, pad_to=None, available_bytes=None):
    """Convert English text to 16-bit big-endian halfwords.

    Args:
        text: English string
        terminator: 0xFFFF for dialogue, 0x1FFF for names
        max_halfwords: Maximum number of halfwords (enforces truncation)
        pad_to: Pad output to this many halfwords with 0x0000
        available_bytes: Maximum bytes available (if larger than max_halfwords*2, ignored)

    Returns:
        bytes: Big-endian halfword sequence

    Raises:
        ValueError: If text is too long and no truncation allowed
    """
    halfwords = []

    for char in text:
        glyph_idx = ascii_to_glyph(char)
        # 16-bit big-endian halfword (lower 12 bits = glyph, upper bits = control flags, all zeros)
        halfwords.append(glyph_idx & 0x0FFF)

    # Determine size limit from most restrictive constraint
    max_hw = None
    if available_bytes:
        max_hw = available_bytes // 2
    if max_halfwords:
        max_hw = max_halfwords if max_hw is None else min(max_hw, max_halfwords)

    # Enforce max size with truncation (leave room for terminator)
    if max_hw and len(halfwords) >= max_hw:
        halfwords = halfwords[:max_hw - 1]

    # Add terminator
    halfwords.append(terminator)

    # Pad if needed
    if pad_to:
        while len(halfwords) < pad_to:
            halfwords.append(0x0000)

    # Convert to big-endian bytes
    result = b''
    for hw in halfwords:
        result += struct.pack('>H', hw)

    return result


# ==============================================================================
# REL FILE STRUCTURE
# ==============================================================================

class RELFile:
    """Minimal REL file parser/writer for data section patching."""

    def __init__(self, path):
        self.path = path
        self.data = bytearray(open(path, 'rb').read())
        self.header = self._parse_header()

    def _parse_header(self):
        """Parse REL header to find section offsets.

        REL header format (Wii/GC):
          0x00: u32 module_id
          0x04: u32 next (link, 0 in file)
          0x08: u32 prev (link, 0 in file)
          0x0C: u32 num_sections
          0x10: u32 section_info_offset
          ...
        Section info table: array of {u32 offset_flags, u32 size}
          offset_flags bit 0 = executable flag, actual offset = offset_flags & ~1
        """
        num_sections = struct.unpack_from('>I', self.data, 0x0C)[0]
        section_info_offset = struct.unpack_from('>I', self.data, 0x10)[0]

        sections = {}
        section_sizes = {}
        for i in range(num_sections):
            entry_off = section_info_offset + i * 8
            sec_off_raw = struct.unpack_from('>I', self.data, entry_off)[0]
            sec_size = struct.unpack_from('>I', self.data, entry_off + 4)[0]
            sec_off = sec_off_raw & ~1  # Strip exec flag
            if sec_off != 0 and sec_size != 0:
                sections[i] = sec_off
                section_sizes[i] = sec_size

        self._section_sizes = section_sizes
        return sections

    def get_section_base(self, section_num):
        """Get the file offset of a section."""
        if section_num in self.header:
            return self.header[section_num]
        return None

    def get_section_size(self, section_num):
        """Get the size of a section in bytes."""
        return self._section_sizes.get(section_num, 0)

    def get_section_data(self, section_num):
        """Get the raw bytes of a section."""
        base = self.get_section_base(section_num)
        size = self.get_section_size(section_num)
        if base is None or size == 0:
            return b''
        return bytes(self.data[base:base + size])

    def patch_at(self, section_num, offset_in_section, data_bytes):
        """Patch bytes at (section, offset) in the REL file.

        Args:
            section_num: Section number (4, 5, 6, etc.)
            offset_in_section: Offset within the section
            data_bytes: Bytes to write

        Raises:
            ValueError: If section doesn't exist or write overflows section
        """
        section_base = self.get_section_base(section_num)
        if section_base is None:
            raise ValueError(f"Section {section_num} not found in REL")

        section_size = self.get_section_size(section_num)
        write_end_in_section = offset_in_section + len(data_bytes)

        # CRITICAL: Enforce section boundary — never write past section end
        if write_end_in_section > section_size:
            raise ValueError(
                f"Patch would overflow section {section_num}: "
                f"offset 0x{offset_in_section:X} + {len(data_bytes)} bytes = "
                f"0x{write_end_in_section:X}, section size = 0x{section_size:X}"
            )

        file_offset = section_base + offset_in_section
        self.data[file_offset:file_offset + len(data_bytes)] = data_bytes

    def write(self, output_path):
        """Write modified REL to output file."""
        with open(output_path, 'wb') as f:
            f.write(self.data)


# ==============================================================================
# TRANSLATION PROCESSING
# ==============================================================================

def load_translations(json_path):
    """Load translation_english.json."""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data


def process_translations(translation_data):
    """Extract all non-empty English translations with location info.

    Also computes available_bytes for each string based on the distance
    to the next string in the same (file, section). This prevents
    translations from overwriting adjacent strings/data.

    Returns:
        list of dicts: [
            {
                "file": "scs_main.rel",
                "section": 5,
                "offset": 0x3328,
                "japanese": "...",
                "english": "...",
                "length": 10,
                "available_bytes": 40,
            },
            ...
        ]
    """
    # First pass: collect ALL string offsets per (file, section) for boundary computation
    all_offsets = {}  # (file, section) -> sorted list of offsets
    files = translation_data.get('files', {})
    for filename, file_data in files.items():
        strings = file_data.get('strings', [])
        for entry in strings:
            key = (filename, entry.get('section'))
            if key not in all_offsets:
                all_offsets[key] = set()
            all_offsets[key].add(entry.get('offset'))

    # Sort offset sets into lists for binary search
    for key in all_offsets:
        all_offsets[key] = sorted(all_offsets[key])

    # Second pass: extract translated entries with available_bytes
    result = []

    for filename, file_data in files.items():
        strings = file_data.get('strings', [])
        for entry in strings:
            english = entry.get('english', '').strip()
            if english and english != entry.get('japanese', '').strip():
                section = entry.get('section')
                offset = entry.get('offset')
                orig_len = entry.get('length', 0)

                # Compute available bytes: distance to next string in same section
                key = (filename, section)
                offsets = all_offsets.get(key, [])

                # Find next offset after this one
                import bisect
                idx = bisect.bisect_right(offsets, offset)
                if idx < len(offsets):
                    available = offsets[idx] - offset
                else:
                    # Last string in section — use original string size as limit
                    available = orig_len * 2 + 2  # chars * 2 bytes + terminator

                # Floor: never less than the original JP text size.
                # If computed budget < JP size, the "next string" is a false
                # positive (garbled bytecode) that the JP already overwrites.
                jp_min = orig_len * 2 + 2
                if available < jp_min:
                    available = jp_min

                result.append({
                    'file': filename,
                    'section': section,
                    'offset': offset,
                    'japanese': entry.get('japanese', ''),
                    'english': english,
                    'length': orig_len,
                    'quality': entry.get('quality'),
                    'status': entry.get('status'),
                    'available_bytes': available,
                })

    return result


# ==============================================================================
# FONT INJECTION
# ==============================================================================

class _FontBitWriter:
    """Write bits MSB-first to a byte array (for font glyph compression)."""
    def __init__(self):
        self.bytes = []
        self.current_byte = 0
        self.bit_idx = 0
        self.masks = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

    def write_bit(self, bit):
        if bit:
            self.current_byte |= self.masks[self.bit_idx]
        self.bit_idx += 1
        if self.bit_idx >= 8:
            self.bytes.append(self.current_byte)
            self.current_byte = 0
            self.bit_idx = 0

    def flush(self):
        if self.bit_idx > 0:
            self.bytes.append(self.current_byte)
            self.current_byte = 0
            self.bit_idx = 0

    def get_bytes(self):
        self.flush()
        return self.bytes


class _FontBitReader:
    """Read bits MSB-first from a byte array (for font glyph decompression)."""
    def __init__(self, data):
        self.data = data
        self.byte_idx = 0
        self.bit_idx = 0
        self.masks = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

    def read_bit(self):
        if self.byte_idx >= len(self.data):
            return 0
        bit = 1 if (self.data[self.byte_idx] & self.masks[self.bit_idx]) else 0
        self.bit_idx += 1
        if self.bit_idx > 7:
            self.bit_idx = 0
            self.byte_idx += 1
        return bit

    def read_varlen(self):
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


def _write_varlen(writer, value):
    """Write a variable-length integer (1-19) using 2+4 bit encoding."""
    if 1 <= value <= 3:
        writer.write_bit((value >> 1) & 1)
        writer.write_bit(value & 1)
    else:
        writer.write_bit(0)
        writer.write_bit(0)
        adjusted = value - 4
        writer.write_bit((adjusted >> 3) & 1)
        writer.write_bit((adjusted >> 2) & 1)
        writer.write_bit((adjusted >> 1) & 1)
        writer.write_bit(adjusted & 1)


def _decompress_patch_glyph(data):
    """Decompress a single glyph from font_patch.bin compressed format.

    Returns the 28×11 grid as a flat list of 308 byte values (no row padding).
    """
    if len(data) < 2:
        return [0] * 308

    flag_count = data[0]
    bitstream = data[1:1 + flag_count]
    literals = data[1 + flag_count:]

    bits = _FontBitReader(bitstream)
    lit_idx = 0

    def read_literal():
        nonlocal lit_idx
        if lit_idx >= len(literals):
            return 0x00
        val = literals[lit_idx]
        lit_idx += 1
        return val

    counts = [0] * 11
    values = [0] * 11
    grid = []

    for row in range(28):
        for slot in range(11):
            if counts[slot] != 0:
                counts[slot] -= 1
                grid.append(values[slot])
            else:
                bit1 = bits.read_bit()
                if bit1 == 0:
                    val = read_literal()
                    grid.append(val)
                else:
                    fill_count = bits.read_varlen()
                    repeat_count = bits.read_varlen()
                    literal_byte = read_literal()
                    for fi in range(fill_count):
                        if slot + fi < 11:
                            counts[slot + fi] = repeat_count
                            values[slot + fi] = literal_byte
                    counts[slot] -= 1
                    grid.append(values[slot])

    return grid  # 308 bytes (28 rows × 11 slots)


def _compress_glyph_rle(grid_308):
    """Compress a 28×11 glyph grid using the game's FILL/RLE format.

    Uses FILL instructions where consecutive identical values exist across
    rows (column-wise runs), and LITERAL for everything else.

    Args:
        grid_308: flat list of 308 byte values (28 rows × 11 columns)

    Returns:
        bytes: compressed glyph data
    """
    # Build 2D grid[row][slot] for easier access
    grid = []
    for row in range(28):
        grid.append(grid_308[row * 11:(row + 1) * 11])

    bit_writer = _FontBitWriter()
    literals = []
    counts = [0] * 11  # Remaining repeat count per slot (persists across rows)
    values = [0] * 11  # Cached value per slot

    for row in range(28):
        slot = 0
        while slot < 11:
            if counts[slot] > 0:
                # Slot is being filled by a previous FILL — skip it
                counts[slot] -= 1
                slot += 1
                continue

            current_byte = grid[row][slot]

            # Try FILL: find how many consecutive slots from 'slot' share the
            # same value, and how many rows that run continues downward.
            fill_count = 1
            while slot + fill_count < 11 and grid[row][slot + fill_count] == current_byte:
                # Also check that none of these further slots are mid-count
                if counts[slot + fill_count] > 0:
                    break
                fill_count += 1

            # For the run of fill_count columns, how many additional rows
            # below also have the same value?
            # The FILL rc parameter means "total rows covered including current".
            # The decompressor sets counts=rc, then immediately decrements for
            # the current row, leaving rc-1 more rows cached. So rc=N covers
            # rows [row..row+N-1]. We search for up to (19-1)=18 additional
            # matching rows, yielding rc = additional + 1 ≤ 19.
            additional_rows = 0
            max_additional = min(18, 27 - row)  # rc ≤ 19, remaining rows
            for r in range(1, max_additional + 1):
                all_match = True
                for s in range(fill_count):
                    if grid[row + r][slot + s] != current_byte:
                        all_match = False
                        break
                if all_match:
                    additional_rows += 1
                else:
                    break

            # rc = total rows covered (current + additional)
            rc = additional_rows + 1  # always ≥ 1

            # Use FILL when it covers ≥ 2 rows (always saves work on subsequent rows)
            use_fill = rc >= 2

            if use_fill:
                # Clamp to varlen range [1, 19]
                fill_count = min(fill_count, 19)
                rc = min(rc, 19)

                # Write FILL instruction
                bit_writer.write_bit(1)
                _write_varlen(bit_writer, fill_count)
                _write_varlen(bit_writer, rc)
                literals.append(current_byte)

                # Set counts for all filled slots (mirrors decompressor)
                for fi in range(fill_count):
                    if slot + fi < 11:
                        counts[slot + fi] = rc
                        values[slot + fi] = current_byte
                # Current row is consumed: decrement count for current slot
                counts[slot] -= 1
                # Remaining slots in fill range will be consumed as we iterate
                slot += 1
            else:
                # Write LITERAL
                bit_writer.write_bit(0)
                literals.append(current_byte)
                slot += 1

    bitstream = bit_writer.get_bytes()
    flag_count = len(bitstream)

    if flag_count > 255:
        # Fallback: use all-literal encoding (guaranteed to fit in 39 flag bytes)
        return _compress_glyph_literal(grid_308)

    compressed = bytes([flag_count]) + bytes(bitstream) + bytes(literals)
    return compressed


def _compress_glyph_literal(grid_308):
    """Fallback: compress glyph using all-literal encoding (no RLE).

    This always works but produces larger output (348 bytes for 308 data bytes).
    """
    bit_writer = _FontBitWriter()
    literals = []

    for row in range(28):
        for slot in range(11):
            bit_writer.write_bit(0)  # LITERAL
            literals.append(grid_308[row * 11 + slot])

    bitstream = bit_writer.get_bytes()
    return bytes([len(bitstream)]) + bytes(bitstream) + bytes(literals)


def _inject_font_into_dataset(rel_data, font_name, font_offset_in_sec4,
                               recompressed, patch_glyph_count, first_glyph):
    """Inject re-compressed glyphs into a single font dataset within fonttex2.rel.

    Args:
        rel_data: bytearray of the entire REL file (modified in-place)
        font_name: label for log messages (e.g. "FontTex2", "FontMain")
        font_offset_in_sec4: byte offset of this font's header within section 4
        recompressed: list of bytes objects, one per glyph (re-compressed data)
        patch_glyph_count: number of glyphs to inject
        first_glyph: first glyph index to replace (188 for ASCII)
    """
    sec4_base = 0x2A0
    font_base = sec4_base + font_offset_in_sec4

    font_glyph_count = struct.unpack_from('<H', rel_data, font_base + 2)[0]
    offset_table_start = font_base + 4
    glyph_data_base = offset_table_start + font_glyph_count * 4

    total_new_size = sum(len(c) for c in recompressed)
    print(f"[FONT] {font_name}: {font_glyph_count} glyphs, "
          f"glyph_data_base=0x{glyph_data_base:X}, injecting {total_new_size} bytes")

    # Find the contiguous region occupied by target glyphs
    target_set = set(range(first_glyph, first_glyph + patch_glyph_count))

    all_offsets = []
    for i in range(font_glyph_count):
        off = struct.unpack_from('<I', rel_data, offset_table_start + i * 4)[0]
        all_offsets.append((off, i))
    all_offsets_sorted = sorted(all_offsets)

    target_min_off = min(off for off, idx in all_offsets_sorted if idx in target_set)

    # Find next non-target glyph after the target range
    next_non_target_off = None
    for off, idx in all_offsets_sorted:
        if off > target_min_off and idx not in target_set:
            next_non_target_off = off
            break

    if next_non_target_off is not None:
        available_space = next_non_target_off - target_min_off
    else:
        section_info_offset = struct.unpack_from('>I', rel_data, 0x10)[0]
        sec4_size = struct.unpack_from('>I', rel_data, section_info_offset + 4 * 8 + 4)[0]
        available_space = (sec4_base + sec4_size) - (glyph_data_base + target_min_off)

    print(f"[FONT]   Target region: +0x{target_min_off:X}, "
          f"{available_space} bytes available, {total_new_size} bytes needed")

    if total_new_size > available_space:
        raise ValueError(
            f"{font_name}: re-compressed glyphs ({total_new_size} bytes) exceed "
            f"available space ({available_space} bytes)."
        )

    # Write re-compressed glyphs in-place
    write_offset = target_min_off
    for i in range(patch_glyph_count):
        glyph_idx = first_glyph + i
        comp_data = recompressed[i]

        # Update offset table entry (LE u32)
        struct.pack_into('<I', rel_data, offset_table_start + glyph_idx * 4, write_offset)

        # Write compressed data
        file_pos = glyph_data_base + write_offset
        rel_data[file_pos:file_pos + len(comp_data)] = comp_data
        write_offset += len(comp_data)

    # Fill remaining space with 0xFF (background value, safe for any reader)
    remaining = available_space - total_new_size
    if remaining > 0:
        fill_start = glyph_data_base + write_offset
        rel_data[fill_start:fill_start + remaining] = b'\xFF' * remaining

    print(f"[FONT]   Wrote {total_new_size} bytes, "
          f"filled {remaining} bytes with 0xFF")


def inject_font(fonttex2_rel_path, font_patch_bin_path, output_path):
    """Inject font_patch.bin ASCII glyphs into fonttex2.rel IN-PLACE.

    Patches BOTH FontTex2 (sec4+0x000000) and FontMain (sec4+0x05DF64) with
    the same ASCII glyphs. The game uses FontMain for menu/dialogue text and
    FontTex2 for texture overlays — both need patching for full coverage.

    Reads compressed glyphs from font_patch.bin, decompresses them, re-compresses
    with proper FILL/RLE encoding, and overwrites the existing glyph data for
    indices 187-281 (space + JIS row 0x23 = ASCII 0x20-0x7E) without changing the file size.
    """
    original_size = os.path.getsize(fonttex2_rel_path)

    with open(fonttex2_rel_path, 'rb') as f:
        rel_data = bytearray(f.read())

    # Read font patch
    with open(font_patch_bin_path, 'rb') as f:
        patch_data = f.read()

    if len(patch_data) < 4:
        raise ValueError("Font patch too small")

    patch_glyph_count = struct.unpack('<H', patch_data[2:4])[0]
    print(f"[FONT] Loading {patch_glyph_count} ASCII glyphs from patch...")

    # Parse patch: header(4) + offset_table(count*4) + glyph_data
    patch_offsets = []
    for i in range(patch_glyph_count):
        off = struct.unpack_from('<I', patch_data, 4 + i * 4)[0]
        patch_offsets.append(off)
    patch_header_size = 4 + patch_glyph_count * 4
    patch_glyph_data = patch_data[patch_header_size:]

    # ---- Step 1: Decompress each glyph from font_patch.bin ----
    decompressed_glyphs = []
    for i in range(patch_glyph_count):
        off = patch_offsets[i]
        end = patch_offsets[i + 1] if i + 1 < patch_glyph_count else len(patch_glyph_data)
        grid = _decompress_patch_glyph(patch_glyph_data[off:end])
        decompressed_glyphs.append(grid)

    # ---- Step 2: Re-compress with proper FILL/RLE encoding ----
    recompressed = []
    for grid in decompressed_glyphs:
        recompressed.append(_compress_glyph_rle(grid))

    total_new_size = sum(len(c) for c in recompressed)
    print(f"[FONT] Re-compressed {patch_glyph_count} glyphs: "
          f"{len(patch_glyph_data)} -> {total_new_size} bytes")

    first_glyph = 187  # ASCII 0x20 (space) → glyph 187 (before JIS row 0x23)

    # ---- Step 3: Inject into FontMain (sec4+0x05DF64) ----
    # FontMain uses nibbles 0x1-0xF (font_patch.bin already uses 0x1 for foreground)
    _inject_font_into_dataset(rel_data, "FontMain", 0x05DF64,
                              recompressed, patch_glyph_count, first_glyph)

    # ---- Step 4: Inject into FontTex2 (sec4+0x000000) ----
    # FontTex2 only uses nibbles 0x8-0xF, so remap: 0x1→0x8, keep 0xF as-is.
    # FontTex2 has less available space than FontMain, so if our full-width
    # glyphs don't fit, we skip FontTex2 (it's used for texture overlays,
    # not primary text rendering).
    recompressed_ft2 = []
    for grid in decompressed_glyphs:
        remapped = []
        for b in grid:
            hi = (b >> 4) & 0xF
            lo = b & 0xF
            if hi == 0x1: hi = 0x8
            if lo == 0x1: lo = 0x8
            remapped.append((hi << 4) | lo)
        recompressed_ft2.append(_compress_glyph_rle(remapped))

    try:
        _inject_font_into_dataset(rel_data, "FontTex2", 0x000000,
                                  recompressed_ft2, patch_glyph_count, first_glyph)
    except ValueError as e:
        print(f"[FONT] FontTex2 skipped (not enough space): {e}")
        print(f"[FONT] This is OK — FontMain (used for text) was patched successfully.")

    # ---- Step 5: Verify file size is unchanged ----
    assert len(rel_data) == original_size, (
        f"File size changed! Expected {original_size}, got {len(rel_data)}"
    )
    print(f"[FONT] File size unchanged: {len(rel_data)} bytes")

    with open(output_path, 'wb') as f:
        f.write(rel_data)


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main():
    """Main text insertion pipeline."""

    base_dir = Path(__file__).parent
    data_dir = base_dir / 'DATA' / 'files'
    patch_dir = base_dir / 'patch_files'

    # Create output directory
    patch_dir.mkdir(exist_ok=True)

    print("=" * 80)
    print("Jikkyou Powerful Pro Yakyuu 15 — Text Insertion Tool")
    print("=" * 80)
    print()

    # Load translations
    trans_path = base_dir / 'translation_english.json'
    if not trans_path.exists():
        print(f"ERROR: Translation file not found: {trans_path}")
        sys.exit(1)

    print(f"[1/4] Loading translations from {trans_path.name}...")
    translation_data = load_translations(trans_path)

    trans_list = process_translations(translation_data)
    print(f"      Found {len(trans_list)} translated strings")

    # Group by file
    by_file = {}
    for item in trans_list:
        fname = item['file']
        if fname not in by_file:
            by_file[fname] = []
        by_file[fname].append(item)

    print(f"      Across {len(by_file)} files")
    for fname in sorted(by_file.keys()):
        print(f"        {fname}: {len(by_file[fname])} strings")

    print()

    # Files to NEVER patch — these contain VM bytecode, not translatable text.
    # The translation scanner produces false-positive matches in these files,
    # which corrupts VM instructions and causes crashes (e.g., Success Mode).
    EXCLUDE_FILES = {
        'scs_sce1.rel',   # Success Mode year 1 — pure VM bytecode
        'scs_sce2.rel',   # Success Mode year 2 — pure VM bytecode
        'scs_sce3.rel',   # Success Mode year 3 — pure VM bytecode
    }

    # Process each file
    print(f"[2/4] Patching REL files...")
    patched_files = {}
    patch_stats = {'total': 0, 'success': 0, 'truncated': 0, 'skipped': 0, 'errors': []}

    for filename, translations in sorted(by_file.items()):
        if filename in EXCLUDE_FILES:
            print(f"      EXCLUDED: {filename} (VM bytecode — not translatable)")
            patch_stats['skipped'] += len(translations)
            continue

        rel_path = data_dir / filename

        if not rel_path.exists():
            print(f"      WARNING: {filename} not found, skipping")
            continue

        print(f"      Loading {filename}...")
        rel = RELFile(str(rel_path))

        patch_count = 0
        truncated_count = 0
        error_count = 0

        for trans in translations:
            section = trans['section']
            offset = trans['offset']
            english = trans['english']
            orig_len = trans.get('length', 0)
            boundary_bytes = trans.get('available_bytes', None)

            patch_stats['total'] += 1

            # Determine entry type and size constraints
            terminator = 0xFFFF  # Default to dialogue
            max_hw = None
            pad_to = None

            # CRITICAL: Find the REAL string length by scanning for the first
            # 0xFFFF terminator in the original data. The scanner's 'length'
            # field may overcount because it merges adjacent data fields.
            # We must NEVER write past the first real terminator.
            real_len = orig_len  # fallback
            try:
                sec_data = rel.get_section_data(section)
                for scan_i in range(offset, min(offset + orig_len * 2, len(sec_data) - 1), 2):
                    hw = (sec_data[scan_i] << 8) | sec_data[scan_i + 1]
                    if hw == 0xFFFF:
                        real_len = (scan_i - offset) // 2
                        break
            except:
                pass

            # Cap write at real string allocation (real chars + terminator)
            orig_alloc = (real_len + 1) * 2
            available_bytes = orig_alloc

            # Also cap at section boundary
            section_size = rel.get_section_size(section)
            if section_size > 0:
                max_from_section = section_size - offset
                if max_from_section > 0 and max_from_section < available_bytes:
                    available_bytes = max_from_section

            if orig_len <= 5:
                terminator = 0x1FFF
            elif orig_len <= 20:
                terminator = 0xFFFF

            # NEVER pad — leave original bytes after terminator untouched
            pad_to = None

            # Convert to halfwords (auto-truncates to fit available_bytes)
            try:
                hw_bytes = text_to_halfwords(english, terminator, max_hw, pad_to, available_bytes)

                # Check if truncation occurred
                min_needed = (len(english) + 1) * 2
                was_truncated = len(hw_bytes) < min_needed

                # Patch the REL
                rel.patch_at(section, offset, hw_bytes)
                patch_count += 1
                if was_truncated:
                    truncated_count += 1
                    patch_stats['truncated'] += 1
                else:
                    patch_stats['success'] += 1

            except Exception as e:
                error_count += 1
                patch_stats['errors'].append({
                    'file': filename,
                    'section': section,
                    'offset': offset,
                    'text': english[:30],
                    'error': str(e)
                })

        print(f"        Patched {patch_count}/{len(translations)} " +
              f"({truncated_count} truncated, {error_count} failed)")

        # Write patched file
        output_path = patch_dir / filename
        rel.write(str(output_path))
        patched_files[filename] = output_path

    print()

    # Font injection (optional)
    print(f"[3/4] Checking font injection...")
    font_patch = base_dir / 'font_patch.bin'
    fonttex2_rel = data_dir / 'fonttex2.rel'

    if font_patch.exists() and fonttex2_rel.exists():
        print(f"      Font patch found, will inject into fonttex2.rel")
        try:
            fonttex2_out = patch_dir / 'fonttex2.rel'
            inject_font(str(fonttex2_rel), str(font_patch), str(fonttex2_out))
            print(f"      Wrote {fonttex2_out}")
        except Exception as e:
            print(f"      ERROR: Font injection failed: {e}")
    else:
        print(f"      Font patch or fonttex2.rel not found, skipping")

    print()

    # Summary
    print(f"[4/4] Summary")
    print(f"      Total files patched: {len(patched_files)}")
    print(f"      Total translations processed: {patch_stats['total']}")
    print(f"      Successfully patched: {patch_stats['success']}")
    print(f"      Truncated to fit: {patch_stats['truncated']}")
    print(f"      Failed to patch: {len(patch_stats['errors'])}")
    print(f"      Output directory: {patch_dir}")
    print()

    # Generate report
    report_path = patch_dir / 'PATCH_REPORT.txt'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("Jikkyou Powerful Pro Yakyuu 15 — Text Patch Report\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated from: {trans_path.name}\n")
        f.write(f"Total translated strings: {len(trans_list)}\n")
        f.write(f"Total files patched: {len(patched_files)}\n")
        f.write(f"Successfully patched: {patch_stats['success']}\n")
        f.write(f"Truncated to fit: {patch_stats['truncated']}\n")
        f.write(f"Failed: {len(patch_stats['errors'])}\n\n")

        f.write("Patched Files:\n")
        for fname in sorted(patched_files.keys()):
            trans_count = len(by_file[fname])
            f.write(f"  {fname}: {trans_count} strings\n")

        if patch_stats['errors']:
            f.write(f"\nErrors ({len(patch_stats['errors'])} total):\n")
            for err in patch_stats['errors'][:20]:
                f.write(f"  {err['file']} sec{err['section']} +0x{err['offset']:X}:\n")
                f.write(f"    Text: {err['text']}...\n")
                f.write(f"    Error: {err['error'][:60]}...\n")
            if len(patch_stats['errors']) > 20:
                f.write(f"  ... and {len(patch_stats['errors']) - 20} more\n")

        f.write("\nSample Translations:\n")
        for item in trans_list[:10]:
            f.write(f"  {item['file']} sec{item['section']} +0x{item['offset']:X}:\n")
            f.write(f"    JP: {item['japanese']}\n")
            f.write(f"    EN: {item['english']}\n")

    print(f"Report written to: {report_path}")
    print()
    print("Done!")


if __name__ == '__main__':
    main()
