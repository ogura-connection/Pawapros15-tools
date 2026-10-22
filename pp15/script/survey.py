"""Surveys of the whole game folder: where is packed text, which files look compressed. (`pp15 scan entropy`, `scan scan`)

Used while finding out where the game keeps its text; kept because the commands answer "did we miss a text store?".

  entropy   Shannon entropy (bits per byte) of every section of the script modules and of every file by type. Plain
            data and text score low; compressed or encrypted data scores above about 7.5.
  scan      look in every game file for runs of 12-bit packed text (the story format, see packed_text.py) and for
            compressed streams (Yaz0, LZ10, LZ11) that decompress cleanly, then look for text inside those.

Public names: find_packed_text, decompress_yaz0, decompress_lz, count_16bit_text, entropy, sampled_entropy,
print_entropy_report(top), print_scan_report(include_sound).
"""
import collections
import math
import os
import re
import struct
from typing import List, Optional, Tuple

from pp15 import config
from pp15.disc.extract_text import is_quality_text
from pp15.glyphs import glyph_to_char
from pp15.script.packed_text import pack_text, unpack_text, units_valid
from pp15.script.rel import Rel
from pp15.script.scripts import SCRIPT_FILES

HIGH_ENTROPY = 7.5          # bits per byte above which data looks compressed or encrypted
ENTROPY_WINDOW = 16384      # bytes per window when mapping a section
SAMPLE_CHUNK = 1 << 22      # a file over three of these is sampled at its start, middle and end
READ_CHUNK = 1 << 24        # bytes read at a time by the scan
KANA_FIRST, KANA_LAST = 282, 450   # glyph numbers of hiragana and katakana


def entropy(b: bytes) -> float:
    """Shannon entropy of a byte string, in bits per byte (0 for empty)."""
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


def sampled_entropy(path: str, chunk: int = SAMPLE_CHUNK) -> Tuple[float, bool]:
    """(entropy of the whole file, whether it was only sampled). Files over 3 chunks (12 MB) are sampled at the start,
    middle and end."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        if size <= 3 * chunk:
            return entropy(f.read()), False
        parts = []
        for pos in (0, size // 2, size - chunk):
            f.seek(pos)
            parts.append(f.read(chunk))
        return entropy(b"".join(parts)), True


def print_entropy_report(top: int) -> None:
    """Entropy of every section of the script modules, then of every game file grouped by extension; `top`
    high-entropy files are listed per extension."""
    win = ENTROPY_WINDOW
    print("Section entropy, bits/byte (compressed or encrypted data is above ~7.5)\n")
    for fn in SCRIPT_FILES + ["work_scs.rel"]:
        rel = Rel(os.path.join(config.DATA_FILES, fn))
        for s in rel.sections:
            if not s["size"]:
                continue
            if s["bss"]:
                print("%-13s sec%-2d BSS   size 0x%06x (not stored in the file)" % (fn, s["index"], s["size"]))
                continue
            d = rel.sec_data(s["index"])
            ws = [entropy(d[a:a + win]) for a in range(0, len(d), win)]
            high = sum(1 for w in ws if w > HIGH_ENTROPY)
            print("%-13s sec%-2d %-5s size 0x%06x  whole %.2f  16KB windows min %.2f max %.2f  high: %d"
                  % (fn, s["index"], "code" if s["exec"] else "data", s["size"], entropy(d), min(ws), max(ws), high))
    print("\nWhole-file entropy by type (* = sampled, large file)\n")
    by_ext = collections.defaultdict(list)
    for root, _, files in os.walk(config.DATA_FILES):
        for fn in files:
            ext = os.path.splitext(fn)[1].lower() or "(none)"
            if ext in (".thp", ".rsd"):                 # video and sound: large and not text
                continue
            path = os.path.join(root, fn)
            e, sampled = sampled_entropy(path)
            by_ext[ext].append((e, os.path.relpath(path, config.DATA_FILES), os.path.getsize(path), sampled))
    for ext, rows in sorted(by_ext.items()):
        es = [r[0] for r in rows]
        high = sorted((r for r in rows if r[0] > HIGH_ENTROPY), reverse=True)
        print("%-8s files %4d  mean %.2f  max %.2f  above 7.5: %d" % (ext, len(rows), sum(es) / len(es), max(es), len(high)))
        for e, rel_path, size, sampled in high[:top]:
            print("      %.2f%s %-28s %d bytes" % (e, "*" if sampled else " ", rel_path, size))


def is_kana(u: int) -> bool:
    """True for the glyph numbers of hiragana and katakana."""
    return KANA_FIRST <= u <= KANA_LAST


def find_packed_text(data: bytes, min_units: int = 5) -> List[Tuple[int, List[int]]]:
    """Heuristic search for 12-bit packed text in arbitrary data.

    A text-mode instruction is a halfword XX00 (XX <= 0x1F), followed by a run of valid units that is mostly kana,
    the terminator 0xFFF and 0xF padding. Returns [(byte offset of the instruction, units)]. It undercounts (short or
    kana-poor lines are skipped); use Script for real parsing."""
    n = len(data) // 2
    hw = struct.unpack(">%dH" % n, data[:n * 2])
    hits, skip_to = [], 0
    for m in re.finditer(rb"[\x00-\x1f]\x00", data):
        p = m.start()
        if p % 2 or p // 2 < skip_to:
            continue
        i = p // 2
        if i + 2 >= n or hw[i + 1] == 0:
            continue
        r = unpack_text(hw, i + 1, max_units=500, strict=True)
        if r is None:
            continue
        units, j = r
        if len(units) < min_units or not units_valid(units):
            continue
        if sum(map(is_kana, units)) < 0.4 * len(units):
            continue
        if list(hw[i + 1:j]) != pack_text(units):
            continue
        hits.append((p, units))
        skip_to = j
    return hits


def decompress_yaz0(d: bytes, pos: int) -> Optional[bytes]:
    """Nintendo Yaz0 stream at d[pos:] (header: 'Yaz0', 32-bit big-endian size, 8 bytes), or None if it does not parse."""
    size = struct.unpack_from(">I", d, pos + 4)[0]
    if not 16 <= size <= 1 << 26:
        return None
    out, p = bytearray(), pos + 16
    try:
        while len(out) < size:
            flags = d[p]; p += 1
            for bit in range(8):
                if len(out) >= size:
                    break
                if flags & (0x80 >> bit):
                    out.append(d[p]); p += 1
                else:
                    b1, b2 = d[p], d[p + 1]; p += 2
                    dist = ((b1 & 0xF) << 8 | b2) + 1
                    n = b1 >> 4
                    if n == 0:
                        n = d[p] + 0x12; p += 1
                    else:
                        n += 2
                    if dist > len(out):
                        return None
                    for _ in range(n):
                        out.append(out[-dist])
    except IndexError:
        return None
    return bytes(out)


def decompress_lz(d: bytes, pos: int) -> Optional[bytes]:
    """Nintendo LZ10 / LZ11 stream at d[pos:] (header byte 0x10 / 0x11 + 24-bit little-endian size), or None.

    A stream that does not shrink the data by at least a third is rejected as a false hit."""
    kind = d[pos]
    size = d[pos + 1] | d[pos + 2] << 8 | d[pos + 3] << 16
    if kind not in (0x10, 0x11) or not 64 <= size <= 1 << 26:
        return None
    out, p = bytearray(), pos + 4
    try:
        while len(out) < size:
            flags = d[p]; p += 1
            for bit in range(8):
                if len(out) >= size:
                    break
                if not flags & (0x80 >> bit):
                    out.append(d[p]); p += 1
                    continue
                if kind == 0x10:
                    n = (d[p] >> 4) + 3
                    dist = ((d[p] & 0xF) << 8 | d[p + 1]) + 1; p += 2
                else:
                    ind = d[p] >> 4
                    if ind == 0:
                        n = ((d[p] & 0xF) << 4 | d[p + 1] >> 4) + 0x11
                        dist = ((d[p + 1] & 0xF) << 8 | d[p + 2]) + 1; p += 3
                    elif ind == 1:
                        n = ((d[p] & 0xF) << 12 | d[p + 1] << 4 | d[p + 2] >> 4) + 0x111
                        dist = ((d[p + 2] & 0xF) << 8 | d[p + 3]) + 1; p += 4
                    else:
                        n = ind + 1
                        dist = ((d[p] & 0xF) << 8 | d[p + 1]) + 1; p += 2
                if dist > len(out):
                    return None
                for _ in range(n):
                    out.append(out[-dist])
    except IndexError:
        return None
    if p - pos < 32 or len(out) < 2 * (p - pos) // 3:
        return None
    return bytes(out)


def count_16bit_text(data: bytes) -> int:
    """Count runs of plain 16-bit glyph text (the format used in REL data tables) that read as Japanese."""
    n = len(data) // 2
    hw = struct.unpack(">%dH" % n, data[:n * 2])
    runs, cur = 0, []
    for v in hw:
        ch = glyph_to_char(v & 0x1FFF) if v not in (0, 0x1FFF, 0xFFFF) else None
        if ch:
            cur.append(ch)
            continue
        if len(cur) >= 4 and is_quality_text("".join(cur)) and sum(0x3040 <= ord(c) <= 0x30FF for c in cur) >= 2:
            runs += 1
        cur = []
    return runs


def print_scan_report(include_sound: bool) -> None:
    """Scan DATA/files for 12-bit packed text and for compressed streams, and print what was found."""
    print("Packed 12-bit text and compressed-data scan of DATA/files")
    print("(skipping .thp/.rsd%s)\n" % ("" if include_sound else " and sound/; use --all to include sound"))
    packed, comp, nfiles = [], [], 0
    for root, dirs, files in os.walk(config.DATA_FILES):
        if not include_sound and os.path.basename(root) == "sound":
            dirs[:] = []
            continue
        for fn in sorted(files):
            if fn.lower().endswith((".thp", ".rsd")):
                continue
            path = os.path.join(root, fn)
            rel_path = os.path.relpath(path, config.DATA_FILES)
            nfiles += 1
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                chunk_no = 0
                while True:
                    data = f.read(READ_CHUNK)
                    if not data:
                        break
                    hits = find_packed_text(data)
                    if hits:
                        packed.append((rel_path, len(hits), sum(len(u) for _, u in hits)))
                    # compressed-stream candidates: magic words anywhere, LZ headers at chunk start
                    cands = [(m.start(), "Yaz0") for m in re.finditer(rb"Yaz0", data)]
                    if chunk_no == 0 and size > 64 and data[0] in (0x10, 0x11):
                        cands.append((0, "LZ%02X" % data[0]))
                    if chunk_no == 0 and fn.endswith(".rel") and size > 0x40:
                        for s in Rel(path).sections:
                            o = s["offset"]
                            if o and s["size"] > 64 and data[o] in (0x10, 0x11):
                                cands.append((o, "LZ%02X" % data[o]))
                    for pos, kind in cands:
                        out = decompress_yaz0(data, pos) if kind == "Yaz0" else decompress_lz(data, pos)
                        if out:
                            comp.append((rel_path, pos, kind, len(out), len(find_packed_text(out)), count_16bit_text(out)))
                    chunk_no += 1
    print("Files scanned: %d\n" % nfiles)
    print("Files containing 12-bit packed text runs:")
    for rel_path, runs, glyphs in sorted(packed, key=lambda r: -r[1]):
        print("  %-28s runs %6d  glyphs %7d" % (rel_path, runs, glyphs))
    if not packed:
        print("  none")
    print("\nCompressed streams that decompress cleanly (Yaz0 / LZ10 / LZ11):")
    for rel_path, pos, kind, n, p12, p16 in comp:
        print("  %-28s +0x%x %s -> %d bytes, packed-text runs %d, 16-bit text runs %d" % (rel_path, pos, kind, n, p12, p16))
    if not comp:
        print("  none")
