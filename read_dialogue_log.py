#!/usr/bin/env python3
"""
read_dialogue_log.py — Read and decode the dialogue log buffer from a Dolphin
RAM dump, producing human-readable text and machine-parseable JSON.

The log is written by the PPC hook injected by inject_dialogue_logger.py.
It lives in scs_main.rel sec5's zero region as a circular buffer of 64-byte
entries, each containing the VM return address, source/dest pointers,
destination buffer ID, and up to 20 glyph halfwords.

Usage:
    # Read from a Dolphin RAM dump (MEM1, 24MB):
    python3 read_dialogue_log.py --ramdump mem1.raw

    # Read from a Dolphin RAM dump with known sec5 base address:
    python3 read_dialogue_log.py --ramdump mem1.raw --sec5-base 0x80XXXXXX

    # Auto-scan the RAM dump for the log header magic ("DLOG"):
    python3 read_dialogue_log.py --ramdump mem1.raw --scan

    # Output JSON:
    python3 read_dialogue_log.py --ramdump mem1.raw --json output.json

    # Read directly from a patched REL file (for verification only):
    python3 read_dialogue_log.py --rel DATA/files/scs_main.rel

Does NOT modify any game files.
"""

import argparse
import json
import struct
import sys
from pathlib import Path


# ============================================================
# Constants (must match inject_dialogue_logger.py)
# ============================================================

LOG_ENTRY_SIZE = 64
LOG_MAGIC = 0x4C4F4700       # "LOG\0"
LOG_HEADER_MAGIC = 0x444C4F47  # "DLOG"

MEM1_BASE = 0x80000000
MEM1_SIZE = 0x01800000  # 24 MB

# Default sec5 offsets (for scs_main.rel)
DEFAULT_LOG_HEADER_SEC5 = 0x0D1000
DEFAULT_LOG_BUFFER_SEC5 = 0x0D1010

# scs_main file offsets
SCS_SEC5_FILE_OFFSET = 0x087E10

# Buffer ID → human-readable name
BUFFER_NAMES = {
    0x025E: 'body_text',
    0x0280: 'name_primary',
    0x0294: 'name_secondary',
    0x02BC: 'context_name',
    # Other values may appear for r17+0xA4 or r18-0x7DD0 calls
}


# ============================================================
# Glyph Decoding (same as build_dialogue_table.py)
# ============================================================

def glyph_to_char(g):
    """Convert a glyph index to a Unicode character."""
    # ASCII range (injected font)
    if g == 187:
        return ' '
    if 188 <= g <= 281:
        return chr(0x21 + (g - 188))

    # JIS X 0208 range
    if g <= 657:
        row = (g // 94) + 0x21
        col = (g % 94) + 0x21
    elif g <= 705:
        row = 0x28
        col = (g - 658) + 0x21
    elif g <= 3743:
        k = g - 706
        row = (k // 94) + 0x30
        col = (k % 94) + 0x21
    else:
        return f'[{g}]'

    try:
        if row % 2 == 1:
            s1 = (row + 1) // 2 + 0x70
            if s1 > 0x9F:
                s1 += 0x40
            s2 = col + 0x1F if col <= 0x5F else col + 0x20
        else:
            s1 = row // 2 + 0x70
            if s1 > 0x9F:
                s1 += 0x40
            s2 = col + 0x7E
        return bytes([s1, s2]).decode('shift_jis')
    except (UnicodeDecodeError, ValueError):
        return f'[{g}]'


def decode_glyphs(halfwords):
    """Decode a list of glyph halfwords to a string."""
    chars = []
    for hw in halfwords:
        g = hw & 0x0FFF
        if g == 0 or hw == 0x1FFF or hw == 0xFFFF:
            continue
        chars.append(glyph_to_char(g))
    return ''.join(chars)


# ============================================================
# Log Entry Parsing
# ============================================================

def parse_log_entry(data, offset):
    """Parse a single 64-byte log entry.

    Returns dict or None if entry is empty/invalid.
    """
    if offset + LOG_ENTRY_SIZE > len(data):
        return None

    magic = struct.unpack_from('>I', data, offset)[0]
    if magic != LOG_MAGIC:
        return None

    entry_index = struct.unpack_from('>I', data, offset + 0x04)[0]
    caller_lr = struct.unpack_from('>I', data, offset + 0x08)[0]
    vm_ip = struct.unpack_from('>I', data, offset + 0x0C)[0]
    source_ptr = struct.unpack_from('>I', data, offset + 0x10)[0]
    dest_ptr = struct.unpack_from('>I', data, offset + 0x14)[0]
    dest_buf_id = struct.unpack_from('>H', data, offset + 0x18)[0]
    glyph_count = struct.unpack_from('>H', data, offset + 0x1A)[0]

    # Read glyph halfwords
    glyphs = []
    for i in range(min(glyph_count, 20)):
        hw = struct.unpack_from('>H', data, offset + 0x1C + i * 2)[0]
        glyphs.append(hw)

    # Decode text
    text = decode_glyphs(glyphs)

    # Look up buffer name
    buf_name = BUFFER_NAMES.get(dest_buf_id, f'0x{dest_buf_id:04X}')

    return {
        'entry_index': entry_index,
        'caller_lr': caller_lr,
        'vm_ip': vm_ip,
        'source_ptr': source_ptr,
        'dest_ptr': dest_ptr,
        'dest_buf_id': dest_buf_id,
        'dest_buf_name': buf_name,
        'glyph_count': glyph_count,
        'glyphs_raw': glyphs,
        'glyphs_hex': [f'0x{hw:04X}' for hw in glyphs],
        'text_japanese': text,
    }


def parse_log_header(data, offset):
    """Parse the 16-byte log header.

    Returns dict or None if header magic doesn't match.
    """
    if offset + 16 > len(data):
        return None

    magic = struct.unpack_from('>I', data, offset)[0]
    if magic != LOG_HEADER_MAGIC:
        return None

    return {
        'magic': magic,
        'write_index': struct.unpack_from('>I', data, offset + 4)[0],
        'total_entries': struct.unpack_from('>I', data, offset + 8)[0],
        'max_entries': struct.unpack_from('>I', data, offset + 12)[0],
    }


# ============================================================
# RAM Dump Reading
# ============================================================

def scan_for_header(mem):
    """Scan RAM for the "DLOG" header magic.

    Returns list of (virtual_address, header_dict) tuples.
    """
    results = []
    magic_bytes = struct.pack('>I', LOG_HEADER_MAGIC)

    pos = 0
    while pos < len(mem) - 16:
        idx = mem.find(magic_bytes, pos)
        if idx == -1:
            break
        vaddr = MEM1_BASE + idx
        header = parse_log_header(mem, idx)
        if header and header['max_entries'] > 0 and header['max_entries'] < 100000:
            results.append((vaddr, header))
        pos = idx + 4

    return results


def read_log_from_ram(mem, header_vaddr):
    """Read all log entries from a RAM dump given the header virtual address.

    Returns (header_dict, list_of_entry_dicts).
    """
    header_offset = header_vaddr - MEM1_BASE
    header = parse_log_header(mem, header_offset)
    if header is None:
        print(f"ERROR: No valid log header at 0x{header_vaddr:08X}")
        return None, []

    # Log buffer starts 16 bytes after header
    buffer_offset = header_offset + 16
    max_entries = header['max_entries']
    total = header['total_entries']
    write_idx = header['write_index']

    print(f"Log header at 0x{header_vaddr:08X}:")
    print(f"  write_index: {write_idx}")
    print(f"  total_entries: {total}")
    print(f"  max_entries: {max_entries}")

    if total == 0:
        print("  (no entries logged yet)")
        return header, []

    # Read entries in chronological order
    # If total <= max, entries are at slots 0..total-1
    # If total > max, the buffer has wrapped. Oldest is at write_idx % max,
    # newest is at (write_idx - 1) % max.
    entries = []
    if total <= max_entries:
        # No wrap — read sequentially
        for i in range(total):
            off = buffer_offset + i * LOG_ENTRY_SIZE
            entry = parse_log_entry(mem, off)
            if entry:
                entries.append(entry)
    else:
        # Wrapped — read from oldest to newest
        start = write_idx % max_entries
        for i in range(max_entries):
            slot = (start + i) % max_entries
            off = buffer_offset + slot * LOG_ENTRY_SIZE
            entry = parse_log_entry(mem, off)
            if entry:
                entries.append(entry)

    return header, entries


def read_log_from_rel(rel_path, cfg_name='scs'):
    """Read log entries directly from a patched REL file (verification only).

    This reads the log region from the file on disk. Only useful for
    checking that the header was written correctly — actual log entries
    are only populated at runtime.
    """
    with open(rel_path, 'rb') as f:
        data = f.read()

    if cfg_name == 'scs':
        sec5_off = SCS_SEC5_FILE_OFFSET
        header_off = sec5_off + DEFAULT_LOG_HEADER_SEC5
        buffer_off = sec5_off + DEFAULT_LOG_BUFFER_SEC5
    else:
        print("ERROR: Only scs_main.rel is supported for --rel mode currently")
        sys.exit(1)

    header = parse_log_header(data, header_off)
    if header is None:
        print(f"No log header found at file offset 0x{header_off:06X}")
        print("(The REL may not be patched, or the offsets are wrong)")
        return None, []

    print(f"Log header at file offset 0x{header_off:06X}:")
    print(f"  max_entries: {header['max_entries']}")
    print(f"  write_index: {header['write_index']} (should be 0 in unplayed file)")
    print(f"  total_entries: {header['total_entries']}")

    # Read entries (will be empty in a freshly patched file)
    entries = []
    max_entries = header['max_entries']
    for i in range(min(max_entries, 10)):  # Only check first 10 slots
        off = buffer_off + i * LOG_ENTRY_SIZE
        entry = parse_log_entry(data, off)
        if entry:
            entries.append(entry)

    return header, entries


# ============================================================
# Output Formatting
# ============================================================

def print_entries_text(entries, verbose=False):
    """Print entries in human-readable format."""
    if not entries:
        print("\n(no log entries)")
        return

    print(f"\n{'='*80}")
    print(f"{'#':>5}  {'VM Return Addr':>14}  {'Buffer':>16}  {'Caller LR':>14}  Text")
    print(f"{'='*80}")

    for e in entries:
        idx = e['entry_index']
        vm = f"0x{e['vm_ip']:08X}"
        buf = e['dest_buf_name']
        lr = f"0x{e['caller_lr']:08X}"
        text = e['text_japanese']

        print(f"{idx:5d}  {vm}  {buf:>16}  {lr}  {text}")

        if verbose:
            print(f"       src=0x{e['source_ptr']:08X} dst=0x{e['dest_ptr']:08X} "
                  f"buf_id=0x{e['dest_buf_id']:04X} glyphs={e['glyph_count']}")
            if e['glyphs_raw']:
                hex_str = ' '.join(f'{hw:04X}' for hw in e['glyphs_raw'])
                print(f"       raw: {hex_str}")
            print()

    print(f"\nTotal entries: {len(entries)}")

    # Summary: unique VM IPs
    unique_ips = set()
    for e in entries:
        unique_ips.add(e['vm_ip'])
    print(f"Unique VM return addresses: {len(unique_ips)}")

    # Summary: by buffer type
    by_buf = {}
    for e in entries:
        buf = e['dest_buf_name']
        by_buf[buf] = by_buf.get(buf, 0) + 1
    print("By buffer type:")
    for buf, count in sorted(by_buf.items(), key=lambda x: -x[1]):
        print(f"  {buf}: {count}")


def write_json(entries, header, output_path):
    """Write entries and header to a JSON file."""
    output = {
        'header': {
            'magic': f"0x{header['magic']:08X}",
            'write_index': header['write_index'],
            'total_entries': header['total_entries'],
            'max_entries': header['max_entries'],
        },
        'entries': []
    }

    for e in entries:
        output['entries'].append({
            'entry_index': e['entry_index'],
            'vm_return_addr': f"0x{e['vm_ip']:08X}",
            'caller_lr': f"0x{e['caller_lr']:08X}",
            'source_ptr': f"0x{e['source_ptr']:08X}",
            'dest_ptr': f"0x{e['dest_ptr']:08X}",
            'dest_buf_id': f"0x{e['dest_buf_id']:04X}",
            'dest_buf_name': e['dest_buf_name'],
            'glyph_count': e['glyph_count'],
            'glyphs_hex': e['glyphs_hex'],
            'text_japanese': e['text_japanese'],
        })

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\nJSON output written to: {output_path}")
    print(f"  {len(output['entries'])} entries")


# ============================================================
# Deduplication and Analysis
# ============================================================

def deduplicate_entries(entries):
    """Group entries by (vm_ip, dest_buf_id) and show unique dialogue lines."""
    seen = {}
    for e in entries:
        key = (e['vm_ip'], e['dest_buf_id'])
        if key not in seen:
            seen[key] = e
        # Keep first occurrence (chronologically earliest)

    unique = sorted(seen.values(), key=lambda e: e['entry_index'])
    return unique


def generate_translation_csv(entries, output_path):
    """Generate a CSV template for translation from unique dialogue entries.

    Output columns: vm_return_addr, dest_buf, japanese_text, english_text
    """
    unique = deduplicate_entries(entries)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('vm_return_addr,dest_buf,japanese_text,english_text\n')
        for e in unique:
            vm = f"0x{e['vm_ip']:08X}"
            buf = e['dest_buf_name']
            jp = e['text_japanese'].replace('"', '""')
            f.write(f'{vm},{buf},"{jp}",""\n')

    print(f"\nTranslation CSV template written to: {output_path}")
    print(f"  {len(unique)} unique dialogue lines")
    print(f"  Fill in the english_text column, then use build_dialogue_table.py --csv to build the table")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Read and decode the dialogue log from a Dolphin RAM dump')

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--ramdump', type=str,
                            help='Path to Dolphin MEM1 RAM dump (24MB)')
    input_group.add_argument('--rel', type=str,
                            help='Path to patched scs_main.rel (verification only)')

    parser.add_argument('--sec5-base', type=str, default=None,
                       help='Runtime base address of sec5 (hex). If not provided, uses --scan.')
    parser.add_argument('--scan', action='store_true', default=True,
                       help='Auto-scan RAM for "DLOG" header magic (default: on)')
    parser.add_argument('--json', type=str, default=None,
                       help='Output JSON file path')
    parser.add_argument('--csv', type=str, default=None,
                       help='Output translation CSV template')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed entry info (pointers, raw glyphs)')
    parser.add_argument('--unique', action='store_true',
                       help='Show only unique dialogue lines (deduplicated by VM IP + buffer)')
    parser.add_argument('--limit', type=int, default=0,
                       help='Limit output to N most recent entries (0 = all)')

    args = parser.parse_args()

    if args.rel:
        header, entries = read_log_from_rel(args.rel)
        if header is None:
            sys.exit(1)
        print_entries_text(entries, args.verbose)
        return

    # RAM dump mode
    ramdump_path = Path(args.ramdump)
    if not ramdump_path.exists():
        print(f"ERROR: File not found: {ramdump_path}")
        sys.exit(1)

    with open(ramdump_path, 'rb') as f:
        mem = f.read()

    print(f"RAM dump: {ramdump_path} ({len(mem)} bytes = {len(mem)/1024/1024:.1f} MB)")

    if len(mem) < MEM1_SIZE:
        print(f"WARNING: Expected {MEM1_SIZE} bytes (24MB MEM1), got {len(mem)}")

    # Find log header
    header_vaddr = None

    if args.sec5_base:
        sec5_base = int(args.sec5_base, 16)
        header_vaddr = sec5_base + DEFAULT_LOG_HEADER_SEC5
        print(f"Using provided sec5 base: 0x{sec5_base:08X}")
        print(f"  Log header at: 0x{header_vaddr:08X}")
    else:
        # Auto-scan for "DLOG" magic
        print("Scanning for 'DLOG' header magic...")
        results = scan_for_header(mem)
        if not results:
            print("ERROR: No 'DLOG' header found in RAM dump.")
            print("  The logging hook may not be active, or the game hasn't loaded scs_main.rel yet.")
            sys.exit(1)

        if len(results) == 1:
            header_vaddr = results[0][0]
            print(f"  Found at: 0x{header_vaddr:08X}")
        else:
            print(f"  Found {len(results)} candidates:")
            for vaddr, hdr in results:
                print(f"    0x{vaddr:08X}: total={hdr['total_entries']}, max={hdr['max_entries']}")
            # Use the one with the most entries
            best = max(results, key=lambda x: x[1]['total_entries'])
            header_vaddr = best[0]
            print(f"  Using: 0x{header_vaddr:08X} (most entries)")

    # Read log
    header, entries = read_log_from_ram(mem, header_vaddr)
    if header is None:
        sys.exit(1)

    # Apply filters
    if args.unique:
        entries = deduplicate_entries(entries)
        print(f"\nAfter deduplication: {len(entries)} unique lines")

    if args.limit > 0 and len(entries) > args.limit:
        entries = entries[-args.limit:]
        print(f"Showing last {args.limit} entries")

    # Output
    print_entries_text(entries, args.verbose)

    if args.json:
        write_json(entries, header, args.json)

    if args.csv:
        # Use all entries (not limited) for CSV
        if args.ramdump:
            _, all_entries = read_log_from_ram(mem, header_vaddr)
        else:
            all_entries = entries
        generate_translation_csv(all_entries, args.csv)


if __name__ == '__main__':
    main()
