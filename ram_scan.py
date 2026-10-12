#!/usr/bin/env python3
"""
ram_scan.py - look inside a Dolphin save state: loaded modules and memory use

  ram_scan.py STATE_FILE        e.g. ../dolphin-test/StateSaves/RP5JA4.s01

Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4, Rev 1), Dolphin 2609a state format.
Prints the modules in the OS module queue with their real addresses, checks them against the
memory plan in moduleID2addr.o (see FINDINGS.md), and draws a map of which memory holds data.
The memory dump is written to _work/ram/ (game data: git-ignored, never commit it).
Faster with `pip install lz4`; without it a slow built-in decompressor is used.
"""
import os
import re
import struct
import sys

import scan_story as S
import rebuild_scripts as R

MEM1_SIZE = 0x1800000


def lz4_block(src, size):
    try:
        import lz4.block
        return lz4.block.decompress(src, uncompressed_size=size)
    except ImportError:
        pass
    out, i, n = bytearray(), 0, len(src)
    while i < n:
        token = src[i]; i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]; i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]; i += lit
        if i >= n:
            break
        dist = src[i] | src[i + 1] << 8; i += 2
        ml = token & 15
        if ml == 15:
            while True:
                b = src[i]; i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - dist
        if dist >= ml:
            out += out[start:start + ml]
        else:
            chunk = bytes(out[start:])
            out += (chunk * (ml // dist + 1))[:ml]
    return bytes(out)


def read_mem1(path):
    d = open(path, "rb").read()
    p = 0x20 + struct.unpack_from("<I", d, 0x1C)[0]
    for q in range(p, p + 32):
        usize, clen = struct.unpack_from("<Qi", d, q)
        if q + 12 + clen == len(d) and 0 < usize < 1 << 31:
            break
    else:
        sys.exit("State header not understood (written for Dolphin 2609a, LZ4, one block)")
    raw = lz4_block(d[q + 12:], usize)
    for m in re.finditer(rb"RP5JA4", raw):
        if raw[m.start() + 0x18:m.start() + 0x1C] == b"\x5d\x1c\x9e\xa3":
            return raw[m.start():m.start() + MEM1_SIZE]
    sys.exit("MEM1 not found in the state")


def main():
    if len(sys.argv) != 2:
        return print(__doc__)
    mem = read_mem1(sys.argv[1])
    os.makedirs(os.path.join(S.WORK_DIR, "ram"), exist_ok=True)
    with open(os.path.join(S.WORK_DIR, "ram", os.path.basename(sys.argv[1]) + ".mem1"), "wb") as f:
        f.write(mem)
    u32 = lambda a: struct.unpack_from(">I", mem, a - 0x80000000)[0]
    mods = S.load_all_rels()
    plan_dir = R.ORIG_DIR if os.path.isdir(R.ORIG_DIR) else S.DATA_FILES
    with open(os.path.join(plan_dir, R.PLAN_FILE), "rb") as f:
        plan = f.read()
    t_addr, t_size, _, n = R.plan_tables(plan)
    planned = {}
    for i in range(n):
        planned.setdefault(struct.unpack_from(">I", plan, t_addr + i * 4)[0], []).append(
            struct.unpack_from(">I", plan, t_size + i * 4)[0])

    live, p = [], u32(0x800030C8)          # OS module queue head
    while p:
        mid, nxt, _, nsec, secs = struct.unpack_from(">5I", mem, p - 0x80000000)
        end = p
        for k in range(nsec):
            off, size = struct.unpack_from(">II", mem, secs - 0x80000000 + k * 8)
            if off and size:
                end = max(end, (off & ~3) + size)
        live.append((p, end, mods[mid].name if mid in mods else "module %d" % mid))
        p = nxt
    print("Loaded modules: %d (general memory pool starts at 0x814E0000)" % len(live))
    prev = 0
    for a, end, name in sorted(live):
        note = "" if a in planned else "   not at an address of the original plan"
        if prev and a - prev > 0x1000:
            note += "   (%d KB free before it)" % ((a - prev) // 1024)
        print("  %08X-%08X %8d KB  %-13s%s" % (a, end, (end - a) // 1024, name, note))
        prev = max(prev, end)
    print("\nMemory holding data, 64 KB per character, 1 MB per row (. empty  - <5%  + <50%  # more)")
    for row in range(0x80300000, 0x81800000, 0x100000):
        line = ""
        for b in range(row - 0x80000000, row - 0x80000000 + 0x100000, 0x10000):
            nz = 0x10000 - mem.count(0, b, b + 0x10000)
            line += "." if nz == 0 else "-" if nz < 0xCCC else "+" if nz < 0x8000 else "#"
        print("  %08X %s" % (row, line))


if __name__ == "__main__":
    main()
