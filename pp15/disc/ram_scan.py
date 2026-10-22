"""Look inside a Dolphin save state: which game modules are loaded where, and how much memory holds data.

    pp15 ram-scan STATE_FILE        e.g. <dolphin-test>/StateSaves/RP5JA4.s01 (config.EMU_DIR)

What it is for: the game loads its code modules (.rel files) into memory at addresses given by a "memory plan" (the
file moduleID2addr.o, see FINDINGS.md). A Dolphin save state is a copy of the console's memory at one moment, so it
shows where the modules really are and how much room is left, which matters when translated modules grow.

Works for Jikkyou Powerful Pro Yakyuu 15 (Wii, game id RP5JA4, Rev 1) and the Dolphin 2609a state format. Prints the
modules in the system's module queue with their real addresses, notes the ones not at an address of the original plan,
and draws a map of which memory holds data. The memory dump is written to _work/ram/ (game data: git-ignored, never
commit it). Faster with `pip install lz4`; without it the slow decompressor of pp15/disc/lz4_fallback.py is used.

Public functions: decompress_lz4, read_mem1, loaded_modules, main.
"""
import argparse
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Tuple

from pp15 import config
from pp15.build import rebuild
from pp15.disc import lz4_fallback
from pp15.script import scan

MEM1_SIZE = 0x1800000           # the Wii's main memory: 24 MB
MEM1_BASE = 0x80000000          # its address as the game sees it
GAME_ID = b"RP5JA4"
WII_DISC_MAGIC = b"\x5d\x1c\x9e\xa3"        # at +0x18 of the game id header in memory
MODULE_QUEUE_HEAD = 0x800030C8              # address of the OS's list of loaded modules
POOL_START = 0x814E0000                     # the general memory pool begins here; modules live below it
STATE_HEADER_SIZE = 0x20
GAP_NOTE_BYTES = 0x1000                     # report free gaps larger than this between modules
MAP_START, MAP_END, MAP_ROW, MAP_CELL = 0x80300000, 0x81800000, 0x100000, 0x10000   # memory map: 1 MB rows of 64 KB cells


def decompress_lz4(src: bytes, size: int) -> bytes:
    """Decompress an LZ4 block that unpacks to `size` bytes, with the `lz4` package if installed, else the slow
    built-in decompressor."""
    try:
        import lz4.block
    except ImportError:
        return lz4_fallback.decompress_block(src)
    return lz4.block.decompress(src, uncompressed_size=size)


def read_mem1(path: str) -> bytes:
    """The Wii's main memory (MEM1, 24 MB) from a Dolphin 2609a save state file. Exits with a message if the state is
    not in the expected format (one LZ4 block) or the game's memory is not found in it."""
    with open(path, "rb") as f:
        data = f.read()
    p = STATE_HEADER_SIZE + struct.unpack_from("<I", data, 0x1C)[0]
    for q in range(p, p + 32):                  # find the block header: uncompressed size (8 bytes), compressed size (4)
        uncompressed_size, compressed_size = struct.unpack_from("<Qi", data, q)
        if q + 12 + compressed_size == len(data) and 0 < uncompressed_size < 1 << 31:
            break
    else:
        sys.exit("State header not understood (written for Dolphin 2609a, LZ4, one block)")
    raw = decompress_lz4(data[q + 12:], uncompressed_size)
    for m in re.finditer(re.escape(GAME_ID), raw):
        if raw[m.start() + 0x18:m.start() + 0x1C] == WII_DISC_MAGIC:
            return raw[m.start():m.start() + MEM1_SIZE]
    sys.exit("MEM1 not found in the state")


def loaded_modules(mem: bytes, modules: Dict[int, "scan.Rel"]) -> List[Tuple[int, int, str]]:
    """The modules in the OS module queue: [(start address, end address, module name)].

    Arguments: `mem` the memory from read_mem1, `modules` {module id: scan.Rel} of the original modules (for names).
    Each queue entry holds the module id, the next entry, ..., the number of sections and the section table; the end
    address is the end of the module's last section."""
    u32 = lambda address: struct.unpack_from(">I", mem, address - MEM1_BASE)[0]
    live, p = [], u32(MODULE_QUEUE_HEAD)
    while p:
        module_id, next_entry, _, section_count, sections = struct.unpack_from(">5I", mem, p - MEM1_BASE)
        end = p
        for k in range(section_count):
            off, size = struct.unpack_from(">II", mem, sections - MEM1_BASE + k * 8)
            if off and size:
                end = max(end, (off & ~3) + size)
        live.append((p, end, modules[module_id].name if module_id in modules else "module %d" % module_id))
        p = next_entry
    return live


def planned_addresses() -> Dict[int, List[int]]:
    """{address: [sizes]} of the original memory plan (moduleID2addr.o)."""
    plan_dir = rebuild.ORIG_DIR if os.path.isdir(rebuild.ORIG_DIR) else config.DATA_FILES
    with open(os.path.join(plan_dir, rebuild.PLAN_FILE), "rb") as f:
        plan = f.read()
    address_table, size_table, _, rows = rebuild.plan_tables(plan)
    planned = {}
    for i in range(rows):
        planned.setdefault(struct.unpack_from(">I", plan, address_table + i * 4)[0], []).append(
            struct.unpack_from(">I", plan, size_table + i * 4)[0])
    return planned


def print_modules(live: List[Tuple[int, int, str]], planned: Dict[int, List[int]]) -> None:
    """Print the loaded modules by address, with a note for each one not at a planned address and for big gaps."""
    print("Loaded modules: %d (general memory pool starts at 0x%08X)" % (len(live), POOL_START))
    previous_end = 0
    for start, end, name in sorted(live):
        note = "" if start in planned else "   not at an address of the original plan"
        if previous_end and start - previous_end > GAP_NOTE_BYTES:
            note += "   (%d KB free before it)" % ((start - previous_end) // 1024)
        print("  %08X-%08X %8d KB  %-13s%s" % (start, end, (end - start) // 1024, name, note))
        previous_end = max(previous_end, end)


def print_memory_map(mem: bytes) -> None:
    """Draw which memory holds data: one character per 64 KB, one row per MB (. empty, - under 5%, + under 50%, # more)."""
    print("\nMemory holding data, 64 KB per character, 1 MB per row (. empty  - <5%  + <50%  # more)")
    for row in range(MAP_START, MAP_END, MAP_ROW):
        line = ""
        for cell in range(row - MEM1_BASE, row - MEM1_BASE + MAP_ROW, MAP_CELL):
            nonzero = MAP_CELL - mem.count(0, cell, cell + MAP_CELL)
            line += "." if nonzero == 0 else "-" if nonzero < 0xCCC else "+" if nonzero < 0x8000 else "#"
        print("  %08X %s" % (row, line))


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 ram-scan STATE`. `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 ram-scan", description=__doc__.split("\n\n")[0])
    parser.add_argument("state", metavar="STATE", help="a Dolphin save state, e.g. <dolphin-test>/StateSaves/RP5JA4.s01")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    mem = read_mem1(args.state)
    os.makedirs(os.path.join(config.WORK_DIR, "ram"), exist_ok=True)
    with open(os.path.join(config.WORK_DIR, "ram", os.path.basename(args.state) + ".mem1"), "wb") as f:
        f.write(mem)
    live = loaded_modules(mem, scan.load_all_rels())
    print_modules(live, planned_addresses())
    print_memory_map(mem)


if __name__ == "__main__":
    main()
