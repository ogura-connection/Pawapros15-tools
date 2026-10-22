"""The memory plan: where in the Wii's memory the game loads each module, and how big it says each module is.

What it is for: the game loads every module (REL file) at a fixed address. The file /moduleID2addr.o on the disc
holds three tables per module (address, memory size, file size), and the game reads exactly "file size" bytes, so a
module that grew but is not entered there is loaded cut off. This module reads and updates those tables so that
modules grown by the English text still fit in memory and are read completely.

In the original plan scs_main.rel (Success Mode, the main script) ends 8 bytes before the scenario modules
(scs_sce1/2/3.rel, one shared slot of 0x5D980 bytes). When the English needs more room the build moves the
scenario slot to memory the plan leaves unused (FREE_AREA, 2.1 MB) and lets scs_main.rel grow into the old slot
(up to +383 KB). The build stops if a module does not fit even then.

Public names:
    PLAN_FILE                          name of the plan file
    plan_tables(plan)                  file offsets of the three tables and the number of modules
    memory_size(image)                 memory a module needs once linked
    plan_index(plan, image)            the row of a module in the plan
    update_plan(plan, images)          the plan with the four Success Mode script modules grown
    update_plan_ore(plan, orig_plan, changes)   the plan with the My Life modules changed
"""
import struct
import sys

from pp15.build.relocations import HEADER_FIX_SIZE

PLAN_FILE = "moduleID2addr.o"       # an ELF object file; its symbols name the three tables

# The game reserves everything below 0x814E0000 for modules (main.dol 0x8003A938 raises the OS arena to it) and its
# plan ends at 0x812CB794: the area in between is free.
MAIN, SCENARIOS = "scs_main.rel", ("scs_sce1.rel", "scs_sce2.rel", "scs_sce3.rel")
SCENARIO_SLOT = (0x80B5F880, 0x80BBD200)      # start, end of the memory the scenario modules share
FREE_AREA = (0x812CB800, 0x814E0000)          # start, end of memory the plan leaves unused
# My Life: the scenes that do not fit in orepena.rel go behind the data of ore_work.rel, which is then loaded here,
# in the upper part of the free area (the scenario modules use the lower part).
ORE_WORK_ADDR = 0x81400000

# Offsets in the REL header of the numbers that decide a module's memory use.
HEADER_BSS_SIZE = 0x20       # size of the zero-filled data (BSS) added behind the module
HEADER_BSS_ALIGN = 0x44      # alignment of the BSS
ELF_SECTION_TABLE_OFFSET = 0x20      # in the ELF header: where the section headers are
ELF_SECTION_ENTRY = 0x2E             # ... and their size and number (two u16)
ELF_SYMBOL_SIZE = 16


def plan_tables(plan: bytes) -> tuple[int, int, int, int]:
    """File offsets of the address, memory-size and file-size tables in the plan file, and the number of rows."""
    shoff = struct.unpack_from(">I", plan, ELF_SECTION_TABLE_OFFSET)[0]
    shentsize, shnum = struct.unpack_from(">HH", plan, ELF_SECTION_ENTRY)
    secs = [struct.unpack_from(">10I", plan, shoff + i * shentsize) for i in range(shnum)]
    symtab = next(s for s in secs if s[1] == 2)         # section type 2 = symbol table
    strtab = secs[symtab[6]][4]
    out = {}
    for k in range(symtab[5] // ELF_SYMBOL_SIZE):
        name, value, size, _, _, shndx = struct.unpack_from(">IIIBBH", plan, symtab[4] + k * ELF_SYMBOL_SIZE)
        name = plan[strtab + name:plan.index(b"\0", strtab + name)].decode()
        if name.startswith("moduleID2") and shndx < shnum:
            out[name] = (secs[shndx][4] + value, size // 4)
    return out["moduleID2addr"][0], out["moduleID2size"][0], out["moduleID2relFileSize"][0], out["moduleID2addr"][1]


def memory_size(image: bytes) -> int:
    """Memory a module needs once linked: the part kept after linking, then its BSS (aligned as the header says)."""
    bss_size, bss_align, fix_size = (struct.unpack_from(">I", image, o)[0]
                                     for o in (HEADER_BSS_SIZE, HEADER_BSS_ALIGN, HEADER_FIX_SIZE))
    return (fix_size + bss_align - 1) // bss_align * bss_align + bss_size


def _rows_of(plan: bytes, image: bytes) -> list[int]:
    """The rows of the plan whose file size and memory size are those of `image`."""
    t_addr, t_size, t_file, n = plan_tables(plan)
    return [i for i in range(n) if struct.unpack_from(">I", plan, t_file + i * 4)[0] == len(image)
            and struct.unpack_from(">I", plan, t_size + i * 4)[0] == memory_size(image)]


def plan_index(plan: bytes, image: bytes) -> int:
    """The row of a module in the memory plan (found by its file size and the memory it needs)."""
    hits = _rows_of(plan, image)
    if len(hits) != 1:
        raise ValueError("a module is not in the memory plan, or twice (%d rows)" % len(hits))
    return hits[0]


def update_plan_ore(plan: bytes, orig_plan: bytes, changes: dict) -> bytes:
    """The plan with the My Life modules changed.

    changes = {module name: (original image, new image, new address or None)}. A module with an address is moved
    there (the annex host, ore_work.rel); the others only get their new file size and must not need more memory.
    Stops the build (sys.exit) when a module would overlap another or leave the free area.
    """
    d = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    for name, (old, new, addr) in changes.items():
        i = plan_index(orig_plan, old)
        struct.pack_into(">I", d, t_file + i * 4, len(new))
        if addr is None:
            if memory_size(new) != memory_size(old):
                sys.exit("%s would need another amount of memory; it cannot grow." % name)
            continue
        end = addr + memory_size(new)
        for k in range(n):                  # nothing else may reach into the place (the scenario modules do not)
            a2, s2 = (struct.unpack_from(">I", d, t + k * 4)[0] for t in (t_addr, t_size))
            if k != i and s2 and a2 < end and a2 + s2 > addr:
                sys.exit("%s at 0x%08X would share memory with module row %d of the plan (0x%08X..0x%08X)."
                         % (name, addr, k, a2, a2 + s2))
        if end > FREE_AREA[1]:
            sys.exit("%s does not fit in the free memory: it ends at 0x%08X, the limit is 0x%08X (%d bytes "
                     "too many)." % (name, end, FREE_AREA[1], end - FREE_AREA[1]))
        struct.pack_into(">I", d, t_addr + i * 4, addr)
        struct.pack_into(">I", d, t_size + i * 4, memory_size(new))
        print("  %-13s 0x%08X..0x%08X, %d KB of room left" % (name, addr, end, (FREE_AREA[1] - end) // 1024))
    return bytes(d)


def update_plan(plan: bytes, images: dict) -> bytes:
    """The plan with the four Success Mode script modules grown. Returns the new moduleID2addr.o.

    images = {module name: (original image, new image)}. The file size and memory size of each module are updated.
    If scs_main.rel no longer fits in front of the scenario slot, the scenario modules move to FREE_AREA and
    scs_main.rel may use their old slot. Stops the build (sys.exit) when a module does not fit.
    """
    d = bytearray(plan)
    t_addr, t_size, t_file, n = plan_tables(plan)
    index = {}
    for name, (old, _) in images.items():
        hits = _rows_of(plan, old)
        if len(hits) != 1:
            raise ValueError("%s: not found in the memory plan" % name)
        index[name] = hits[0]
    addr = {name: struct.unpack_from(">I", plan, t_addr + i * 4)[0] for name, i in index.items()}
    need = {name: memory_size(new) for name, (_, new) in images.items()}
    if addr[MAIN] + need[MAIN] > SCENARIO_SLOT[0] or \
            max(need[fn] for fn in SCENARIOS) > SCENARIO_SLOT[1] - SCENARIO_SLOT[0]:
        for fn in SCENARIOS:
            addr[fn] = FREE_AREA[0]
        print("  memory plan: scenario modules moved to 0x%08X, scs_main.rel may use their old slot" % FREE_AREA[0])
        limit = {MAIN: SCENARIO_SLOT[1], **{fn: FREE_AREA[1] for fn in SCENARIOS}}
    else:
        limit = {MAIN: SCENARIO_SLOT[0], **{fn: SCENARIO_SLOT[1] for fn in SCENARIOS}}
    for name, (old, new) in images.items():
        i, end = index[name], addr[name] + need[name]
        struct.pack_into(">I", d, t_addr + i * 4, addr[name])
        struct.pack_into(">I", d, t_size + i * 4, need[name])
        struct.pack_into(">I", d, t_file + i * 4, len(new))
        if end > limit[name]:
            sys.exit("%s does not fit in memory: it needs 0x%X bytes at 0x%08X, the limit is 0x%08X "
                     "(%d bytes too many)." % (name, need[name], addr[name], limit[name], end - limit[name]))
        if old != new:
            print("  %-13s 0x%08X..0x%08X, %d KB of room left" % (name, addr[name], end, (limit[name] - end) // 1024))
    return bytes(d)
