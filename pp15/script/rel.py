"""Reader for REL files, the code-and-data modules the game loads while it runs.

A REL file (extension .rel) is the Wii's relocatable module format: a header, a table of sections (code, read-only data,
data, reserved memory), the section contents, and a list of "relocations". A relocation says "at this place in this
section, write the address of that place in that other module once everything is loaded". Almost all of the game's text
and scripts sit in the data sections of REL files, so every tool starts by reading them with `Rel`.

Public names:
  Rel(path)               one parsed module: sections, section bytes, relocations
  load_all_rels()         every module of the game, keyed by module id (reads the untouched originals when saved)
  RELOC_NAMES             readable names of the relocation types
  R_NOP, R_SECTION, R_END the three relocation record kinds that are not real relocations
See docs/GLOSSARY.md ("REL", "Relocation").
"""
import os
import struct
from typing import Dict, List, Tuple

from pp15 import config

# Relocation types that matter here (the PowerPC names). 1 = a full 32-bit address; the others are halves or
# branch offsets inside instructions.
RELOC_NAMES = {1: "ADDR32", 2: "ADDR24", 3: "ADDR16", 4: "ADDR16_LO", 5: "ADDR16_HI",
               6: "ADDR16_HA", 10: "REL24", 11: "REL14"}
# Record kinds in a relocation list that do not relocate anything: padding, "switch to section N", "end of list".
R_NOP, R_SECTION, R_END = 201, 202, 203

# (source section, source offset, type, target module id, target section, addend)
Relocation = Tuple[int, int, int, int, int, int]


class Rel:
    """One REL module read completely into memory.

    Attributes: path, name (file name), data (all bytes), mod_id (module number other modules use to point into this
    one), sections (list of {"index", "offset" (file offset), "size", "exec" (code), "bss" (memory only)}),
    version, bss_size, and the file offsets rel_off / imp_off / imp_size of the relocation tables."""

    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        # The header is twelve big-endian 32-bit words; the ones that are not needed here are skipped.
        (self.mod_id, _, _, nsec, sec_off, _, _, self.version, self.bss_size,
         self.rel_off, self.imp_off, self.imp_size) = struct.unpack_from(">12I", d, 0)
        self.sections: List[dict] = []
        for i in range(nsec):
            raw, size = struct.unpack_from(">II", d, sec_off + i * 8)
            off = raw & ~3                      # the low two bits of the offset are flags
            self.sections.append({"index": i, "offset": off, "size": size,
                                  "exec": bool(raw & 1), "bss": off == 0 and size != 0})
        self._relocs = None
        self._data_reloc_map = None

    def sec_data(self, i: int) -> bytes:
        """The stored bytes of section i (empty for a memory-only section)."""
        s = self.sections[i]
        if s["bss"] or not s["size"]:
            return b""
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def relocs(self) -> List[Relocation]:
        """Every real relocation of the module, read once: [(src_section, src_offset, type, target_module,
        target_section, addend)]."""
        if self._relocs is None:
            d, out = self.data, []
            for k in range(self.imp_size // 8):         # one entry per module this one points into
                mod, off = struct.unpack_from(">II", d, self.imp_off + k * 8)
                sec = pos = 0
                while True:
                    delta, typ, tsec, addend = struct.unpack_from(">HBBI", d, off)
                    off += 8
                    pos += delta
                    if typ == R_END:
                        break
                    if typ == R_SECTION:
                        sec, pos = tsec, 0
                    elif typ != R_NOP:
                        out.append((sec, pos, typ, mod, tsec, addend))
            self._relocs = out
        return self._relocs

    def data_relocs(self, sec: int, off: int) -> List[Tuple[int, int, int, int]]:
        """The relocations written at exactly (section sec, offset off): [(type, target module, target section,
        addend)]. For data tables (pointer tables) whose entries are filled in by relocations."""
        if self._data_reloc_map is None:
            self._data_reloc_map = {}
            for (s, pos, typ, tm, ts, addend) in self.relocs():
                self._data_reloc_map.setdefault((s, pos), []).append((typ, tm, ts, addend))
        return self._data_reloc_map.get((sec, off), [])

    def script_section(self) -> int:
        """Index of the section that holds the module's script: the largest stored section that is not code."""
        cands = [s for s in self.sections if s["size"] and not s["bss"] and not s["exec"]]
        return max(cands, key=lambda s: s["size"])["index"]


def load_all_rels() -> Dict[int, Rel]:
    """Every .rel module of the game, {module id: Rel}.

    Offsets used by the translation tools refer to the original files. Once `python3 -m pp15 build` has patched
    DATA/files, the originals are kept in _work/orig, so that folder is preferred when it exists."""
    orig = config.ORIG_DIR
    src = orig if os.path.isdir(orig) else config.DATA_FILES
    mods = {}
    for fn in sorted(os.listdir(src)):
        if fn.endswith(".rel"):
            r = Rel(os.path.join(src, fn))
            mods[r.mod_id] = r
    return mods
