"""The working state of one build, shared by the build stages.

What it is for: building the English game is a long chain of steps (write the scripts out again, add the name
tables, patch every module, rewrite the memory plan, verify). Each step reads what the earlier ones decided and adds
its own results. `BuildState` is the one place that holds those results, so every step can be a small function
with a clear name instead of a few hundred lines sharing local variables.

Public names:
    BuildState                 the state; the attributes are listed in its docstring
    exit_on_value_error()      turn a ValueError of a check into a plain error message that stops the build
"""
import contextlib
import sys


@contextlib.contextmanager
def exit_on_value_error():
    """Inside `with`, a ValueError (the build's way of saying "this input is wrong") ends the program with its message."""
    try:
        yield
    except ValueError as e:
        sys.exit(str(e))


class BuildState:
    """Everything the build stages share. Created by `pipeline.prepare`, filled by the stages in order.

    Inputs (set once):
        orig            all original modules {module id: scan.Rel}
        scripts         the four Success Mode scripts (scan.Script)
        blocks          the scripts of the other modes (scan.BlockScript), laid out again in place
        ui_texts        English of fixed-slot strings {module name: {(section, offset): (cells, text)}}
        message_texts   English of message scripts {module name: {(section, offset): (message, pieces)}}
        dol             the dialog strings of main.dol with their English (dol_block.load_dol)
        kyu_english     English pitch names, or empty
        names, players, stores, schools, ore_names
                        the English name tables (surnames, real players, in-place name stores, school names,
                        My Life names); `names` is None when there is no name table to build
        slots           {letter pair: glyph number}, from font_assign.assign_pairs
        repl            {module name: {halfword index: units}}: the encoded replacement of every dialogue run

    Results (filled while building):
        remaps          {(module id, section): Remap}: how rebuilt sections moved
        new_secs        {module id: (section, new section bytes)} sections that were written again
        inplace         {(module id, section): BlockRemap} for scripts laid out again in their own space
        block_data      {module id: (section, offset, bytes)} the bytes of those scripts
        ores            the My Life scripts laid out (dicts: sc, segs, remap, annex, host)
        annexes         the annex bytes of all My Life scripts, one behind the other
        extra_images    {module name: (original image, new image, address or None)} for the My Life memory plan
        images          {module name: (original image, new image)} for the Success Mode memory plan
        patched         {module id: {(section, offset): bytes}} bytes changed in place (checked by verify)
        moved           {(module id, section, position): addend} pointers re-aimed on purpose
        changed         names of the files that differ from the original

        host, name_bytes, short, host_names, name_remap
                        the surname table appended to scc_main.rel and the 8-letter table of main_prg.rel
        school_ptrs, school_addr, ore_ptrs, ore_addr
                        pointer tables and address functions of the school names and the My Life names
    """

    def __init__(self, orig, scripts, blocks, ui_texts, message_texts, dol, kyu_english):
        self.orig, self.scripts, self.blocks = orig, scripts, blocks
        self.ui_texts, self.message_texts, self.dol, self.kyu_english = ui_texts, message_texts, dol, kyu_english
        self.names = self.players = self.stores = self.schools = self.ore_names = None
        self.slots, self.repl = {}, {}
        self.remaps, self.new_secs, self.inplace, self.block_data = {}, {}, {}, {}
        self.ores, self.annexes, self.extra_images, self.images = [], b"", {}, {}
        self.patched, self.moved, self.changed = {}, {}, []
        self.host = self.name_bytes = self.short = self.host_names = self.name_remap = None
        self.school_ptrs, self.school_addr, self.ore_ptrs, self.ore_addr = {}, None, {}, None

    def record(self, module, sec: int, off: int, data: bytes) -> None:
        """Remember that `data` was written at section `sec` + `off` of the module, so that verify() expects it."""
        self.patched.setdefault(module.mod_id, {})[(sec, off)] = data

    def is_rebuilt(self, module) -> bool:
        """True if the module's section was written again or an earlier step re-aimed a pointer inside it."""
        return module.mod_id in self.new_secs or any(mid == module.mod_id for mid, _ in self.remaps)

    def ui_string_inside(self, module, ranges: list) -> bool:
        """True if a translated fixed-slot string of the module lies in one of the (section, from, to) ranges.

        Two writers must never touch the same bytes, so a step that writes a region asks this first.
        """
        return any(s == sec and lo <= o < hi
                   for s, o in self.ui_texts.get(module.name, ()) for sec, lo, hi in ranges)
