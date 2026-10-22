"""Build stage: add the English name tables behind the data of the modules that hold names.

What it is for: names do not fit where they were. Player and school names are tables of fixed cells in the
original; in English they need more room, so the build appends new tables behind the data of modules that can grow
(or that are loaded into the heap) and re-aims the pointers at them:
  - My Life names: a table behind the annexes of ore_work.rel, for orepena.rel;
  - surnames: a wide table behind the data of scc_main.rel (loaded into the heap), used for team-mates and name
    entry, and school names appended to the same table for sct_main.rel.
The tables are appended here; the pointers into them are written later, module by module (name_patches.py).

Public functions:
    add_my_life_names(state)
    add_surname_and_school_tables(state)
"""
from pp15.build.build_state import exit_on_value_error
from pp15.build.script_emit import SECTION_ALIGN, Remap
from pp15.build.text_encode import encode_text
from pp15.build.memory_plan import ORE_WORK_ADDR
from pp15.names import schools, table
from pp15.script import scan


def add_my_life_names(state) -> None:
    """My Life names in Latin letters: a table behind the annexes of ore_work.rel, pointers made absolute.

    Sets state.ore_ptrs / state.ore_addr and extends the data section of ore_work.rel in state.new_secs.
    """
    if not state.ore_names:
        return
    my_life = next(m for m in state.orig.values() if m.name == schools.ORE_MODULE)
    spec = scan.BLOCK_SCRIPTS[schools.ORE_MODULE]
    host = next(m for m in state.orig.values() if m.name == scan.ORE_ANNEX_MODULE)
    section, data_end = spec["annex_section"], spec["annex_from"]
    with exit_on_value_error():
        state.ore_ptrs = schools.pointers(my_life, state.ore_names)
        state.ore_names = {o: state.ore_names[o] for o in set(state.ore_ptrs.values())}
        name_bytes, where = schools.table(state.ore_names, lambda t: encode_text(t, state.slots))
    current = state.new_secs[host.mod_id][1] if host.mod_id in state.new_secs else host.sec_data(section)
    pad = bytes(-len(current) % SECTION_ALIGN)
    table_start = len(current) + len(pad)
    state.new_secs[host.mod_id] = (section, current + pad + name_bytes)
    state.remaps[(host.mod_id, section)] = Remap(data_end // 2, data_end // 2, {},
                                                 len(current) + len(pad) + len(name_bytes) - data_end)
    section_address = ORE_WORK_ADDR + host.sections[section]["offset"]
    state.ore_addr = lambda off: section_address + table_start + where[off]
    print("%-13s %5d My Life names in Latin letters, %d bytes behind the annexes (for %s)"
          % (host.name, len(state.ore_names), len(pad) + len(name_bytes), my_life.name))


def _add_school_names(state, sec_data: bytes, name_remap) -> bytes:
    """Append the school names (narrow letters, for the score display) to the surname section; returns the section."""
    host = state.host
    if not state.schools:
        return sec_data
    scoreboard = next(m for m in state.orig.values() if m.name == schools.MODULE)
    with exit_on_value_error():
        state.school_ptrs = schools.pointers(scoreboard, state.schools)
        state.schools = {o: state.schools[o] for o in set(state.school_ptrs.values())}
        school_bytes, where = schools.table(state.schools, lambda t: encode_text(t, state.slots, narrow=True))
    pad = bytes(-len(sec_data) % SECTION_ALIGN)
    school_start = len(sec_data) + len(pad)
    sec_data = sec_data + pad + school_bytes
    name_remap.growth += len(pad) + len(school_bytes)
    section_address = table.HOST_ADDR + host.sections[table.HOST_SECTION]["offset"]
    state.school_addr = lambda off: section_address + school_start + where[off]
    print("%-13s %5d school names in Latin letters, %d bytes appended (for %s)"
          % (host.name, len(state.schools), len(pad) + len(school_bytes), schools.MODULE))
    return sec_data


def _write_host_names(state, sec_data: bytes, name_remap) -> bytes:
    """The host module's own name fields (foreign players): written in place inside the new section."""
    host = state.host
    state.host_names = {}
    if host.name not in state.stores:
        return sec_data
    with exit_on_value_error():
        state.host_names = table.inplace_patches(host, state.stores[host.name], lambda t: encode_text(t, state.slots))
    sec_data = bytearray(sec_data)
    for (ps, po), data in state.host_names.items():
        assert ps == table.HOST_SECTION and po + len(data) <= name_remap.hi
        sec_data[po:po + len(data)] = data
    state.patched.setdefault(host.mod_id, {}).update(state.host_names)
    return bytes(sec_data)


def add_surname_and_school_tables(state) -> None:
    """Surnames (and school names) in Latin letters appended behind the data of scc_main.rel.

    Sets state.host, name_bytes, short (the 8-letter table for main_prg.rel), name_remap, host_names,
    school_ptrs, school_addr and records the new section in state.new_secs / state.remaps.
    """
    if not state.names:
        return
    host = state.host = next(m for m in state.orig.values() if m.name == table.HOST)

    def encode(text):
        """Encode one English name with the chosen font slots."""
        return encode_text(text, state.slots)
    with exit_on_value_error():
        state.name_bytes = table.table(state.names, encode)
        short_host = next(m for m in state.orig.values() if m.name == table.SHORT_HOST)
        old_short = short_host.sec_data(table.SHORT_SECTION)[
            table.SHORT_TABLE:table.SHORT_TABLE + table.COUNT * table.OLD_STRIDE]
        state.short = table.short_table(state.names, encode, old_short)
    sec_data, state.name_remap = table.append_table(host, state.name_bytes)
    sec_data = _write_host_names(state, sec_data, state.name_remap)
    sec_data = _add_school_names(state, sec_data, state.name_remap)
    state.new_secs[host.mod_id] = (table.HOST_SECTION, sec_data)
    state.remaps[(host.mod_id, table.HOST_SECTION)] = state.name_remap
    print("%-13s %5d surnames in Latin letters, %d bytes appended; main_prg.rel: %d in 8 letters, %d stay kanji"
          % (host.name, len(state.names), state.name_remap.growth, len(state.names) - len(state.short[1]),
             len(state.short[1])))
