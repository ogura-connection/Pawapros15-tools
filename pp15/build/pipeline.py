"""The build itself: from a translation to checked, installable game files.

What it is for: `pp15 build` calls `build()`. It runs the stages in order, each in its own module:
  1. prepare            load the original modules, the name tables and the English; choose the font slots for every
                        letter pair (font_assign.py)
  2. lay_out_scripts    write every story script out again (script_stage.py)
  3. name tables        append the English name tables (name_stage.py)
  4. dialogs of main.dol  lay the system dialog block out again (dol_block.py)
  5. build_modules      put each module together and write it to _work/build/ (module_stage.py)
  6. memory plan        record the new file and memory sizes (memory_plan.py)
  7. verify             re-read everything and compare with the originals (verify.py, dol_block.verify_dol)
Nothing is installed here; rebuild.py copies the checked files to DATA/ afterwards.

Public functions:
    prepare(...)   -> BuildState with the inputs loaded and the font slots chosen
    build(...)     -> the names of the files that differ from the original
"""
import os
import shutil
import sys

from pp15.build import dol_block, name_stage, script_stage
from pp15.build.build_state import BuildState, exit_on_value_error
from pp15.build.font_assign import assign_pairs
from pp15.build.memory_plan import PLAN_FILE, memory_size, plan_tables, update_plan, update_plan_ore
from pp15.build.module_files import BUILD_DIR, ORIG_DIR, load_dir, load_scripts
from pp15.build.module_stage import build_modules
from pp15.build.text_encode import encode_text
from pp15.build.verify import verify
from pp15.names import kyu, schools, table
from pp15.script import scan
from pp15.text import fragments, strings


def _require_clean_parse(script_list: list) -> None:
    """Stop the build if any script did not parse without errors (rebuilding it would corrupt the game)."""
    for sc in script_list:
        if sc.errors or len(sc.hw) * 2 != sc.rel.sections[sc.sec]["size"]:
            sys.exit("%s: script does not parse cleanly, not rebuilding" % sc.rel.name)


def _english_names(state) -> list:
    """Every name in English that needs a font slot: surnames, short names, real players, in-place names, My Life."""
    if not state.names:
        return ()
    return (table.plates(state.names) + table.short_names(state.names) + table.player_plates(state.players)
            + table.inplace_plates(state.stores) + list(state.ore_names.values()))


def prepare(texts: dict, ui_texts: dict | None, dol_entries: list | None, message_texts: dict | None) -> BuildState:
    """Load the originals and every English table, and choose the font slot of every letter pair.

    texts = {module name: {halfword index: English}} (translation_file.load_translation);
    ui_texts = strings.load_for_build(); dol_entries = strings.load_dol_for_build();
    message_texts = messages.load_for_build().
    """
    orig = load_dir(ORIG_DIR)
    scripts = load_scripts(orig)
    kyu_english = kyu.load_tsv()
    dol = dol_block.load_dol(dol_entries)
    _require_clean_parse(scripts)
    blocks = scan.load_block_scripts(orig)         # scripts of the other modes: laid out again in place
    _require_clean_parse(blocks)
    state = BuildState(orig, scripts, blocks, ui_texts or {}, message_texts or {}, dol, kyu_english)
    state.names = table.load_tsv() if os.path.exists(table.TSV) else None
    state.players = table.load_players() if state.names and os.path.exists(table.PLAYERS_TSV) else []
    state.stores = table.inplace_stores() if state.names else {}       # given names ...: written in place
    state.schools = schools.load_tsv() if state.names else {}          # Eikan Nine school names: a table behind the surnames
    state.ore_names = schools.load_tsv(schools.ORE_TSV)                # My Life names: a table behind the annexes
    with exit_on_value_error():
        state.fragments = fragments.load_for_build(orig)       # pieces of text no slot covers, written in place
    counted = {name: dict(state.ui_texts.get(name, {})) for name in set(state.ui_texts) | set(state.fragments)}
    for name, pieces in state.fragments.items():               # their letter pairs count like those of the strings
        counted[name].update({key: (cells, "" if en == fragments.BLANK else en) for key, (cells, _, en) in pieces.items()})
    state.slots = assign_pairs(scripts + blocks, texts, orig, counted, dol, state.message_texts,
                               _english_names(state), narrow=list(state.schools.values()))
    state.repl = {name: {i: encode_text(t, state.slots) for i, t in runs.items()} for name, runs in texts.items()}
    state.images = {sc.rel.name: (sc.rel.data, sc.rel.data) for sc in scripts}
    return state


def _write_dol(state) -> None:
    """Lay the dialog block of main.dol out again and keep it in _work/build/ (the build folder is emptied first)."""
    dol_image = dol_block.build_dol(state.dol, state.slots, state.orig, state.remaps) if state.dol else None
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    os.makedirs(BUILD_DIR)
    if state.dol and dol_image != strings.dol_data():
        with open(dol_block.DOL_BUILT, "wb") as f:
            f.write(dol_image)
        state.changed.append(dol_block.DOL)


def _write_memory_plan(state) -> None:
    """Update moduleID2addr.o for the grown modules and write it to _work/build/ when it changed."""
    with open(os.path.join(ORIG_DIR, PLAN_FILE), "rb") as f:
        plan = f.read()
    new_plan = update_plan(plan, state.images)
    if state.extra_images:
        new_plan = update_plan_ore(new_plan, plan, state.extra_images)
    if state.names:                           # scc_main.rel moves to the free area with its surname table
        with open(os.path.join(BUILD_DIR, table.HOST), "rb") as f:
            host_image = f.read()
        with exit_on_value_error():
            new_plan, end = table.place_host(new_plan, plan, state.host.data, host_image, plan_tables, memory_size)
        print("  %-13s 0x%08X..0x%08X" % (table.HOST, table.HOST_ADDR, end))
    if new_plan != plan:
        with open(os.path.join(BUILD_DIR, PLAN_FILE), "wb") as f:
            f.write(new_plan)
        state.changed.append(PLAN_FILE)


def _dropped_relocations(state) -> set:
    """Relocations the build turned into R_NOP because the pointer became an absolute address (school and My Life names)."""
    dropped = {(m.mod_id, schools.SECTION, pos) for m in state.orig.values()
               if m.name == schools.MODULE for pos in state.school_ptrs}
    dropped |= {(m.mod_id, schools.SECTION, pos) for m in state.orig.values()
                if m.name == schools.ORE_MODULE for pos in state.ore_ptrs}
    return dropped


def _verify_build(state) -> None:
    """Re-read the built files and check them against the originals (verify.py, then main.dol)."""
    dropped = _dropped_relocations(state)
    new = verify(state.orig, state.scripts, state.repl, state.remaps, state.patched, state.moved, state.inplace,
                 state.blocks, state.ores, dropped)
    if state.names:                           # the appended table reads back as built
        h = new[state.host.mod_id]
        start = state.name_remap.new_table
        got = h.sec_data(table.HOST_SECTION)[start:start + len(state.name_bytes)]
        assert got == state.name_bytes and len(h.sec_data(table.HOST_SECTION)) == state.name_remap.hi + state.name_remap.growth, h.name
        assert all(h.sec_data(ps)[po:po + len(v)] == v for (ps, po), v in state.host_names.items()), h.name
        print("Verified: %s holds the %d-byte surname table at sec%d+0x%X." % (h.name, len(got), table.HOST_SECTION, start))
    if state.dol:                             # the My Life modules: relocations and sections are checked in verify()
        dol_block.verify_dol(state.orig, new, state.dol, state.slots,
                             tuple(state.extra_images) + ((table.HOST,) if state.names else ()), dropped)


def build(texts: dict, pad: dict | None = None, ui_texts: dict | None = None, dol_entries: list | None = None,
          message_texts: dict | None = None) -> list[str]:
    """Build every changed module, and main.dol, into _work/build/. Returns the list of file names that changed.

    texts = the translation (translation_file.load_translation); pad = {module name: extra bytes} (test option);
    ui_texts, dol_entries, message_texts = the loaders of strings.py / messages.py named in `prepare`.
    Stops (SystemExit with a message) when a check fails; nothing in DATA/ is touched.
    """
    state = prepare(texts, ui_texts, dol_entries, message_texts)
    script_stage.lay_out_scripts(state, pad)
    name_stage.add_my_life_names(state)
    name_stage.add_surname_and_school_tables(state)
    _write_dol(state)
    build_modules(state)
    _write_memory_plan(state)
    _verify_build(state)
    return state.changed
