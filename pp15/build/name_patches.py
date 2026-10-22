"""Build steps that write names into the modules that use them.

What it is for: name_stage.py appended the new name tables. Here each module that reads a name gets its change:
pointers re-aimed at the appended tables, small name tables rewritten in place, and the few names that code builds
by itself. Every function takes (state, module, image) and returns (new image, a note for the build log, possibly
empty). A step that does not concern the module returns the image unchanged.

Public functions:
    patch_school_pointers    sct_main.rel: school names point at the table appended to scc_main.rel
    write_short_surnames     main_prg.rel: the 8-letter surname table, and the real players' names
    write_name_stores        modules with name tables in place (given names ...)
    patch_surname_readers    code that reads the surname table now reads six cells
    patch_name_in_code       a name built by code (a My Life rival)
"""
import sys

from pp15.build.build_state import exit_on_value_error
from pp15.build.text_encode import encode_text
from pp15.names import schools, table

PLAYER_NAME_BYTES = 12      # a real player's name: six 16-bit cells
PLAYER_SECTION = 5          # main_prg.rel section that holds the real players' names


def patch_school_pointers(state, module, image: bytes) -> tuple[bytes, str]:
    """School names: pointers to the table in scc_main.rel."""
    if not (state.names and state.schools and module.name == schools.MODULE):
        return image, ""
    with exit_on_value_error():
        image, written = schools.patch_pointers(module, image, state.school_ptrs, state.school_addr)
    state.patched.setdefault(module.mod_id, {}).update(written)
    return image, ", %d school-name pointers into %s" % (len(written), table.HOST)


def _write_players(state, module, image: bytes) -> tuple[bytes, str]:
    """Real players: every copy of every name, in place in section 5."""
    with exit_on_value_error():
        patches = table.player_patches(module, state.players, lambda t: encode_text(t, state.slots))
    base = module.sections[PLAYER_SECTION]["offset"]
    if any(state.ui_string_inside(module, [(PLAYER_SECTION, o, o + PLAYER_NAME_BYTES)]) for o in patches):
        sys.exit("%s: a UI string is translated inside a player name" % module.name)
    image = bytearray(image)
    for o, data in patches.items():
        image[base + o:base + o + len(data)] = data
        state.patched[module.mod_id][(PLAYER_SECTION, o)] = data
    return bytes(image), ", %d real players in %d places" % (len(state.players), len(patches))


def write_short_surnames(state, module, image: bytes) -> tuple[bytes, str]:
    """The surname table in place with eight letters (main_prg.rel), then the real players' names."""
    if not (state.names and module.name == table.SHORT_HOST):
        return image, ""
    start = table.SHORT_TABLE
    new_table = state.short[0]
    if state.ui_string_inside(module, [(table.SHORT_SECTION, start, start + len(new_table))]):
        sys.exit("%s: a UI string is translated inside the surname table" % module.name)
    pos = module.sections[table.SHORT_SECTION]["offset"] + start
    image = image[:pos] + new_table + image[pos + len(new_table):]
    state.record(module, table.SHORT_SECTION, start, new_table)
    note = ", surnames in 8 letters"
    if state.players:
        image, players_note = _write_players(state, module, image)
        note += players_note
    return image, note


def write_name_stores(state, module, image: bytes) -> tuple[bytes, str]:
    """Names in place (given names ...): the in-place tables of modules other than the surname host."""
    if module.name not in state.stores or (state.names and module.name == table.HOST):
        return image, ""
    with exit_on_value_error():
        patches = table.inplace_patches(module, state.stores[module.name], lambda t: encode_text(t, state.slots))
    if state.ui_string_inside(module, [(ps, po, po + len(data)) for (ps, po), data in patches.items()]):
        sys.exit("%s: a UI string is translated inside a name" % module.name)
    image = bytearray(image)
    for (ps, po), data in patches.items():
        pos = module.sections[ps]["offset"] + po
        image[pos:pos + len(data)] = data
        state.record(module, ps, po, data)
    return bytes(image), ", %d names in place" % len(patches)


def patch_surname_readers(state, module, image: bytes) -> tuple[bytes, str]:
    """Code that reads the surname table: it must read the new table, six cells per name."""
    if not (state.names and module.name in table.READERS):
        return image, ""
    with exit_on_value_error():
        image, written = table.patch_code(module, image, state.host.mod_id)
    state.patched.setdefault(module.mod_id, {}).update(written)
    return image, ", surname readers patched"


def patch_name_in_code(state, module, image: bytes) -> tuple[bytes, str]:
    """A name built by code (the My Life rival 奥居): its code words are rewritten."""
    if module.name not in table.CODE_NAMES:
        return image, ""
    with exit_on_value_error():
        image, written = table.patch_code_name(module, image, lambda t: encode_text(t, state.slots))
    state.patched.setdefault(module.mod_id, {}).update(written)
    return image, ", %d code words of a name patched" % len(written)
