"""Build stage: produce the new file of every module.

What it is for: after the scripts are laid out and the name tables appended, every module is put together: its base
image (rebuilt section, re-aimed pointers, or the new font), then a series of small steps that write the other kinds
of translated content into it (fixed-slot strings, messages, names, code words, pictures). The result is written
to _work/build/ when it differs from the original.

Public functions:
    build_modules(state)    writes the changed modules to _work/build/ and fills state.changed
"""
import os
import sys

from pp15.build import code_patches, name_patches, ui_write
from pp15.build.font_assign import build_font_file
from pp15.build.memory_plan import ORE_WORK_ADDR
from pp15.build.module_files import BUILD_DIR
from pp15.build.ore_script import ore_relocations
from pp15.build.relocations import parse_imports, patch_addends, rebuild_module
from pp15.names import schools, table
from pp15.script import scan


def _base_image(state, module) -> tuple[bytes, str]:
    """The module with its own rebuilt section (or the new font), or just with its pointers re-aimed."""
    if module.name == "fonttex2.rel" and state.slots:
        return build_font_file(state.orig, state.slots), "%d glyphs replaced in both fonts" % len(state.slots)
    if module.mod_id not in state.new_secs:
        image, n = patch_addends(module, state.remaps)
        return image, "%d addends" % n
    sec, data = state.new_secs[module.mod_id]
    is_name_host = bool(state.names) and module.name == table.HOST
    remaps = {**state.remaps, **state.inplace} if is_name_host else state.remaps      # it points into block scripts
    image, note = rebuild_module(module, sec, data, remaps), "rebuilt"
    if state.ores and module is state.ores[0]["host"]:
        state.extra_images[module.name] = (module.data, image, ORE_WORK_ADDR)
    elif is_name_host:
        note = "surname table appended"         # not in the memory plan: loaded into the heap
    else:
        state.images[module.name] = (module.data, image)
    return image, note


def _relink_block_scripts(state, module, image: bytes) -> tuple[bytes, str]:
    """A block script laid out again: write its bytes into its module, and re-aim the pointers of every module."""
    if not state.inplace or module.name == "fonttex2.rel":
        return image, ""
    if module.mod_id in state.new_secs:
        n = sum((mod, e[3]) in state.inplace for mod, _, entries, _ in
                parse_imports(module.data, module.imp_off, module.imp_size) for e in entries)
        if (n and not (state.names and module.name == table.HOST)) or module.mod_id in state.block_data:
            sys.exit("%s: a rebuilt module that also points at a block script is not supported" % module.name)
        return bytes(image), ""
    if module.mod_id in state.block_data:
        sec, off, data = state.block_data[module.mod_id]
        pos = module.sections[sec]["offset"] + off
        if state.ui_string_inside(module, [(sec, off, off + len(data))]):
            sys.exit("%s: a UI string is translated inside the script" % module.name)
        image = image[:pos] + data + image[pos + len(data):]
        state.record(module, sec, off, data)
    image, n = patch_addends(module, state.inplace, bytes(image))
    return image, (", %d pointers into a script laid out again" % n) if n else ""


def _write_my_life_script(state, module, image: bytes) -> tuple[bytes, str]:
    """The My Life script and its label table; any other module must not point into that script."""
    ore = next((o for o in state.ores if module is o["sc"].rel), None)
    if not ore:
        if any(mod == o["sc"].rel.mod_id and e[3] == o["sc"].sec
               and o["sc"].region[0] <= e[4] < o["sc"].region[1] and not o["sc"].in_island(e[4])
               for o in state.ores
               for mod, _, entries, _ in parse_imports(module.data, module.imp_off, module.imp_size) for e in entries):
            sys.exit("%s points into a script of the My Life kind: not supported" % module.name)
        return image, ""
    script = ore["sc"]
    if state.is_rebuilt(module):
        sys.exit("%s: a rebuilt module cannot hold the My Life script" % module.name)
    image = bytearray(image)
    for off, data in ore["segs"]:
        if state.ui_string_inside(module, [(script.sec, off, off + len(data))]):
            sys.exit("%s: a UI string is translated inside the script" % module.name)
        pos = module.sections[script.sec]["offset"] + off
        image[pos:pos + len(data)] = data
        state.record(module, script.sec, off, data)
    image, n = ore_relocations(module, bytes(image), script, ore["remap"])
    note = ""
    if state.ore_ptrs and module.name == schools.ORE_MODULE:     # its names: pointers into ore_work.rel
        try:
            image, written = schools.patch_pointers(module, image, state.ore_ptrs, state.ore_addr)
        except ValueError as e:
            sys.exit(str(e))
        state.patched.setdefault(module.mod_id, {}).update(written)
        note += ", %d name pointers into %s" % (len(written), scan.ORE_ANNEX_MODULE)
    state.extra_images[module.name] = (module.data, image, None)
    return image, note + ", script laid out again, %d labels in the annex" % n


def _patch_code_words(state, module, image: bytes) -> tuple[bytes, str]:
    """Code words (the Linked World birth date)."""
    if module.name not in code_patches.CODE_PATCHES:
        return image, ""
    try:
        image, written = code_patches.patch_code_words(module, image)
    except ValueError as e:
        sys.exit(str(e))
    state.patched.setdefault(module.mod_id, {}).update(written)
    return image, ", %d code words patched" % len(written)


def _patch_sprite_art(state, module, image: bytes) -> tuple[bytes, str]:
    """Sprite art kept in a module (the boot controller screen)."""
    art = code_patches.rel_art().get(module.name)
    if not art:
        return image, ""
    if state.ui_string_inside(module, [(ps, po, po + len(data)) for (ps, po), data in art.items()]):
        sys.exit("%s: a UI string is translated inside sprite art" % module.name)
    image = bytearray(image)
    for (ps, po), data in art.items():
        pos = module.sections[ps]["offset"] + po
        image[pos:pos + len(data)] = data
        state.record(module, ps, po, data)
    return bytes(image), ", %d art patches" % len(art)


# The steps that write content into a module, in the order they run. Each is (state, module, image) -> (image, note).
# Order matters: the later steps overwrite regions the earlier ones may have laid out.
MODULE_STEPS = (
    ui_write.write_ui_strings,
    ui_write.write_message_scripts,
    ui_write.write_pitch_names,
    _relink_block_scripts,
    name_patches.patch_school_pointers,
    _write_my_life_script,
    name_patches.write_short_surnames,
    name_patches.write_name_stores,
    name_patches.patch_surname_readers,
    name_patches.patch_name_in_code,
    _patch_code_words,
    _patch_sprite_art,
    ui_write.write_fragments,           # last: it checks that no earlier step touched the bytes it writes over
)


def build_modules(state) -> None:
    """Put every module together; write those that differ from the original to _work/build/ (state.changed)."""
    for module in state.orig.values():
        image, note = _base_image(state, module)
        for step in MODULE_STEPS:
            image, extra = step(state, module, image)
            note += extra
        if image != module.data:
            with open(os.path.join(BUILD_DIR, module.name), "wb") as f:
                f.write(image)
            state.changed.append(module.name)
            print("  %-13s %s, 0x%X -> 0x%X bytes" % (module.name, note, len(module.data), len(image)))
