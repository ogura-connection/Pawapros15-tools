"""Write the translated menu texts, messages and pitch names into their modules.

What it is for: apart from the story scripts, the game keeps many texts in fixed places inside its modules. Three
kinds are written here, each into the module image the build has so far:
  - fixed-slot strings (menus, system text): each has a slot of a fixed number of cells and the English is written
    into it in place, nothing moves. Some groups ("blocks") are laid out again to give long strings more room, and
    their pointers are re-aimed;
  - message scripts (Pennant news and similar): each message is laid out again inside its span;
  - pitch names (a separate font): laid out again with new pointers;
  - fragments (pp15/text/fragments.py): pieces of Japanese no slot covers, English written over them in place.

Every function takes (state, module, image) and returns (new image, a note for the build log, possibly empty).

Public functions:
    encode_string(en, cells, slots, is_help)   one English UI string as the bytes of its slot
    layout_block(module, block, english, slots)   a block of movable strings laid out again
    write_ui_strings, write_message_scripts, write_pitch_names, write_fragments   the build steps
"""
import struct
import sys

from pp15.build.build_state import exit_on_value_error
from pp15.build.relocations import parse_imports
from pp15.build.text_encode import encode_text
from pp15.names import kyu
from pp15.script import scan
from pp15.text import messages, strings

STRING_END = b"\xff\xff"             # the unit 0xFFFF that closes a string
HELP_STRING_END = b"\x1f\xff"        # help strings may end in 0x1FFF instead (a line break that closes the text)


def encode_string(en: str, cells: int, slots: dict, is_help: bool = False) -> bytes:
    """An English UI string as the bytes of its slot: glyph numbers, padded with glyph 0.

    A run written {c:...} (strings.colour_runs) gets colour c in the top four bits of each of its units.
    `is_help`: a help string (strings.HELP_FILES), its line breaks written as strings.HELP_NL.
    Raises ValueError when the string does not fit `cells` cells or contains a line break.
    """
    units = []
    for colour, part in strings.colour_runs(en):
        units += [u | colour << 12 for u in encode_text(part, slots)] if colour else encode_text(part, slots)
    if is_help:
        units = [strings.HELP_NL if u == scan.TEXT_NEWLINE else u for u in units]
    if scan.TEXT_NEWLINE in units or len(units) > cells:
        raise ValueError("%r does not fit a slot of %d cells (no line breaks)" % (en, cells))
    return struct.pack(">%dH" % cells, *(units + [0] * (cells - len(units))))


def layout_block(module, block: dict, english: dict, slots: dict) -> tuple[bytes, dict, dict]:
    """A block of movable strings (strings.BLOCKS) laid out again.

    `english` = {(section, offset): (cells, text)}; a string without English keeps its Japanese.
    Returns (the bytes of the block, {position of a pointer in its section: new addend},
    {new addend: the units it must read}). Stops the build (sys.exit) if the pointer table is not as expected or the
    strings do not fit.
    """
    sec, start, end = block["section"], block["start"], block["end"]
    pointers = {pos: addend for s, pos, typ, mod, tsec, addend in module.relocs()
                if s == sec and block["table"] <= pos < block["table"] + 4 * block["count"]
                and (typ, mod, tsec) == (1, module.mod_id, sec)}                      # R_PPC_ADDR32 into the block
    if len(pointers) != block["count"] or len(set(pointers.values())) != len(pointers) \
            or not all(start <= a < end for a in pointers.values()):
        sys.exit("%s: the pointer table at sec%d+%d is not as expected" % (module.name, sec, block["table"]))
    hw = struct.unpack(">%dH" % ((end - start) // 2), module.sec_data(sec)[start:end])
    seqs = []
    for pos in sorted(pointers):
        old = pointers[pos]
        if (sec, old) in english:
            units = encode_text(english[(sec, old)][1], slots)
            if scan.TEXT_NEWLINE in units or len(units) > block["max"]:
                sys.exit("%s %d:%d: %r is not one line of %d cells" % (module.name, sec, old, english[(sec, old)][1], block["max"]))
        else:
            i = (old - start) // 2
            units = list(hw[i:hw.index(0xFFFF, i)])
        seqs.append(tuple(units))
    starts, used = strings.block_layout(seqs)
    if used > len(hw):
        sys.exit("%s: the strings at sec%d+%d need %d cells, the block has %d" % (module.name, sec, start, used, len(hw)))
    out = [0] * len(hw)
    for a, units in zip(starts, seqs):
        out[a:a + len(units) + 1] = list(units) + [0xFFFF]
    addends = {pos: start + 2 * a for pos, a in zip(sorted(pointers), starts)}
    return struct.pack(">%dH" % len(out), *out), addends, {start + 2 * a: u for a, u in zip(starts, seqs)}


def _aim_pointers(state, module, image: bytearray, section: int, addends: dict) -> int:
    """Write the new addend of every relocation of the module that sits at a position of `addends` in `section`.

    The relocation tables stay where they are; only the 4-byte addend changes. Remembers each change in
    state.moved. Returns how many were changed.
    """
    done = 0
    for mod, _, entries, _ in parse_imports(bytes(image), module.imp_off, module.imp_size):
        for sec, rpos, typ, tsec, addend, off in entries:
            if mod == module.mod_id and sec == section and rpos in addends:
                struct.pack_into(">I", image, off + 4, addends[rpos])
                state.moved[(module.mod_id, sec, rpos)] = addends[rpos]
                done += 1
    return done


def _write_slots(state, module, image: bytearray) -> None:
    """Write each fixed-slot English string into its slot (strings in movable blocks are left to _move_blocks)."""
    for (sec, off), (cells, en) in state.ui_texts[module.name].items():
        if strings.block_of(module.name, sec, off):
            continue                                     # laid out with its block, below
        is_help = module.name in strings.HELP_FILES and "\n" in en
        data = encode_string(en, cells, state.slots, is_help)
        remap = state.remaps.get((module.mod_id, sec), lambda o: o)
        pos = module.sections[sec]["offset"] + remap(off)     # sections in front of a rebuilt one stay
        if any(mid == module.mod_id and s < sec for mid, s in state.remaps):
            sys.exit("%s: a string table behind the rebuilt section is not supported" % module.name)
        wide = (module.name, sec, off) in strings.WIDE_SLOTS
        if wide:                                         # the 0xFFFF moves into the alignment cell
            assert image[pos + len(data) - 2:pos + len(data) + 2] == b"\xff\xff\x00\x00", (module.name, sec, off)
            image[pos + len(data):pos + len(data) + 2] = STRING_END
        else:
            closed_by_help_end = is_help or (module.name, sec, off) in strings.HELP_END_SLOTS
            assert image[pos + len(data):pos + len(data) + 2] in (
                (HELP_STRING_END, STRING_END) if closed_by_help_end else (STRING_END,)), (module.name, sec, off)
        image[pos:pos + len(data)] = data
        state.patched[module.mod_id][(sec, off)] = data + STRING_END * wide


def _move_blocks(state, module, image: bytearray) -> str:
    """Strings that move: lay each block out again, re-aim its pointers, check every pointer reads its string."""
    note = ""
    for blk in strings.BLOCKS.get(module.name, ()):
        if not any(strings.block_of(module.name, sec, off) is blk for sec, off in state.ui_texts[module.name]):
            continue
        if state.is_rebuilt(module):
            sys.exit("%s: a block of movable strings in a rebuilt module is not supported" % module.name)
        data, addends, reads = layout_block(module, blk, state.ui_texts[module.name], state.slots)
        pos = module.sections[blk["section"]]["offset"] + blk["start"]
        image[pos:pos + len(data)] = data
        state.patched[module.mod_id][(blk["section"], blk["start"])] = data
        done = _aim_pointers(state, module, image, blk["section"], addends)
        assert done == blk["count"], (module.name, done)
        for a, units in reads.items():                   # every pointer reads its string, closed by 0xFFFF
            at = module.sections[blk["section"]]["offset"] + a
            got = struct.unpack_from(">%dH" % (len(units) + 1), image, at)
            assert got == units + (0xFFFF,) and blk["start"] <= a < blk["end"], (module.name, a)
        note += ", %d strings laid out again at sec%d+%d" % (blk["count"], blk["section"], blk["start"])
    return note


def write_ui_strings(state, module, image: bytes) -> tuple[bytes, str]:
    """Build step: the fixed-slot strings of the module (menus, system text), in place or in movable blocks."""
    if module.name not in state.ui_texts:
        return image, ""
    image = bytearray(image)
    state.patched.setdefault(module.mod_id, {})
    _write_slots(state, module, image)
    note = _move_blocks(state, module, image)
    return bytes(image), note + ", %d UI strings" % len(state.ui_texts[module.name])


def write_message_scripts(state, module, image: bytes) -> tuple[bytes, str]:
    """Build step: message scripts (Pennant news and similar), each laid out again inside its own span."""
    if module.name not in state.message_texts:
        return image, ""
    if state.is_rebuilt(module):
        sys.exit("%s: message scripts in a rebuilt module are not supported" % module.name)
    image = bytearray(image)
    state.patched.setdefault(module.mod_id, {})
    for (sec, off), (msg, pieces) in state.message_texts[module.name].items():
        units = messages.encode(msg, pieces, lambda text: encode_text(text, state.slots))
        data = struct.pack(">%dH" % len(units), *units)
        if state.ui_string_inside(module, [(sec, off, off + len(data))]):
            sys.exit("%s %d:%d: a UI string is translated inside this message" % (module.name, sec, off))
        pos = module.sections[sec]["offset"] + off
        image[pos:pos + len(data)] = data
        state.patched[module.mod_id][(sec, off)] = data
    return bytes(image), ", %d messages" % len(state.message_texts[module.name])


def write_pitch_names(state, module, image: bytes) -> tuple[bytes, str]:
    """Build step: the pitch names (their own font): new layout, new pointers."""
    if module.name not in kyu.BLOCKS or not state.kyu_english:
        return image, ""
    if state.is_rebuilt(module):
        sys.exit("%s: pitch names in a rebuilt module are not supported" % module.name)
    blk = kyu.BLOCKS[module.name]
    if state.ui_string_inside(module, [(blk["section"], blk["start"], blk["end"])]):
        sys.exit("%s: a UI string is translated inside the pitch names" % module.name)
    with exit_on_value_error():
        data, addends, reads = kyu.layout(module, blk, state.kyu_english)
    image = bytearray(image)
    pos = module.sections[blk["section"]]["offset"] + blk["start"]
    image[pos:pos + len(data)] = data
    state.record(module, blk["section"], blk["start"], data)
    done = _aim_pointers(state, module, image, blk["section"], addends)
    assert done == blk["count"], (module.name, done)
    for a, s in reads.items():                           # every pointer reads its name, closed by the end mark
        at = module.sections[blk["section"]]["offset"] + a
        assert image[at:at + len(s) + 1] == s + bytes([kyu.END]) and blk["start"] <= a < blk["end"]
    return bytes(image), ", %d pitch names" % len(state.kyu_english)


def write_fragments(state, module, image: bytes) -> tuple[bytes, str]:
    """Build step: fragments, each English written over the cells of its Japanese with the original colour bits.

    Runs after every other step and refuses a fragment whose bytes an earlier step changed or that a fixed-slot string
    overlaps, so two writers never share bytes."""
    pieces = getattr(state, "fragments", {}).get(module.name)
    if not pieces:
        return image, ""
    if any(mid == module.mod_id and s < sec for mid, s in state.remaps for sec, _ in pieces):
        sys.exit("%s: a fragment behind a rebuilt section is not supported" % module.name)
    image = bytearray(image)
    for (sec, off), (cells, colour, en) in sorted(pieces.items()):
        if state.ui_string_inside(module, [(sec, off, off + 2 * cells)]):
            sys.exit("%s %d:%d: a fixed-slot string lies inside this fragment" % (module.name, sec, off))
        remap = state.remaps.get((module.mod_id, sec), lambda o: o)
        pos = module.sections[sec]["offset"] + remap(off)
        if bytes(image[pos:pos + 2 * cells]) != module.sec_data(sec)[off:off + 2 * cells]:
            sys.exit("%s %d:%d: an earlier build step changed the bytes of this fragment" % (module.name, sec, off))
        units = [u | colour << 12 for u in encode_text(en, state.slots)]
        if scan.TEXT_NEWLINE in units or len(units) > cells:
            sys.exit("%s %d:%d: %r does not fit %d cells (no line breaks)" % (module.name, sec, off, en, cells))
        data = struct.pack(">%dH" % cells, *(units + [0] * (cells - len(units))))
        image[pos:pos + len(data)] = data
        state.record(module, sec, off, data)
    return bytes(image), ", %d fragments" % len(pieces)
