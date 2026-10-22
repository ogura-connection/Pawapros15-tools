"""Small fixed changes to a few places in the game that are not text: code words and pictures stored in modules.

What it is for: two things cannot be done by rewriting text, so the build patches the bytes directly after
everything else is in place:
  - single machine-code words (CODE_PATCHES), e.g. the Linked World card builds its birth date from kanji and the
    code must be told to print slashes instead;
  - sprite pictures kept inside .rel modules, listed in _work/boot/rel_art.json (written by the art tools).

Public names:
    CODE_PATCHES                          the list of code words changed
    patch_code_words(module, image)       apply them to one module's image
    rel_art()                             the picture patches: {file: {(section, offset): bytes}}
"""
import json
import os
import struct

from pp15 import config

REL_ART = os.path.join(config.WORK_DIR, "boot", "rel_art.json")   # sprite art inside modules: {file: {"sec:off": hex}}


def rel_art() -> dict:
    """Byte patches of art kept in .rel modules (written by _work/boot/make_ctl.py): {file: {(section, offset): bytes}}."""
    if not os.path.exists(REL_ART):
        return {}
    with open(REL_ART) as f:
        js = json.load(f)
    return {fn: {tuple(int(v) for v in k.split(":")): bytes.fromhex(h) for k, h in p.items()} for fn, p in js.items()}


# Code words patched in place: {file: {(section, offset): (original word, new word)}}.
# scc_tops.rel sec1 0x3F30..0x41AC builds the Linked World card birth date "誕生日1981年10月26日" from glyphs:
# 年 and 月 become ／ (glyph 30), 日 becomes 0xFFFF (end of text), so the card reads "Birth 1981／10／26".
# The words are PowerPC `li` instructions (load a number into a register); the number is the glyph.
CODE_PATCHES = {
    "scc_tops.rel": {
        (1, 0x4004): (0x39400B42, 0x3940001E),   # li r10, 0xB42 (年) -> li r10, 30 (／)
        (1, 0x40E0): (0x38A005A1, 0x38A0001E),   # li r5, 0x5A1 (月)  -> li r5, 30 (／)
        (1, 0x4168): (0x38C00B31, 0x38C0FFFF),   # li r6, 0xB31 (日)  -> li r6, -1 (sth stores 0xFFFF = end)
    },
}


def patch_code_words(module, image: bytes) -> tuple[bytes, dict]:
    """The module's image with CODE_PATCHES applied, and {(section, offset): the 4 bytes written}.

    Raises ValueError unless every word is still the expected original, lies in a code section, and has no
    relocation pointing into it (a relocation would overwrite the patch when the module loads).
    """
    words = CODE_PATCHES.get(module.name)
    if not words:
        return image, {}
    d, written = bytearray(image), {}
    for (sec, off), (old, new) in sorted(words.items()):
        if not module.sections[sec]["exec"]:
            raise ValueError("%s sec%d+0x%X: not a code section" % (module.name, sec, off))
        if any(s == sec and off <= p < off + 4 for s, p, *_ in module.relocs()):
            raise ValueError("%s sec%d+0x%X: a relocation points into this word" % (module.name, sec, off))
        pos = module.sections[sec]["offset"] + off
        if struct.unpack_from(">I", module.data, pos)[0] != old or struct.unpack_from(">I", d, pos)[0] != old:
            raise ValueError("%s sec%d+0x%X: not the expected original word 0x%08X" % (module.name, sec, off, old))
        struct.pack_into(">I", d, pos, new)
        written[(sec, off)] = struct.pack(">I", new)
    return bytes(d), written
