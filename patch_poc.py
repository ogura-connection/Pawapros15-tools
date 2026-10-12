#!/usr/bin/env python3
"""Proof of concept: replace one Success Mode line with same-length English, in place.

  patch_poc.py apply | restore
Backup of the original file goes to _work/ (git-ignored). Nothing moves, so no relocations change.
"""
import os, shutil, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_story as S
import pawapuro15_text_tools as T

FILE = os.path.join(S.DATA_FILES, "scs_sce1.rel")
BACKUP = os.path.join(S.WORK_DIR, "scs_sce1.rel.orig")
OFFSET = 0x6434          # file offset of the text instruction (XX00) of the first Success line
EXPECT = "今日はオレにとって"
NEW = "FIRST DAY"           # must be exactly len(EXPECT) glyphs


def fullwidth(s):
    return "".join(chr(ord(c) - 0x20 + 0xFF00) if 0x21 <= ord(c) <= 0x7E else ("　" if c == " " else c) for c in s)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "restore":
        shutil.copy(BACKUP, FILE)
        return print("restored")
    if cmd != "apply":
        return print(__doc__)
    if not os.path.exists(BACKUP):
        os.makedirs(S.WORK_DIR, exist_ok=True)
        shutil.copy(FILE, BACKUP)
    data = bytearray(open(BACKUP, "rb").read())
    hw = [(data[i] << 8) | data[i + 1] for i in range(OFFSET + 2, len(data) - 1, 2)]
    units, nxt = S.unpack_text(hw, 0)
    assert S.decode_units(units) == EXPECT, S.decode_units(units)
    new = [0 if c == "　" else T.char_to_glyph(c) for c in fullwidth(NEW)]
    assert None not in new and len(new) == len(units), (new, len(units))
    out = S.pack_text(new)
    assert len(out) == nxt, (len(out), nxt)
    for k, h in enumerate(out):
        data[OFFSET + 2 + 2 * k:OFFSET + 4 + 2 * k] = h.to_bytes(2, "big")
    open(FILE, "wb").write(data)
    print("patched", EXPECT, "->", NEW, [hex(u) for u in new])


main()
