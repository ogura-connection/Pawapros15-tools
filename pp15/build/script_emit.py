"""Write a story script out again with new text, and record where everything moved.

What it is for: the game's story scripts (the dialogue of Success Mode and of the other modes) keep their text
inline between the instructions. When the English text is longer or shorter than the Japanese, everything behind it
moves, so a script has to be written out again and every pointer into it has to follow. A *remap* is the record of
that move: a callable that turns an old offset inside the section into the new one (and refuses an offset that
points into the middle of an instruction or a line of text).

Two ways to write a script out:
  - emit_script: the section grows or shrinks and the data behind it moves (the Success Mode scripts);
  - emit_block: the script is laid out again inside the bytes it already has; the padding that sat in front of
    the labels is given up (the Eikan Nine and similar scripts, whose module cannot grow).
The third way, for the My Life script, is in ore_script.py.

Public names:
    SECTION_ALIGN          data behind a script keeps this alignment
    Remap, BlockRemap      old offset -> new offset
    emit_script(script, replacements, pad)   -> (section bytes, Remap)
    emit_block(script, replacements)         -> (region bytes, BlockRemap, bytes of room left)
"""
import struct
import sys

from pp15.script import scan

SECTION_ALIGN = 8      # data behind a script keeps its alignment (REL header align = 8)


class Remap:
    """Old section offset -> new section offset for one rebuilt script section.

    The script lies between byte offsets lo and hi; text inside it may change length. An offset in front of it stays,
    one behind it moves by `growth`, one inside maps through `newidx` ({old halfword index: new halfword index}).
    """

    def __init__(self, lo: int, hi: int, newidx: dict, growth: int):
        """lo, hi = halfword indices of the script's first instruction and the end; growth = change in bytes."""
        self.lo, self.hi, self.newidx, self.growth = lo * 2, hi * 2, newidx, growth

    def __call__(self, off: int) -> int:
        if off < self.lo:
            return off
        if off >= self.hi:
            return off + self.growth
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2


def emit_script(script, replacements: dict, pad: int = 0) -> tuple[bytes, Remap]:
    """Write one script section out again with new text.

    `script` = a scan.Script; `replacements` = {halfword index of a text instruction: list of units}.
    `pad` = extra zero bytes at the end (only used to test memory headroom). Returns (section bytes, Remap).
    """
    hw = script.hw
    lo, hi = min(script.kind), max(script.kind) + 1
    out, newidx, i = list(hw[:lo]), {}, lo
    while i < hi:
        newidx[i] = len(out)
        out.append(hw[i])
        if i in script.texts:
            _, _, j = script.texts[i]
            out += scan.pack_text(replacements[i]) if i in replacements else hw[i + 1:j]
            i = j
        else:
            i += 1
    while (len(out) - hi) * 2 % SECTION_ALIGN:
        out.append(0)
    growth = (len(out) - hi) * 2
    out += hw[hi:]
    data = struct.pack(">%dH" % len(out), *out) + b"\0" * pad
    return data, Remap(lo, hi, newidx, growth)


class BlockRemap:
    """Old section offset -> new one for a script laid out again inside its own space (a scan.BlockScript).

    Nothing behind the script moves (`growth` is 0); only offsets inside it change.
    """
    growth = 0

    def __init__(self, lo: int, hi: int, newidx: dict):
        """lo, hi = byte offsets of the region; newidx = {old halfword index: new halfword index}."""
        self.lo, self.hi, self.newidx = lo, hi, newidx

    def __call__(self, off: int) -> int:
        if not self.lo <= off < self.hi:
            return off
        if off % 2 or off // 2 not in self.newidx:
            raise ValueError("reference into the middle of a text run or instruction: 0x%X" % off)
        return self.newidx[off // 2] * 2


def emit_block(script, replacements: dict) -> tuple[bytes, BlockRemap, int]:
    """Lay a block script out again in the bytes it has.

    The zero padding in front of the labels is given up (the game does not need the alignment: the Success scripts
    run without it) and collected at the end. Returns (bytes of the region, BlockRemap, number of bytes left over);
    stops the build (sys.exit) if the English needs more than the padding gives.
    """
    hw = script.hw
    lo, hi = script.region[0] // 2, script.region[1] // 2
    out, newidx, i = [], {}, lo
    while i < hi:
        k = script.kind.get(i)
        if k is None:
            i += 1
            continue
        if k == "op":
            newidx[i] = lo + len(out)
        out.append(hw[i])
        if i in script.texts:
            _, _, j = script.texts[i]
            out += scan.pack_text(replacements[i]) if i in replacements else hw[i + 1:j]
            i = j
        else:
            i += 1
    room = hi - lo - len(out)
    if room < 0:
        sys.exit("%s: the script is %d bytes too long for its place (%d bytes); shorten some lines."
                 % (script.rel.name, -room * 2, (hi - lo) * 2))
    out += [0] * room
    return struct.pack(">%dH" % len(out), *out), BlockRemap(lo * 2, hi * 2, newidx), room * 2
