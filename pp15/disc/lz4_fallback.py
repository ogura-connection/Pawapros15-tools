"""A slow pure-Python LZ4 block decompressor, used when the `lz4` package is not installed.

Why: Dolphin (the Wii emulator) compresses its save states with LZ4, and `pp15 ram-scan` has to unpack one. The `lz4`
package does it in a blink (`pip install lz4`); this module does the same in plain Python, in a few seconds per
state, so the tool works without any install.

LZ4 block format in two sentences: the data is a series of sequences; each starts with a token byte whose high four
bits are the length of a run of literal bytes (15 means more length bytes follow, each adding up until one is not 255),
then the literals, then a 2-byte little-endian distance back into the output and the match length (low four bits of
the token, plus 4, extended the same way) to copy from there. The last sequence has literals only.

Public function: decompress_block.
"""

from typing import Tuple


def _read_length(src: bytes, i: int, length: int) -> Tuple[int, int]:
    """Extend a 4-bit length of 15 with the following bytes (255 means "another byte follows").
    Returns (length, index of the next unread byte)."""
    while True:
        extra = src[i]
        i += 1
        length += extra
        if extra != 255:
            return length, i


def decompress_block(src: bytes) -> bytes:
    """Decompress one LZ4 block (no frame header, no size prefix). Raises IndexError on truncated data."""
    out, i, n = bytearray(), 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        literal_length = token >> 4
        if literal_length == 15:
            literal_length, i = _read_length(src, i, literal_length)
        out += src[i:i + literal_length]
        i += literal_length
        if i >= n:                       # the last sequence ends after its literals
            break
        distance = src[i] | src[i + 1] << 8
        i += 2
        match_length = token & 15
        if match_length == 15:
            match_length, i = _read_length(src, i, match_length)
        match_length += 4                # the minimum match length of LZ4
        start = len(out) - distance
        if distance >= match_length:
            out += out[start:start + match_length]
        else:                            # the match overlaps the bytes being written: repeat the distance-long pattern
            pattern = bytes(out[start:])
            out += (pattern * (match_length // distance + 1))[:match_length]
    return bytes(out)
