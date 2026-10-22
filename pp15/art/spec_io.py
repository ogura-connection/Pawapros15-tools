"""Read a spec file and find the sprite bank one of its groups works on.

A spec (specs/<name>.json) says which English lettering goes into <name>.arc. These two functions are the parts of
spec handling that need no drawing code, so both the renderer (pp15/art/spec_render.py) and the sheet preview
(pp15/art/sheet.py) can use them without importing each other.

  load_spec(path)         the spec with "arc" resolved to a file and "source" = the untouched original when one is saved
  bank_of(banks, group)   the bank a repack group works on
"""
import json
import os

from pp15 import config
from pp15.art import textures


def bank_of(banks: list, group: dict) -> dict:
    """The bank a repack group works on. A few files (scs_sys.arc) store the sprites of a bank behind its
    palette, so pp15.art.textures.banks files them under the next bank: "sprites" names where they ended up."""
    b = textures.bank_named(banks, group["bank"])
    if group.get("split") and not b["sprites"]:       # order.arc g3_od: the sprites follow behind the palette, under the same name
        b = dict(b, sprites=banks[banks.index(b) + 1]["sprites"])
    if "sprites" in group:
        b = dict(b, sprites=textures.bank_named(banks, group["sprites"])["sprites"])
    if "sprite_prefix" in group:                      # only the tables named opd_<prefix>_.. (a reader bank can hold several)
        pre = "opd_" + group["sprite_prefix"] + "_"
        b = dict(b, sprites={n: ps for n, ps in b["sprites"].items() if n.startswith(pre)})
    return b


def load_spec(path: str) -> dict:
    """The spec, with "arc" as a path, and "source" = the untouched original if one was saved: labels
    are always drawn onto the original pages, so applying a spec twice gives the same file."""
    with open(path) as f:
        spec = json.load(f)
    spec["arc"] = spec["arc"] if os.path.exists(spec["arc"]) else os.path.join(config.DATA_FILES, spec["arc"])
    saved = os.path.join(textures.ORIG_ARC_DIR, os.path.basename(spec["arc"]))
    spec["source"] = saved if os.path.exists(saved) else spec["arc"]
    return spec
