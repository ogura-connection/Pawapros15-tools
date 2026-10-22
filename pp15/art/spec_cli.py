"""The `pp15 art`, `pp15 apply-art` and `pp15 restore-art` commands: write a spec's English lettering into an .arc file.

A spec (specs/<name>.json, format in pp15/art/spec_render.py) describes the English lettering for <name>.arc. `apply`
draws it onto the pages of the original Japanese file and writes the result to DATA/files; the first time a file is
written, its untouched original is saved to _work/orig_arc so the lettering can always be redrawn from scratch and
`restore` can put the original back.

  pp15 art boxes PACK TEX [MIN_INDEX]   label boxes (left, top, right, bottom) of one MLB texture
  pp15 art preview SPEC.json OUT.png    before/after sheet of every changed page of a spec, nothing written
  pp15 art apply SPEC.json              write the labels into DATA/files/<arc> (original kept first)
  pp15 art restore ARC                  put the saved original .arc back
  (pp15 apply-art SPEC.json and pp15 restore-art ARC are the same as the last two)

  cmd_apply(spec_path), cmd_preview(spec_path, out), cmd_restore(arc), cmd_boxes(pack, tex, min_index), main(argv)
"""
import argparse
import os
import sys

import numpy as np
from PIL import Image

from pp15.art import labels, textures
from pp15.art.spec_io import bank_of, load_spec
from pp15.art.spec_render import render_spec

PREVIEW_ZOOM = 3                 # pages are shown this many times larger in a preview
PREVIEW_GAP = 8                  # pixels between the before and after pictures
PREVIEW_BACKGROUND = (96, 96, 96, 255)


def _read_source(spec: dict) -> tuple:
    """(file bytes, banks) of the file a spec is drawn onto (the saved original if there is one)."""
    with open(spec["source"], "rb") as f:
        d = f.read()
    return d, textures.banks(d, textures.elf_symbols(d))


def cmd_boxes(pack: str, tex: int, min_index: int = 1) -> None:
    """Print the label boxes of texture `tex` of the MLB file `pack`, numbered in reading order."""
    idx, _, _ = labels.mlb_texture(pack, tex)
    for k, b in enumerate(labels.find_boxes(idx, min_index)):
        print(k, b, "%dx%d" % (b[2] - b[0], b[3] - b[1]))


def _preview_pictures(spec: dict, d: bytes, banks: list, pages: dict) -> list:
    """Before and after pictures (RGBA, zoomed) of every page the spec changed, in pairs."""
    groups = list(spec.get("labels", ())) + list(spec.get("repack", ())) + list(spec.get("paint", ()))
    pictures = []
    for (bank, page), new in pages.items():
        grp = next((g for g in groups if g.get("bank") == bank and g.get("page", page) == page), {"bank": bank})
        b = bank_of(banks, grp) if "repack" in spec and grp in spec["repack"] else textures.bank_named(banks, bank)
        pal = textures.palette_colours(d, b["pal"])
        index = grp.get("palette")
        if index is None:                       # groups without "palette": the one most parts of the page use
            use = textures.page_palette_use(b)[page]
            index = use.most_common(1)[0][0] if use else 0
        off, size = b["pages"][page]
        colours = textures.page_colours(pal, index, textures.raw_size(d, off, size))
        old = textures.decode_indices(d, off, size)
        for arr in (old, new):
            im = Image.new("RGBA", (textures.PAGE, textures.PAGE), PREVIEW_BACKGROUND)
            im.alpha_composite(Image.fromarray(np.ascontiguousarray(colours[arr]), "RGBA"))
            pictures.append(im.resize((textures.PAGE * PREVIEW_ZOOM, textures.PAGE * PREVIEW_ZOOM), Image.NEAREST))
    return pictures


def cmd_preview(spec_path: str, out: str) -> None:
    """Save a PNG with the old and new version of every changed page of the spec, side by side. Writes no game file."""
    spec = load_spec(spec_path)
    d, banks = _read_source(spec)
    result = render_spec(spec, d, banks, spec.get("project"))
    pictures = _preview_pictures(spec, d, banks, result.pages)
    side = textures.PAGE * PREVIEW_ZOOM
    sheet = Image.new("RGB", (textures.PAGE * 2 * PREVIEW_ZOOM + PREVIEW_GAP, side * (len(pictures) // 2)), (30, 30, 30))
    for k, im in enumerate(pictures):
        sheet.paste(im.convert("RGB"), ((k % 2) * (side + PREVIEW_GAP), (k // 2) * side))
    sheet.save(out)
    print("%d labels on %d pages -> %s" % (len(spec.get("labels", ())) + len(result.repacked), len(result.pages), out))


def cmd_apply(spec_path: str) -> None:
    """Draw the spec onto its .arc and write the file into DATA/files (the original is saved first, once)."""
    spec = load_spec(spec_path)
    textures.backup_orig(spec["arc"])
    spec = load_spec(spec_path)                 # again: "source" now points at the saved original
    d, banks = _read_source(spec)
    result = render_spec(spec, d, banks, spec.get("project"))
    out = bytearray(d)
    for (bank, page), idx in result.pages.items():
        b = textures.bank_named(banks, bank)
        off, size = b["pages"][page]
        out[off:off + size] = textures.encode_indices(idx, size, textures.page_bits(d, off, size))
    for off, data in result.patches:
        out[off:off + len(data)] = data
    assert len(out) == len(d)
    with open(spec["arc"], "wb") as f:
        f.write(out)
    for row in result.repacked:
        print("  %-12s %-10s was %-6s now %-6s %s, %d sprite part(s)" % row)
    print("%s: %d labels and %d repacked labels written to %d pages, %d sprite parts moved "
          "(%d bytes changed)" % (os.path.basename(spec["arc"]), len(spec.get("labels", ())),
                                  len(result.repacked), len(result.pages), len(result.patches),
                                  sum(a != b for a, b in zip(d, out))))


def cmd_restore(arc: str) -> None:
    """Put the saved original of an .arc back into DATA/files."""
    if not textures.restore_orig(arc):
        sys.exit("no saved original for %s" % arc)
    print("restored", arc)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pp15 art", description="Put English lettering into the Pawapuro 15 menu pictures.")
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("boxes", help="label boxes of one MLB texture")
    p.add_argument("pack", help="MLB .pack name without extension, e.g. ScsComMain")
    p.add_argument("tex", type=int, help="number of the texture in the pack")
    p.add_argument("min_index", nargs="?", type=int, default=1, help="lowest palette index counted as ink (default 1)")
    p = sub.add_parser("preview", help="before/after picture of the pages a spec changes (writes no game file)")
    p.add_argument("spec", help="specs/<name>.json")
    p.add_argument("out", help="PNG file to write")
    p = sub.add_parser("apply", help="write a spec's lettering into DATA/files/<arc>; the original is kept first")
    p.add_argument("spec", help="specs/<name>.json")
    p = sub.add_parser("restore", help="put the saved original .arc back")
    p.add_argument("arc", help="file name, e.g. scs_main.arc")
    return ap


def main(argv=None) -> None:
    ap = build_parser()
    args = ap.parse_args(sys.argv[1:] if argv is None else list(argv))
    if args.command == "boxes":
        cmd_boxes(args.pack, args.tex, args.min_index)
    elif args.command == "preview":
        cmd_preview(args.spec, args.out)
    elif args.command == "apply":
        cmd_apply(args.spec)
    elif args.command == "restore":
        cmd_restore(args.arc)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
