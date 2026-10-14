#!/usr/bin/env python3
"""Our English sprite lettering as pictures, for reuse in later games (the same art and colours turn up in
other Pawapuro titles).

  export_labels.py [OUT_DIR] [SPEC ...]     default ~/Projects/translation-kit/pawapuro15-wii/labels, all ui_specs

For every label of a spec: the sprites that show it, composed as the game draws them, from the original file
(ja/) and with the spec applied in memory (en/), and OUT_DIR/index.tsv: arc, bank, sprite, English, style,
font, both files. Nothing in DATA/files is read or written for the English: the spec is rendered from the
saved original, which is what `ui_labels.py apply` writes. The output is game art: keep it out of this repository.
"""
import glob
import os
import sys

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "_work", "ui_pages", "tools"))
import ui_labels as L
import ui_textures as U
from compose import sprite_image


def built(spec):
    d = open(spec["source"], "rb").read()
    banks = U.banks(d, U.elf_symbols(d))
    pages = L.render(spec, d, banks, spec.get("project"))
    o = bytearray(d)
    for (bn, pg), idx in pages.items():
        b = next(x for x in banks if x["name"] == bn)
        off, size = b["pages"][pg]
        o[off:off + size] = U.encode_indices(idx, size, U.page_bits(d, off, size))
    for off, data in L.render.patches:
        o[off:off + len(data)] = data
    o = bytes(o)
    return d, banks, o, U.banks(o, U.elf_symbols(o))


def labels_of(spec, banks):
    """(repack group, sprite id, English, style, font) for every label with text."""
    for g in spec.get("repack", ()):
        b = L.bank_of(banks, g)
        rect = lambda p: [p.page, p.x0, p.y0, p.x1, p.y1]
        for lab in g["labels"]:
            text = lab.get("text") or "".join(pc["text"] for pc in lab.get("pieces", ()))
            if not text:
                continue
            style, font = lab.get("style", g.get("style", "command")), lab.get("font", g.get("font", "command"))
            if "sprite" in lab:
                ids = [lab["sprite"]]
            else:
                ids = sorted({n.rsplit("_", 1)[1] for n, ps in b["sprites"].items() for p in ps
                              if rect(p) == lab["from"] and (not lab.get("sprites") or n.rsplit("_", 1)[1] in lab["sprites"])})
            for sid in ids:
                yield g, sid, text, style, font


def main():
    a = sys.argv[1:]
    out = a[0] if a and not a[0].endswith(".json") else os.path.expanduser("~/Projects/translation-kit/pawapuro15-wii/labels")
    specs = [x for x in a if x.endswith(".json")] or sorted(glob.glob(os.path.join(HERE, "ui_specs", "*.json")))
    rows = []
    for path in specs:
        spec = L.load_spec(path)
        arc = os.path.basename(spec["arc"])
        d, banks, o, banks2 = built(spec)
        done = set()
        for g, sid, text, style, font in labels_of(spec, banks):
            bank = g["bank"]
            key = (bank, sid)
            names = {}
            for tag, data, bs in (("ja", d, banks), ("en", o, banks2)):
                b = L.bank_of(bs, g)
                ps = next((ps for n, ps in b["sprites"].items() if n.endswith("_" + sid)), None)
                if not ps:
                    break
                try:
                    im = sprite_image(data, b, ps, bg=(0, 0, 0, 0))
                except Exception:
                    break
                rel = "%s/%s/%s_%s.png" % (tag, arc[:-4], bank, sid)
                if key not in done:
                    os.makedirs(os.path.dirname(os.path.join(out, rel)), exist_ok=True)
                    im.save(os.path.join(out, rel))
                names[tag] = rel
            if len(names) == 2:
                done.add(key)
                rows.append((arc, bank, sid, text.replace("\n", " / "), style, font, names["ja"], names["en"]))
        print("%-14s %4d labels" % (os.path.basename(path), sum(1 for r in rows if r[0] == arc)), flush=True)
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8") as f:
        f.write("arc\tbank\tsprite\tenglish\tstyle\tfont\tjapanese_png\tenglish_png\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    print("%d labels -> %s" % (len(rows), os.path.join(out, "index.tsv")))


if __name__ == "__main__":
    main()
