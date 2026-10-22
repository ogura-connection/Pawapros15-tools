#!/usr/bin/env python3
"""An index of the English lettering of MLB Power Pros (2007, 2008): every label of every UI texture cut out
as its own PNG and read with the Mac's text recognition, so later projects can find a word by name.

  pp15 mlb-labels PROJECT.BIN TEXTURES.TSV OUT_DIR [GAME]

PROJECT.BIN is the disc's project.bin, TEXTURES.TSV the list `pp15 mlb-assets textures` wrote (pack, count of
textures, ...). Writes OUT_DIR/<pack>/<tex>_<l>_<t>_<r>_<b>.png (RGBA as the game's palette has it; a
texture whose palette is filled in at run time, or whose stored palette does not read, comes out as grey
levels of its indices, the way the MLB games tint it) and OUT_DIR/index.tsv: game, pack, texture, box, text, confidence, file. Boxes in which
nothing is read are not kept. Photos, faces, backgrounds, credits and runner portraits are skipped.
Needs dolphin-test/ocr/ocr (swiftc -O ocr.swift -o ocr). The output is game art: keep it out of this repository.
"""
import json
import os
import subprocess
import sys
import tempfile

import numpy as np
from PIL import Image

from pp15 import config
from pp15.art import labels as L
from pp15.reference import mlb_assets as G

OCR = config.OCR
SKIP = ("ScsBG", "ScsFace", "env_credit", "env_game_runner", "env_arrange_logo", "ScsCard", "ScsEyeCatch",
        "PMmot", "ScsBadEnd", "ScsGameOver")


def grey(idx, fmt):
    v = (idx.astype(np.int32) * (17 if fmt == 8 else 1)).clip(0, 255).astype(np.uint8)
    return np.dstack([v, v, v, np.where(idx > 0, 255, 0).astype(np.uint8)])


def rgba(idx, pal, fmt):
    if pal[:, 3].max() == 0:                         # palette set at run time: grey levels of the indices
        return grey(idx, fmt)
    return np.asarray(pal, np.uint8)[idx]


def main(argv=None):
    a = sys.argv[1:] if argv is None else list(argv)
    if len(a) < 3:
        sys.exit(__doc__)
    project, listing, out = a[:3]
    game = a[3] if len(a) > 3 else os.path.basename(os.path.dirname(os.path.dirname(project)))
    os.makedirs(out, exist_ok=True)
    rows, jobs = [], []
    tmp = tempfile.mkdtemp()
    for line in open(listing, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if len(p) < 2 or not p[1].isdigit() or int(p[1]) == 0 or p[0].startswith(SKIP):
            continue
        pack = p[0][:-5] if p[0].endswith(".pack") else p[0]
        for t in range(int(p[1])):
            try:
                idx, pal, fmt = L.mlb_texture(pack, t, project)
            except Exception:
                continue
            img, gimg = rgba(idx, pal, fmt), grey(idx, fmt)
            ok = lambda bx: 6 <= bx[3] - bx[1] <= 96 and 6 <= bx[2] - bx[0] <= 512
            # the ink threshold that gives the most label-sized boxes (a run-time palette leaves the
            # background on a low index that is not 0, and the glow can join two rows)
            best = max(((thr, [bx for bx in L.find_boxes(idx, thr) if ok(bx)])
                        for thr in ((1, 4, 8) if fmt == 8 else (1, 32, 64, 128))), key=lambda x: len(x[1]))
            for l, tp, r, b in best[1]:
                w, h = r - l, b - tp
                if (idx[tp:b, l:r] >= best[0]).sum() < 30:
                    continue
                name = "%s/%d_%d_%d_%d_%d.png" % (pack, t, l, tp, r, b)
                for kind, src in (("", img), ("~grey", gimg)):     # some stored palettes are junk (tinted
                    crop = Image.fromarray(np.ascontiguousarray(src[tp:b, l:r]), "RGBA")   # at run time):
                    show = Image.new("RGBA", crop.size, (40, 40, 60, 255))           # read both, keep the
                    show.alpha_composite(crop)                                       # one that reads
                    q = os.path.join(tmp, "%d%s.png" % (len(jobs), kind))
                    show.convert("RGB").resize((w * 3, h * 3), Image.LANCZOS).save(q)
                    jobs.append((q, crop, name, pack, t, (l, tp, r, b)))
    print("%d boxes to read" % len(jobs), flush=True)
    for a in range(0, len(jobs), 200):
        batch = jobs[a:a + 200]          # 200 is even: the two readings of a box stay in one batch
        r = subprocess.run([OCR], input="\n".join(j[0] for j in batch) + "\n", capture_output=True, text=True)
        read = {}
        for line in r.stdout.splitlines():
            d = json.loads(line)
            read[d["p"]] = d["l"]
        best = {}
        for q, crop, name, pack, t, box in batch:
            ls = read.get(q, [])
            text = " ".join(x["t"] for x in sorted(ls, key=lambda x: (round(x["y"], 1), x["x"]))).strip()
            conf = min((x.get("c", 0) for x in ls), default=0)
            if text and (name not in best or conf > best[name][1]):
                best[name] = (text, conf, crop, pack, t, box)
            os.remove(q)
        for name, (text, conf, crop, pack, t, box) in best.items():
            if True:
                os.makedirs(os.path.join(out, pack), exist_ok=True)
                crop.save(os.path.join(out, name))
                rows.append((game, pack, t, "%d,%d,%d,%d" % box, text.replace("\t", " "), "%.2f" % conf, name))
        print("  %d / %d read, %d kept" % (min(a + 200, len(jobs)), len(jobs), len(rows)), flush=True)
    with open(os.path.join(out, "index.tsv"), "w", encoding="utf-8") as f:
        f.write("game\tpack\ttexture\tbox\ttext\tconfidence\tfile\n")
        for row in rows:
            f.write("\t".join(map(str, row)) + "\n")
    print("kept %d labels -> %s" % (len(rows), os.path.join(out, "index.tsv")))


if __name__ == "__main__":
    main()
