"""An index of the English lettering of MLB Power Pros (2007, 2008): every label of every UI picture cut out as its own PNG
and read with the Mac's text recognition, so later projects can find a word by name.

    pp15 mlb-labels PROJECT.BIN TEXTURES.TSV OUT_DIR [GAME]

What it does: for each picture ("texture", see pp15/reference/mlb_assets.py) of the UI packs it finds the boxes of ink
that look like one label, crops them, enlarges them and lets the helper program read them. PROJECT.BIN is the disc's
project.bin; TEXTURES.TSV the list `pp15 mlb-assets textures` wrote (pack, count of textures, ...).

Output: OUT_DIR/<pack>/<texture>_<left>_<top>_<right>_<bottom>.png (RGBA as the game's palette has it) and
OUT_DIR/index.tsv with the columns game, pack, texture, box, text, confidence, file. A texture whose palette is filled
in at run time, or whose stored palette does not read, comes out as grey levels of its indices (the way the MLB games
tint it); both readings of a box are tried and the one that reads better is kept. Boxes in which nothing is read are
not kept. Photos, faces, backgrounds, credits and runner portraits are skipped (SKIP).

Needs the text-recognition helper dolphin-test/ocr/ocr (build it with `swiftc -O ocr.swift -o ocr`; macOS only).
The output is game art: keep it out of this repository.

Public functions: grey, rgba, find_label_boxes, read_labels, main.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import List, Optional, Tuple

import numpy as np
from PIL import Image

from pp15 import config
from pp15.art import labels

OCR = config.OCR
SKIP = ("ScsBG", "ScsFace", "env_credit", "env_game_runner", "env_arrange_logo", "ScsCard", "ScsEyeCatch",
        "PMmot", "ScsBadEnd", "ScsGameOver")        # pictures with no lettering worth indexing
GX_C4 = 8                                           # GX format number of 4-bit palette pictures; others (C8) have 8 bits
LABEL_HEIGHT_RANGE = (6, 96)                        # pixels: a label box is not smaller or taller than this ...
LABEL_WIDTH_RANGE = (6, 512)                        # ... or wider
MIN_INK_PIXELS = 30                                 # a box with fewer ink pixels is noise
ENLARGE = 3                                         # the helper reads crops enlarged this many times
READ_BATCH = 200                                    # crops sent to the helper at once (even: both readings of a box stay together)
INK_THRESHOLDS_C4 = (1, 4, 8)                       # palette indices from which a pixel counts as ink, tried in turn
INK_THRESHOLDS_C8 = (1, 32, 64, 128)
CROP_BACKGROUND = (40, 40, 60, 255)                 # colour put behind a transparent crop before it is read


def grey(indices: np.ndarray, fmt: int) -> np.ndarray:
    """RGBA image from palette indices read as grey levels (index 0 transparent). C4 indices (0-15) are stretched by 17."""
    v = (indices.astype(np.int32) * (17 if fmt == GX_C4 else 1)).clip(0, 255).astype(np.uint8)
    return np.dstack([v, v, v, np.where(indices > 0, 255, 0).astype(np.uint8)])


def rgba(indices: np.ndarray, palette: np.ndarray, fmt: int) -> np.ndarray:
    """RGBA image from palette indices; a palette that is fully transparent (set at run time) gives grey levels."""
    if palette[:, 3].max() == 0:
        return grey(indices, fmt)
    return np.asarray(palette, np.uint8)[indices]


def find_label_boxes(indices: np.ndarray, fmt: int) -> Tuple[int, list]:
    """The ink threshold that gives the most label-sized boxes, and those boxes (left, top, right, bottom).

    A palette set at run time leaves the background on a low index that is not 0, and the glow can join two rows, so
    several thresholds are tried."""
    def label_sized(box) -> bool:
        return (LABEL_HEIGHT_RANGE[0] <= box[3] - box[1] <= LABEL_HEIGHT_RANGE[1]
                and LABEL_WIDTH_RANGE[0] <= box[2] - box[0] <= LABEL_WIDTH_RANGE[1])
    thresholds = INK_THRESHOLDS_C4 if fmt == GX_C4 else INK_THRESHOLDS_C8
    return max(((threshold, [box for box in labels.find_boxes(indices, threshold) if label_sized(box)])
                for threshold in thresholds), key=lambda candidate: len(candidate[1]))


def collect_jobs(project: str, listing: str, tmp: str) -> list:
    """Cut out every label box of the listed packs and save its enlarged picture(s) in the folder `tmp`.

    Returns jobs (picture path, RGBA crop, file name, pack, texture number, box). Each box has two jobs: the picture
    colours and the grey-level reading (file path ends in ~grey), because some stored palettes are junk."""
    jobs = []
    for line in open(listing, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) == 0 or parts[0].startswith(SKIP):
            continue
        pack = parts[0][:-5] if parts[0].endswith(".pack") else parts[0]
        for texture in range(int(parts[1])):
            try:
                indices, palette, fmt = labels.mlb_texture(pack, texture, project)
            except Exception:
                continue
            colour, grey_levels = rgba(indices, palette, fmt), grey(indices, fmt)
            threshold, boxes = find_label_boxes(indices, fmt)
            for left, top, right, bottom in boxes:
                width, height = right - left, bottom - top
                if (indices[top:bottom, left:right] >= threshold).sum() < MIN_INK_PIXELS:
                    continue
                name = "%s/%d_%d_%d_%d_%d.png" % (pack, texture, left, top, right, bottom)
                for suffix, source in (("", colour), ("~grey", grey_levels)):
                    crop = Image.fromarray(np.ascontiguousarray(source[top:bottom, left:right]), "RGBA")
                    shown = Image.new("RGBA", crop.size, CROP_BACKGROUND)
                    shown.alpha_composite(crop)
                    path = os.path.join(tmp, "%d%s.png" % (len(jobs), suffix))
                    shown.convert("RGB").resize((width * ENLARGE, height * ENLARGE), Image.LANCZOS).save(path)
                    jobs.append((path, crop, name, pack, texture, (left, top, right, bottom)))
    return jobs


def read_labels(jobs: list, out: str, game: str) -> list:
    """Read the jobs with the text-recognition helper, keep for each box the reading with the best confidence, save
    the crops under `out` and return the index rows (game, pack, texture, box, text, confidence, file)."""
    rows = []
    for first in range(0, len(jobs), READ_BATCH):
        batch = jobs[first:first + READ_BATCH]
        result = subprocess.run([OCR], input="\n".join(job[0] for job in batch) + "\n", capture_output=True, text=True)
        read = {}
        for line in result.stdout.splitlines():
            record = json.loads(line)
            read[record["p"]] = record["l"]
        best = {}
        for path, crop, name, pack, texture, box in batch:
            lines = read.get(path, [])
            text = " ".join(x["t"] for x in sorted(lines, key=lambda x: (round(x["y"], 1), x["x"]))).strip()
            confidence = min((x.get("c", 0) for x in lines), default=0)
            if text and (name not in best or confidence > best[name][1]):
                best[name] = (text, confidence, crop, pack, texture, box)
            os.remove(path)
        for name, (text, confidence, crop, pack, texture, box) in best.items():
            os.makedirs(os.path.join(out, pack), exist_ok=True)
            crop.save(os.path.join(out, name))
            rows.append((game, pack, texture, "%d,%d,%d,%d" % box, text.replace("\t", " "), "%.2f" % confidence, name))
        print("  %d / %d read, %d kept" % (min(first + READ_BATCH, len(jobs)), len(jobs), len(rows)), flush=True)
    return rows


def main(argv: Optional[List[str]] = None) -> None:
    """Run `pp15 mlb-labels PROJECT.BIN TEXTURES.TSV OUT_DIR [GAME]`. `argv` defaults to sys.argv[1:]."""
    parser = argparse.ArgumentParser(prog="pp15 mlb-labels", description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("project", metavar="PROJECT.BIN", help="the disc's project.bin")
    parser.add_argument("listing", metavar="TEXTURES.TSV", help="the list written by `pp15 mlb-assets textures`")
    parser.add_argument("out", metavar="OUT_DIR", help="where the label pictures and index.tsv go")
    parser.add_argument("game", nargs="?", help="name of the game in index.tsv (default: the folder two levels above PROJECT.BIN)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    game = args.game or os.path.basename(os.path.dirname(os.path.dirname(args.project)))
    os.makedirs(args.out, exist_ok=True)
    tmp = tempfile.mkdtemp()
    jobs = collect_jobs(args.project, args.listing, tmp)
    print("%d boxes to read" % len(jobs), flush=True)
    rows = read_labels(jobs, args.out, game)
    index_path = os.path.join(args.out, "index.tsv")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("game\tpack\ttexture\tbox\ttext\tconfidence\tfile\n")
        for row in rows:
            f.write("\t".join(map(str, row)) + "\n")
    print("kept %d labels -> %s" % (len(rows), index_path))


if __name__ == "__main__":
    main()
