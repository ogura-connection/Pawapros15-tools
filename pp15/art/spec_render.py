"""Draw every label of a spec (specs/*.json) onto the picture pages of one .arc file, without writing any file.

A spec says which English lettering goes into one .arc (a picture file, see pp15/art/textures.py). It is a JSON object:
  {"arc": "scs_main.arc",
   "project": "~/MLB2008/DATA/files/project.bin",    (optional: where the MLB label art is read from)
   "repack": [...], "paint": [...], "sheet": [...], "strips": [...], "sprite_parts": [...], "labels": [...]}
Each list is optional. They are applied in this order, so a later kind sees the pages an earlier one redrew:

  "repack"  groups of words laid out again on a page, with their sprites re-pointed (pp15/art/repack.py):
            {"bank": "y5_smi_0", "palette": 28, "style": "command", "areas": [[page, x0, y0, x1, y1], ...],
             "labels": [{"from": [page, x0, y0, x1, y1], "text": "Practice"}, {"from": [...]}]}
            A label without "text" keeps its Japanese art; one without "pack" only clears its rectangle.
  "paint"   lettering that is part of a plate, redrawn in place: {"bank", "page", "rect", "text", "font", "ramp"} with
            "ramp" = the palette index for ink level 0 (the plate) to 6. With "copy": [page, x0, y0, x1, y1] (the same plate
            with nothing on it, from the original file) and "style" (a style of pp15/art/typeset.py) the plate is copied
            into the rectangle and the styled word is centred on it ("dx", "dy" move it); a "copy" narrower than the
            rectangle is repeated across it, and "copy": "clear" empties the rectangle.
  "sheet"   lettering painted into a picture cut over several pages (pp15/art/sheet.py).
  "strips"  names in a text atlas that sprites of another file cut out (pp15/art/strips.py).
  "sprite_parts"  new part lists for sprite tables.
  "labels"  lettering cut from an MLB sheet and fitted into the rectangle of the Japanese label:
            {"bank", "page", "palette", "rect": [x0, y0, x1, y1], "pack": "ScsComMain", "tex": 0, "box": [l, t, r, b],
             "style": "comcmd", "roles": {...}, "max_stretch": 1.6, "halo": [4, 5], "lines": 2, "name": "Practice"}
            `rect` is a sprite rectangle of the page (see `pp15 textures parts`); it is cleared, and the label is centred
            in the part of it the Japanese label covered (its bounding box; "area": "rect" uses the whole rectangle),
            minus "margin" pixels. The source colours are sorted into roles (outer / ring / fill for the stat labels;
            edge_dark / edge_light / plate / letter for the command labels) and each role gets one palette index of the
            target page ("roles"). "drop" lists roles left out (the outer edge of a label already sits on a plate of that
            colour), "halo" draws that colour back as a one-pixel edge afterwards, "full" = overrides for the unscaled art,
            used when the label fits as drawn in MLB, "band": ["letter", "plate"] turns letter pixels on the outer edge
            into plate (a solid band round the letters), "lines": 2 stacks the two words of a label when it is too long
            for one line. Nothing is drawn that is not in the MLB sheets: a label with no MLB counterpart is not in a spec.

  render_spec(spec, d, banks, project)   everything the spec changes: pages, sprite-part patches, report -> RenderResult
  render(spec, d, banks, project)        the same, returning only the pages, and leaving patches / repacked / report as
                                         attributes of the function (pp15/kit/export_labels.py reads render.patches)

Nothing here writes to disk: pp15/art/spec_cli.py writes the result into DATA/files. load_spec and bank_of are in
pp15/art/spec_io.py.
"""
from dataclasses import dataclass, field

import numpy as np

from pp15.art import labels, repack, sheet, strips, textures
from pp15.art.spec_io import bank_of
from pp15.art.typeset import RENDER, typeset


@dataclass
class RenderResult:
    """The outcome of rendering a spec.

    pages      {(bank name, page number): (128, 128) index array} of every page that changed
    patches    [(file offset, bytes)] for sprite parts and tables that moved
    repacked   report rows (bank, label, was, now, where, number of parts) of the repack and paint entries
    scales     [(label name, fitted size, source size)] of the "labels" entries
    full_used  [(label name, whether the unscaled "full" variant was used)]
    """
    pages: dict = field(default_factory=dict)
    patches: list = field(default_factory=list)
    repacked: list = field(default_factory=list)
    scales: list = field(default_factory=list)
    full_used: list = field(default_factory=list)


def _page(pages: dict, d: bytes, bank: dict, bank_name: str, number: int) -> np.ndarray:
    """The editable index array of one page, decoded from the file the first time it is needed."""
    key = (bank_name, number)
    if key not in pages:
        pages[key] = textures.decode_indices(d, *bank["pages"][number]).copy()
    return pages[key]


def _render_repack_groups(spec: dict, d: bytes, banks: list, result: RenderResult, project) -> None:
    for group in spec.get("repack", ()):
        bank = bank_of(banks, group)
        local = {p: a for (name, p), a in result.pages.items() if name == group["bank"]}
        rows = repack.repack(group, d, bank, local, result.patches, project)
        for p, a in local.items():
            result.pages[(group["bank"], p)] = a
        result.repacked += [(group["bank"],) + r for r in rows]


def _paint_entry(lab: dict, d: bytes, banks: list, result: RenderResult, project) -> None:
    """A "paint" entry: lettering that is part of a plate is redrawn in place, in `lab["font"]`, either in the ramp of
    `lab["ramp"]` or (with "copy") in a style on a copy of the empty plate."""
    bank = textures.bank_named(banks, lab["bank"])
    page = _page(result.pages, d, bank, lab["bank"], lab["page"])
    x0, y0, x1, y1 = lab["rect"]
    ink, base = typeset(lab["text"], lab["font"], project)
    if "copy" in lab:                           # a plate with nothing on it, from the original file
        if lab["copy"] == "clear":              # lettering with nothing behind it: cleared
            src = np.zeros((y1 - y0, x1 - x0), np.uint8)
        else:
            cp, cx0, cy0, cx1, cy1 = lab["copy"]
            src = textures.decode_indices(d, *bank["pages"][cp])[cy0:cy1, cx0:cx1]
        if src.shape[1] != x1 - x0:             # a narrower strip of plain plate is repeated across
            src = src[:, np.arange(x1 - x0) % src.shape[1]]
        page[y0:y1, x0:x1] = src
        art, _ = RENDER[lab["style"]](ink, base)
        h, w = art.shape
        ox, oy = x0 + (x1 - x0 - w) // 2 + lab.get("dx", 0), y0 + (y1 - y0 - h) // 2 + lab.get("dy", 0)
        area = page[oy:oy + h, ox:ox + w]
        area[art > 0] = art[art > 0]
    else:
        h, w = ink.shape
        ox, oy = x0 + (x1 - x0 - w) // 2, y0 + (y1 - y0 - base) // 2
        page[y0:y1, x0:x1] = lab["ramp"][0]
        area = page[oy:oy + h, ox:ox + w]
        area[ink > 0] = np.array(lab["ramp"], np.uint8)[ink[ink > 0]]
    result.repacked.append((lab["bank"], lab["text"], "painted", "%dx%d" % (w, h),
                            "page %d x %d y %d" % (lab["page"], ox, oy), 0))


def _label_area(lab: dict, page: np.ndarray) -> tuple:
    """The box a MLB-sheet label may use: the area the Japanese label covered (its neighbours overlap the rest), or
    the whole rectangle with "area": "rect"."""
    x0, y0, x1, y1 = lab["rect"]
    ys, xs = np.nonzero(page[y0:y1, x0:x1])
    if len(xs) and lab.get("area", "label") == "label":
        return x0 + xs.min(), y0 + ys.min(), x0 + xs.max() + 1, y0 + ys.max() + 1
    return lab["rect"]


def _choose_variant(lab: dict, area: tuple, project) -> dict:
    """The settings to draw a label with: its "full" overrides (the art as drawn in MLB) if that fits the area without any
    scaling, else a copy of the label as given (so `variant is not lab` is always true in render_spec's report; see
    docs/refactor_notes_art.md)."""
    if "full" in lab:
        full = dict(lab, **lab["full"])
        fm, _ = labels.source_classes(full, project)
        m = full.get("margin", 0)
        if fm.shape[1] <= area[2] - area[0] - 2 * m and fm.shape[0] <= area[3] - area[1] - 2 * m \
                and full.get("lines", 1) == 1:
            return full
    return dict(lab)


def _label_entry(lab: dict, d: bytes, banks: list, result: RenderResult, project) -> None:
    """A "labels" entry: MLB lettering fitted into the rectangle of the Japanese label (see labels.fit)."""
    bank = textures.bank_named(banks, lab["bank"])
    page = _page(result.pages, d, bank, lab["bank"], lab["page"])
    x0, y0, x1, y1 = lab["rect"]
    if "pack" not in lab:                       # a rectangle that is only cleared
        page[y0:y1, x0:x1] = 0
        return
    area = _label_area(lab, page)
    page[y0:y1, x0:x1] = 0
    variant = _choose_variant(lab, area, project)
    m = variant.get("margin", 0)
    ax0, ay0, ax1, ay1 = area[0] + m, area[1] + m, area[2] - m, area[3] - m
    mask, cls = labels.source_classes(variant, project)
    halo = variant.get("halo", ())
    pad = len(halo)                              # room for the rings
    result.full_used.append((lab["name"], variant is not lab))
    words = labels.split_words(mask, cls, variant["lines"]) if variant.get("lines", 1) > 1 else [(mask, cls)]
    band = (ay1 - ay0) // len(words)
    for k, (wm, wc) in enumerate(words):
        box = (ax0, ay0 + k * band, ax1, ay0 + (k + 1) * band)
        label = labels.fit(wm, wc, variant["roles"], box[2] - box[0] - 2 * pad, box[3] - box[1] - 2 * pad,
                           variant.get("max_stretch", 1.0), variant.get("max_scale", 1.0),
                           variant.get("method", "carve"), variant.get("band"))
        result.scales.append((lab["name"], label.shape, wm.shape))
        labels.draw(page, lab["rect"], box, label)
    labels.add_halo(page, lab["rect"], halo)


def render_spec(spec: dict, d: bytes, banks: list, project=None) -> RenderResult:
    """Everything the spec changes in the file bytes `d`: edited pages, sprite-part patches and report rows.
    The entries are applied in the order repack, paint, sheet, strips, sprite_parts, labels, so a later kind sees the
    pages an earlier one redrew."""
    result = RenderResult()
    _render_repack_groups(spec, d, banks, result, project)
    for lab in spec.get("paint", ()):               # lettering that is part of a plate: redrawn in place
        _paint_entry(lab, d, banks, result, project)
    for entry in spec.get("sheet", ()):             # lettering painted across the pages of one picture
        sheet.paint(entry, d, banks, result.patches, project, pages=result.pages)
    for entry in spec.get("strips", ()):            # names in a text atlas whose sprite tables are in another file
        strips.paint_strips(entry, d, banks, result.pages, project)
    if spec.get("sprite_parts"):                    # new parts for sprite tables (names moved in a text atlas)
        result.patches += strips.write_sprite_parts(spec["sprite_parts"], d)
    for lab in spec.get("labels", ()):
        _label_entry(lab, d, banks, result, project)
    return result


def render(spec: dict, d: bytes, banks: list, project=None) -> dict:
    """The index page with every label of the spec drawn, per (bank, page): {(bank, page): array}.
    Also sets render.patches = [(file offset, bytes)] for the sprite parts moved by "repack" groups, render.repacked
    (report rows) and render.report = {"scales", "full"}. New code should call render_spec, which returns all of it."""
    result = render_spec(spec, d, banks, project)
    render.patches, render.repacked = result.patches, result.repacked
    render.report = {"scales": result.scales, "full": result.full_used}
    return result.pages
