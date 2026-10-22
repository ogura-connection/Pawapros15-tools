"""Lay out English labels on a sprite page again, because an English word is wider than the Japanese label it replaces.

A game picture is a 128x128 page of palette indices; the screen shows it through "sprites", each a few rectangles
("parts") cut out of the page and put at a screen position (see pp15/art/textures.py). Japanese labels are two or three
big characters, so their rectangles are small. To fit English, each label of a "repack" group in a spec
(specs/*.json, read by pp15/art/spec_render.py) is typeset (pp15/art/typeset.py), the old rectangles are cleared, the new
words are packed into the free areas of the page that the spec names, and the sprite parts are rewritten to show them.
Nothing moves inside the file and no size changes: page pixels and 10-byte sprite parts are replaced in place.

  repack(group, d, bank, pages, patches, project)   lay out one group; returns report rows
  shelf_pack(sizes, areas, gap)                     place boxes into areas, tallest first
  ribbon_pack(widths, height, areas, gap, empty)    pour long lines of art into rows, cutting them where a row ends
  repack_ribbon / repack_chain                      the two special group kinds ("ribbon": true, "chain": true)

The spec keys each kind of group understands are described in docs/TECHNIQUES.md and in the docstrings below.
"""
import numpy as np

from pp15.art import textures
from pp15.art.lettering_fonts import art_ink
from pp15.art.typeset import RENDER, typeset

EMPTY_CELL = 4          # side of the blank square that sprite parts point at when they must show nothing
LEAVE_CLEAR_ROWS = 4    # default rows of Japanese art left below the foot of the new letters ("under")
OVERLAP_ROWS = 8        # default overlap of stacked lines of big lettering ("overlap")


# ── Packing ──────────────────────────────────────────────────────────────────────────────

def art_box(page: np.ndarray, rect: tuple) -> tuple:
    """Bounding box (x0, y0, x1, y1) of the pixels inside a rectangle, in page coordinates."""
    x0, y0, x1, y1 = rect
    ys, xs = np.nonzero(page[y0:y1, x0:x1])
    return x0 + xs.min(), y0 + ys.min(), x0 + xs.max() + 1, y0 + ys.max() + 1


def shelf_pack(sizes: list, areas: list, gap: tuple = (1, 1)) -> dict:
    """Place (w, h) boxes into areas [(page, x0, y0, x1, y1)]: {index: (page, x, y)}. Tallest boxes
    first; a box goes on the lowest open shelf that is high enough and has room, or opens a new
    shelf of its own height. `gap` = clear pixels left between boxes (across, down), so a neighbour
    never bleeds in when the game filters the texture. Raises ValueError when a box fits nowhere."""
    free = [[page, x0, y0, x1, y1] for page, x0, y0, x1, y1 in areas]     # unshelved part of each area
    shelves = []                                                          # [page, x, y, x1, height]
    placed = {}
    for i in sorted(range(len(sizes)), key=lambda i: (-sizes[i][1], -sizes[i][0])):
        w, h = sizes[i]
        fits = [s for s in shelves if s[4] >= h and s[3] - s[1] >= w]
        if fits:
            shelf = min(fits, key=lambda s: (s[4], s[3] - s[1]))
        else:
            room = [a for a in free if a[4] - a[2] >= h and a[3] - a[1] >= w]
            if not room:
                raise ValueError("no room for a label %dx%d" % (w, h))
            area = min(room, key=lambda a: a[3] - a[1])
            shelf = [area[0], area[1], area[2], area[3], h]
            shelves.append(shelf)
            area[2] += h + gap[1]
        placed[i] = (shelf[0], shelf[1], shelf[2])
        shelf[1] += w + gap[0]
    return placed


def ribbon_pack(widths: list, height: int, areas: list, gap: int = 1, empty: int = EMPTY_CELL) -> tuple:
    """Pour lines of art (all `height` rows high) into the rows of the areas, cutting a line where a row
    ends. Returns ({line: [(page, x, y, c0, c1)]}, (page, x, y) of an empty empty x empty cell). Widest
    first, with as few cuts as possible: a line wider than a row takes whole empty rows and its rest goes
    where it fills a row best; a line that fits no row whole is cut over the rows with the most room."""
    rows = []                                                     # [page, x, y, x1, x0]
    for pg, x0, y0, x1, y1 in areas:
        y = y0
        while y + height <= y1:
            rows.append([pg, x0, y, x1, x0])
            y += height + gap
    out = {}

    def put(i, r, c, take):
        out[i].append((r[0], r[1], r[2], c, c + take))
        r[1] += take + gap
    for i in sorted(range(len(widths)), key=lambda i: -widths[i]):
        c, w = 0, widths[i]
        out[i] = []
        while c < w:
            fits = [r for r in rows if r[3] - r[1] >= w - c]
            if fits:                                              # the rest fits a row whole
                put(i, min(fits, key=lambda r: r[3] - r[1]), c, w - c)
                break
            empty_rows = [r for r in rows if r[1] == r[4]]
            r = empty_rows[0] if empty_rows else max(rows, key=lambda r: r[3] - r[1])
            take = min(w - c, r[3] - r[1])
            if take < min(12, w - c):
                raise ValueError("no room for %d more columns of a line" % (w - c))
            put(i, r, c, take)
            c += take
    for pg, x0, y0, x1, y1 in areas:                              # an empty cell: below the rows, or a row's end
        n = (y1 - y0 + gap) // (height + gap)
        if y1 - (y0 + n * (height + gap)) >= empty and x1 - x0 >= empty:
            return out, (pg, x0, y1 - empty)
    r = max(rows, key=lambda r: r[3] - r[1])
    if r[3] - r[1] < empty:
        raise ValueError("no room for the empty cell")
    return out, (r[0], r[1], r[2])


# ── Shared steps of every group kind ─────────────────────────────────────────────────────

class _Job:
    """What one repack group works on: the spec group, the game file bytes, the bank and the pages being edited."""

    def __init__(self, group, d, bank, pages, patches, project):
        self.group, self.d, self.bank = group, d, bank
        self.pages, self.patches, self.project = pages, patches, project
        self.areas = [tuple(a) for a in group["areas"]]
        self.parts = [p for ps in bank["sprites"].values() for p in ps]

    def option(self, lab: dict, key: str, default=None):
        """A label's own setting, else its group's, else `default`."""
        return lab.get(key, self.group.get(key, default))

    def page(self, n: int) -> np.ndarray:
        """The editable index array of page n, decoded from the file on first use."""
        if n not in self.pages:
            self.pages[n] = textures.decode_indices(self.d, *self.bank["pages"][n]).copy()
        return self.pages[n]

    def sprite(self, name: str) -> list:
        """The parts of the sprite whose symbol ends in _<name> (opd_<set>_<name>)."""
        return next(ps for sym, ps in self.bank["sprites"].items() if sym.endswith("_" + name))

    def screen_box(self, parts: list):
        """(x0, y0, x1, y1) on the screen of the inked pixels of these sprite parts, or None if they show nothing."""
        box = None
        for p in parts:
            ys, xs = np.nonzero(self.page(p.page)[p.y0:p.y1, p.x0:p.x1])
            if len(xs):
                b = (p.x + xs.min(), p.y + ys.min(), p.x + xs.max() + 1, p.y + ys.max() + 1)
                box = b if box is None else (min(box[0], b[0]), min(box[1], b[1]), max(box[2], b[2]), max(box[3], b[3]))
        return box

    def check_clear_is_unshared(self, owned: set, clear: list, blanks=()) -> None:
        """Raise unless nothing outside the group draws from the rectangles that are about to be cleared."""
        for p in self.parts:
            key = (p.page, p.x0, p.y0, p.x1, p.y1)
            if key not in owned and key not in blanks and any(_overlaps(key, r) for r in clear):
                raise ValueError("sprite %s uses x %d-%d y %d-%d of page %d, which this group clears"
                                 % (p.sprite, p.x0, p.x1, p.y0, p.y1, p.page))

    def clear_rectangles(self, rects: list) -> None:
        for pg, x0, y0, x1, y1 in rects:
            self.page(pg)[y0:y1, x0:x1] = 0


def _overlaps(key: tuple, r: tuple) -> bool:
    """True if the part rectangle key = (page, x0, y0, x1, y1) overlaps r = (page, x0, y0, x1, y1)."""
    return key[0] == r[0] and key[1] < r[3] and r[1] < key[3] and key[2] < r[4] and r[2] < key[4]


def _show_art(page: int, p, y: int, x: int, art_y0: int, art_x0: int, art_y1: int, art_x1: int, flags=None) -> bytes:
    """The 10 bytes of part p rewritten to show the page rectangle (art_x0.., art_y0..) at screen (x, y)."""
    return textures.pack_part(page, p.flags if flags is None else flags, p.palette, y, x, art_y0, art_x0, art_y1, art_x1)


def _show_nothing(cell: tuple, p) -> bytes:
    """The 10 bytes of part p rewritten to show the empty cell (page, x, y), at its own position."""
    page, x, y = cell
    return textures.pack_part(page, 0, p.palette, p.y, p.x, y, x, y + EMPTY_CELL, x + EMPTY_CELL)


def _size_text(box: tuple) -> str:
    return "%dx%d" % (box[2] - box[0], box[3] - box[1])


# ── Ribbon groups: lines of big lettering poured into rows ───────────────────────────────

def repack_ribbon(group, d, bank, pages, patches, project=None) -> list:
    """A group of sprite labels set as lines of big lettering ("ribbon": true; the umpire's calls). Each
    label is a sprite; its text (lines split by \\n) is styled line by line, the lines are poured into the
    areas by ribbon_pack, and part n of the sprite shows piece n (the rest show an empty cell). A line
    drawn twice in the same style (HOME RUN in the two-run homer) is stored once. The label is centred on
    the old art; lines stand `step` rows apart (default: line height - "overlap", 8)."""
    job = _Job(group, d, bank, pages, patches, project)
    gap = group.get("gap", [1, 1])[0]
    labels, lines, line_of = group["labels"], [], {}
    plan = []                                    # per label: (parts, screen box, [(line, dx, dy)], W, H)
    for lab in labels:
        mine = job.sprite(lab["sprite"])
        box = job.screen_box(mine)
        style_name = lab.get("style", group.get("style"))
        style = RENDER[style_name]
        font = lab.get("font", group.get("font"))
        label_lines = []
        for text in lab["text"].split("\n"):
            key = (style_name, font, text)
            if key not in line_of:
                line_of[key] = len(lines)
                lines.append(style(*typeset(text, font, project))[0])
            label_lines.append(line_of[key])
        heights = [lines[n].shape[0] for n in label_lines]
        step = lab.get("line_step", heights[0] - lab.get("overlap", OVERLAP_ROWS))
        width = max(lines[n].shape[1] for n in label_lines)
        height = step * (len(heights) - 1) + heights[-1]
        placed_lines = [(n, (width - lines[n].shape[1]) // 2, k * step) for k, n in enumerate(label_lines)]
        plan.append((mine, box, placed_lines, width, height))
    line_height = max(a.shape[0] for a in lines)
    owned = {(p.page, p.x0, p.y0, p.x1, p.y1) for mine, *_ in plan for p in mine}
    clear = job.areas + sorted(owned)
    job.check_clear_is_unshared(owned, clear)
    where, empty_cell = ribbon_pack([a.shape[1] for a in lines], line_height, job.areas, gap)
    job.clear_rectangles(clear)
    for n, a in enumerate(lines):
        for pg, x, y, c0, c1 in where[n]:
            job.page(pg)[y:y + a.shape[0], x:x + c1 - c0] = a[:, c0:c1]
    rows = []
    for lab, (mine, box, placed_lines, width, height) in zip(labels, plan):
        left = (box[0] + box[2]) // 2 - width // 2 + lab.get("dx", 0)
        top = (box[1] + box[3]) // 2 - height // 2 + lab.get("dy", 0)
        pieces = [(pg, x, y, c0, c1, n, dx, dy) for n, dx, dy in placed_lines for pg, x, y, c0, c1 in where[n]]
        if len(pieces) > len(mine):
            raise ValueError("%r needs %d parts, its sprite has %d" % (lab["text"], len(pieces), len(mine)))
        for k, p in enumerate(mine):
            if k < len(pieces):
                pg, x, y, c0, c1, n, dx, dy = pieces[k]
                data = _show_art(pg, p, top + dy, left + dx + c0, y, x, y + lines[n].shape[0], x + c1 - c0)
            else:
                data = _show_nothing(empty_cell, p)
            patches.append((p.offset, data))
        rows.append((lab["text"].replace("\n", " / "), _size_text(box), "%dx%d" % (width, height),
                     "%d pieces" % len(pieces), len(mine)))
    return rows


# ── Chain groups: labels cut into pieces that other labels share ─────────────────────────

def _chain_pieces(job: _Job) -> tuple:
    """Style every label of a chain group. Returns (unique pieces [(art, baseline)], per label ([(piece, base, x,
    height)], width)); identical pieces are stored once."""
    group, project = job.group, job.project
    unique, index_of, plans = [], {}, []
    for lab in group["labels"]:
        font = job.option(lab, "font")
        texts = lab["chain"] if "chain" in lab else [lab["text"]]
        inks = [typeset(t, font, project) for t in texts]
        pieces, width = RENDER[job.option(lab, "style")].chain(inks, job.option(lab, "gap", 4))
        plan = []
        for art, base, x in pieces:
            key = (art.shape, art.tobytes(), base)
            if key not in index_of:
                index_of[key] = len(unique)
                unique.append((art, base))
            plan.append((index_of[key], base, x, art.shape[0]))
        plans.append((plan, width))
    return unique, plans


def repack_chain(group, d, bank, pages, patches, project=None) -> list:
    """A group of sprite labels whose art is cut into pieces that other labels share ("chain": true; the inning card of
    sip_comm.arc). Each label is {"sprite", "layers", "baseline", "font"} plus "text" (one piece) or "chain": [left text,
    right text] with "gap" (clear ink columns between the two). The style must have a .chain(inks, gap) that returns
    ([(art, baseline row of the art, x offset)], width): for two texts the style renders the whole label and cuts it into
    left / middle / right pieces so that the left piece is the same for every label with that left text and the right piece
    the same for every label with that right text; identical pieces are stored once. Part n of each layer of the sprite
    shows piece n (the other parts show an empty cell); "baseline" is the screen row of the baseline in the first layer,
    the label is centred on the first layer's art (or "centre_x")."""
    job = _Job(group, d, bank, pages, patches, project)
    old, owned = [], set()
    for lab in group["labels"]:
        mine = job.sprite(lab["sprite"])
        layers = job.option(lab, "layers", 1)
        per = len(mine) // layers
        old.append((mine, job.screen_box(mine[:per]), per, layers))
        owned |= {(p.page, p.x0, p.y0, p.x1, p.y1) for p in mine}
    clear = job.areas + sorted(owned)
    job.check_clear_is_unshared(owned, clear)
    unique, plans = _chain_pieces(job)
    placed = shelf_pack([(a.shape[1], a.shape[0]) for a, _ in unique] + [(EMPTY_CELL, EMPTY_CELL)], job.areas,
                        tuple(group.get("gap", (1, 1))))
    job.clear_rectangles(clear)
    for k, (art, base) in enumerate(unique):
        pg, x, y = placed[k]
        job.page(pg)[y:y + art.shape[0], x:x + art.shape[1]] = art
    empty_cell = placed[len(unique)]
    rows = []
    for lab, (mine, box, per, layers), (plan, width) in zip(group["labels"], old, plans):
        if len(plan) > per:
            raise ValueError("%r needs %d parts per layer, its sprite has %d"
                             % (lab.get("text") or lab["chain"], len(plan), per))
        left = lab.get("centre_x", (box[0] + box[2]) // 2) - width // 2
        for k, p in enumerate(mine):
            layer, n = divmod(k, per)
            dx = min(q.x for q in mine[layer * per:(layer + 1) * per]) - min(q.x for q in mine[:per])
            dy = min(q.y for q in mine[layer * per:(layer + 1) * per]) - min(q.y for q in mine[:per])
            if n < len(plan):
                piece, base, x, _ = plan[n]
                pg, px, py = placed[piece]
                art = unique[piece][0]
                data = _show_art(pg, p, lab["baseline"] - base + dy, left + x + dx,
                                 py, px, py + art.shape[0], px + art.shape[1])
            else:
                data = _show_nothing(empty_cell, p)
            patches.append((p.offset, data))
        rows.append((lab.get("text") or " | ".join(lab["chain"]), _size_text(box),
                     "%dx%d" % (width, max(h for _, _, _, h in plan)), "%d pieces" % len(plan), len(mine)))
    rows.append(("(%d stored pieces)" % len(unique), "-", "-", "-", 0))
    return rows


# ── Ordinary groups ──────────────────────────────────────────────────────────────────────

class _Layout:
    """The state of one ordinary group between finding the old art and writing the new: what every label showed
    before (`old`), the new art of each (`art`), the extra pieces of labels that need more than one part (`extra`),
    labels cut into strips (`sliced`) and the places the packer gave them (`placed`).

    Indices into `placed`: label k -> k; the empty cell -> len(labels); extra piece j -> len(labels) + 1 + j."""

    def __init__(self, job: _Job):
        self.job = job
        self.labels = job.group["labels"]
        self.blanks = {tuple(r) for r in job.group.get("blank", ())}
        self.old = []                 # per label: (sprite parts it replaces, screen box of their art or None)
        self.art = []                 # per label: (style output array, baseline or None)
        self.sliced = {}              # label index: ([(dx, dy) of each strip], width, height)
        self.seen, self.alias = {}, {}    # strips already stored: art -> place; extra index -> that place
        self.extra = []               # (label index, (art, baseline)) of the second and later pieces of a label
        self.same = {}                # label index -> index of the identical label whose art it shares ("share")
        self.placed = {}
        self.clear = []

    def find_old_art(self) -> None:
        """Fill `old`: the sprite parts each label replaces and the box its Japanese art covered."""
        job = self.job
        owned = set()
        for lab in self.labels:
            if "sprite" in lab:
                mine = job.sprite(lab["sprite"])
                pgs, pls = job.option(lab, "pages"), job.option(lab, "palettes")   # the parts that are lettering
                mine = [p for p in mine if (pgs is None or p.page in pgs) and (pls is None or p.palette in pls)]
                box = job.screen_box(mine[:len(mine) // job.option(lab, "layers", 1)])   # the art as it stands
                self.old.append((mine, box))
            else:
                pg, x0, y0, x1, y1 = lab["from"]
                mine = [p for p in job.parts if (p.page, p.x0, p.y0, p.x1, p.y1) == (pg, x0, y0, x1, y1)]
                if "sprites" in lab:           # only these sprites' parts (a piece one sprite uses another way)
                    mine = [p for p in mine if p.sprite.rsplit("_", 1)[1] in lab["sprites"]]
                else:                          # less the parts a label with "sprites" takes for the same piece
                    taken = {s for o in self.labels if o.get("from") == lab["from"] for s in o.get("sprites", ())}
                    mine = [p for p in mine if p.sprite.rsplit("_", 1)[1] not in taken]
                ax0, ay0, ax1, ay1 = art_box(job.page(pg), (x0, y0, x1, y1))
                self.old.append((mine, (ax0 - x0, ay0 - y0, ax1 - x0, ay1 - y0)))     # relative to the rectangle
            owned |= {(p.page, p.x0, p.y0, p.x1, p.y1) for p in mine}
        self.clear = job.areas + sorted(self.blanks) + sorted(owned)
        job.check_clear_is_unshared(owned, self.clear, self.blanks)

    def style_labels(self) -> None:
        """Fill `art` (and `sliced`, `extra`, `alias`): the new art of every label, by what the label asks for."""
        job, project = self.job, self.job.project
        for k, (lab, (mine, box)) in enumerate(zip(self.labels, self.old)):
            style = RENDER[job.option(lab, "style", "command")]
            font = job.option(lab, "font", "command")
            if "pieces" in lab:                # coloured pieces side by side: one part and one palette each
                arts = [style(*typeset(pc["text"], font, project)) for pc in lab["pieces"]]
                self.art.append(arts[0])
                self.extra += [(k, a) for a in arts[1:]]
            elif "text" in lab and lab.get("slices"):    # wider than a part: cut into strips, one part each
                self._style_sliced(k, lab, style, font)
            elif "text" in lab:
                self.art.append(style(*typeset(lab["text"], font, project)))
            elif "art" in lab:
                self.art.append(style(*art_ink(lab["art"], project)))
            elif lab.get("empty"):                       # a piece that is not needed any more
                self.art.append((np.zeros((1, 1), np.uint8), None))
            else:                                        # keep the Japanese label as it is
                pg, x0, y0, x1, y1 = lab["from"]
                self.art.append((job.page(pg)[y0 + box[1]:y0 + box[3], x0 + box[0]:x0 + box[2]].copy(), None))

    def _style_sliced(self, k: int, lab: dict, style, font) -> None:
        """A label wider than one sprite part: each line is cut into strips of at most `slice_width` columns."""
        lines = [style(*typeset(t, font, self.job.project)) for t in lab["text"].split("\n")]
        step = lab.get("line_step", lines[0][0].shape[0] - lab.get("overlap", OVERLAP_ROWS))
        width = max(a.shape[1] for a, _ in lines)
        height = step * (len(lines) - 1) + lines[-1][0].shape[0]
        strips = []                        # (art, dx, dy) from the top left of the whole label
        for li, (a, b) in enumerate(lines):
            cuts = list(range(0, a.shape[1], lab.get("slice_width", textures.PAGE))) + [a.shape[1]]
            strips += [(a[:, c0:c1], (width - a.shape[1]) // 2 + c0, li * step) for c0, c1 in zip(cuts, cuts[1:])]
        self.sliced[k] = ([(dx, dy) for _, dx, dy in strips], width, height)
        self.art.append((strips[0][0], lines[0][1]))
        self.seen.setdefault((strips[0][0].shape, strips[0][0].tobytes()), ("main", k))
        for a, _, _ in strips[1:]:         # a strip drawn before (HOME RUN of the two-run homer) is shared
            key = (a.shape, a.tobytes())
            if key in self.seen:
                self.alias[len(self.extra)] = self.seen[key]
                self.extra.append((k, (np.zeros((1, 1), np.uint8), lines[0][1])))
            else:
                self.seen[key] = ("extra", len(self.extra))
                self.extra.append((k, (a, lines[0][1])))

    def find_shared_art(self) -> None:
        """With the group's "share" setting, a label whose art equals an earlier label's is stored once."""
        first = {}
        for k, (lab, (a, b)) in enumerate(zip(self.labels, self.art)):
            if (self.job.group.get("share") and "text" in lab and "pieces" not in lab
                    and k not in self.sliced and not lab.get("empty")):
                key = (a.shape, a.tobytes(), b)
                if key in first:
                    self.same[k] = first[key]
                else:
                    first[key] = k

    def pack(self) -> None:
        """Place every piece of art in the group's areas and clear what the Japanese labels occupied."""
        sizes = [(1, 1) if k in self.same else (a.shape[1], a.shape[0]) for k, (a, _) in enumerate(self.art)]
        sizes += [(EMPTY_CELL, EMPTY_CELL)] + [(a.shape[1], a.shape[0]) for _, (a, _) in self.extra]
        self.placed = shelf_pack(sizes, self.job.areas, tuple(self.job.group.get("gap", (1, 1))))
        self.job.clear_rectangles(self.clear)

    @property
    def empty_cell(self) -> tuple:
        return self.placed[len(self.labels)]

    def extra_cell(self, j: int) -> tuple:
        return self.placed[len(self.labels) + 1 + j]


def _where_to_put(lab: dict, job: _Job, box: tuple, base, w: int, h: int) -> tuple:
    """(top, left) of a label's new art relative to the old art's box: keeps the old horizontal centre and sits on the
    old baseline, unless the label asks for the left edge, the right edge, the middle, or a fixed row / column."""
    under = job.option(lab, "under", LEAVE_CLEAR_ROWS)       # rows of the Japanese art below the foot of its letters
    centre = lab.get("centre_x", (box[0] + box[2]) // 2)     # keep the horizontal centre
    if lab.get("align") == "left":                           # or the left edge
        centre = box[0] + w // 2
    if lab.get("align") == "right":                          # or the right edge
        centre = box[2] - w + w // 2
    top = (box[3] - under - base) if base is not None else box[1]   # sit on the old baseline
    if job.option(lab, "valign") == "centre" and base is not None:  # or in the middle of the old art
        top = (box[1] + box[3]) // 2 - h // 2
    left = centre - w // 2
    if job.option(lab, "baseline") is not None and base is not None:    # a fixed row and column of the sprite,
        top = job.option(lab, "baseline") - base                        # for a list of names set in one line
    if job.option(lab, "left") is not None:
        left = job.option(lab, "left")
    return top, left


def _write_sliced(lay: _Layout, i: int, lab: dict, mine: list, box: tuple, place: tuple, img) -> tuple:
    """Write the strips of a label cut into several parts: strip n is drawn by part n of the sprite."""
    job = lay.job
    offs, width, height = lay.sliced[i]
    pg, x, y = place

    def spot(j):
        kind, n = lay.alias.get(j, ("extra", j))
        if kind == "main":
            return lay.placed[n] + (lay.art[n][0],)
        return lay.extra_cell(n) + (lay.extra[n][1][0],)
    spots = [(pg, x, y, img)] + [spot(j) for j, (li, a) in enumerate(lay.extra) if li == i]
    if len(spots) > len(mine):
        raise ValueError("%s needs %d parts, its sprite has %d" % (lab["text"], len(spots), len(mine)))
    left = job.option(lab, "left", lab.get("centre_x", (box[0] + box[2]) // 2) - width // 2)
    top = (box[1] + box[3]) // 2 - height // 2 + lab.get("dy", 0)
    for n, p in enumerate(mine):
        if n < len(spots):
            sp, sx, sy, a = spots[n]
            job.page(sp)[sy:sy + a.shape[0], sx:sx + a.shape[1]] = a
            data = _show_art(sp, p, top + offs[n][1], left + offs[n][0], sy, sx, sy + a.shape[0], sx + a.shape[1])
        else:
            data = _show_nothing(lay.empty_cell, p)
        job.patches.append((p.offset, data))
    return (lab["text"].replace("\n", " / "), _size_text(box), "%dx%d" % (width, height),
            "page %d x %d y %d +%d strips" % (pg, x, y, len(spots) - 1), len(mine))


def _write_pieces(lay: _Layout, i: int, lab: dict, mine: list, box: tuple, place: tuple, img, base, top: int) -> tuple:
    """Write a label of coloured pieces side by side: piece n is drawn by part n, left to right."""
    job = lay.job
    pg, x, y = place
    h, w = img.shape
    more = [(lay.extra_cell(j), a) for j, (li, a) in enumerate(lay.extra) if li == i]
    join = job.option(lab, "join", 0)                    # pixels a piece overlaps the one before
    total = w + sum(a[0].shape[1] - join for _, a in more)
    x_on = (box[0] + box[2]) // 2 - total // 2
    for n, p in enumerate(mine):
        pal = lab["pieces"][n]["palette"] if n < len(lab["pieces"]) else p.palette
        if n == 0:
            data = textures.pack_part(pg, p.flags, pal, top, x_on, y, x, y + h, x + w)
            x_on += w - join
        elif n <= len(more):
            (mp, mx, my), (mimg, mbase) = more[n - 1]
            job.page(mp)[my:my + mimg.shape[0], mx:mx + mimg.shape[1]] = mimg
            data = textures.pack_part(mp, p.flags, pal, top + base - mbase, x_on, my, mx,
                                      my + mimg.shape[0], mx + mimg.shape[1])
            x_on += mimg.shape[1] - join
        else:
            data = _show_nothing(lay.empty_cell, p)
        job.patches.append((p.offset, data))
    return ("".join(pc["text"] for pc in lab["pieces"]), _size_text(box), "%dx%d" % (total, h),
            "page %d x %d y %d" % (pg, x, y), len(mine))


def _write_plain(lay: _Layout, lab: dict, mine: list, box: tuple, place: tuple, img, top: int, left: int) -> tuple:
    """Write an ordinary label: every part showing the old rectangle is pointed at the new art."""
    job = lay.job
    pg, x, y = place
    h, w = img.shape
    per = len(mine) // job.option(lab, "layers", 1) if "sprite" in lab else 1
    for k, p in enumerate(mine):
        if "sprite" in lab:                                  # box is in screen coordinates
            if k % per == 0:                                 # the first piece of each layer shows the new art
                dx = min(q.x for q in mine[k:k + per]) - min(q.x for q in mine[:per])
                dy = min(q.y for q in mine[k:k + per]) - min(q.y for q in mine[:per])
                data = _show_art(pg, p, top + dy, left + dx, y, x, y + h, x + w)
            else:
                data = _show_nothing(lay.empty_cell, p)
        else:                                                # box is relative to the old rectangle
            data = _show_art(pg, p, p.y + top, p.x + left, y, x, y + h, x + w)
        job.patches.append((p.offset, data))
    return (lab.get("text") or lab.get("name") or "(kept)", _size_text(box), "%dx%d" % (w, h),
            "page %d x %d y %d" % (pg, x, y), len(mine))


def _write_labels(lay: _Layout) -> list:
    """Draw every label's art on its page and rewrite its sprite parts; returns the report rows."""
    job = lay.job
    rows = []
    for i, (lab, (mine, box)) in enumerate(zip(lay.labels, lay.old)):
        img, base = lay.art[i]
        place = lay.placed[lay.same.get(i, i)]
        pg, x, y = place
        h, w = img.shape
        job.page(pg)[y:y + h, x:x + w] = img
        if lab.get("empty"):                                 # its parts show the empty cell from now on
            job.patches.extend((p.offset, _show_nothing(lay.empty_cell, p)) for p in mine)
            rows.append(("(emptied)", _size_text(box), "-", "-", len(mine)))
        elif i in lay.sliced:
            rows.append(_write_sliced(lay, i, lab, mine, box, place, img))
        else:
            top, left = _where_to_put(lab, job, box, base, w, h)
            if "pieces" in lab:
                rows.append(_write_pieces(lay, i, lab, mine, box, place, img, base, top))
            else:
                rows.append(_write_plain(lay, lab, mine, box, place, img, top, left))
    return rows


def repack(group: dict, d: bytes, bank: dict, pages: dict, patches: list, project=None) -> list:
    """Lay out the labels of one repack group. `pages` {page: index array} are edited in place;
    `patches` collects (file offset, 10 bytes) for the sprite parts. Returns report rows.

    A label is found by "from" (a rectangle [page, x0, y0, x1, y1]: every part showing it is
    re-pointed and keeps its place; with "sprites": [ids] only the parts of those sprites, and the label
    without "sprites" for the same rectangle leaves them alone) or by "sprite" (the end of an opd_ name: the whole sprite is one
    label, however many pieces it was drawn from; its first part shows the new art, the others are
    pointed at an empty cell)."""
    if group.get("ribbon"):
        return repack_ribbon(group, d, bank, pages, patches, project)
    if group.get("chain"):
        return repack_chain(group, d, bank, pages, patches, project)
    layout = _Layout(_Job(group, d, bank, pages, patches, project))
    layout.find_old_art()
    layout.style_labels()
    layout.find_shared_art()
    layout.pack()
    return _write_labels(layout)
