"""Label styles of art run 2, agent D (scs_open fiction notice, scs_grad graduation, orihen ball naming, scs_intr
scenario introduction, scs_titl start screen). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# scs_open z3_fic_0 (palette 0, grey ramp): white letters, a grey soft edge, black outline, dark blue-grey shadow
STYLES["d2_fic"] = ringfill([0xf], [0xb, 4], [3, 2])

ui_type.TTF["d_georgia"] = ("/System/Library/Fonts/Supplemental/Georgia Bold.ttf", 0)
ui_type.TTF["d_times"] = ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0)
ui_type.TTF["d_impact"] = ("/System/Library/Fonts/Supplemental/Impact.ttf", 0)

# scs_titl r4_staz (8-bit, palette 16): the three buttons. Gradient letters, a thin dark outline, a white band, a blue
# shadow to the lower right (orange / lime / green fill; each has its own run of palette entries)
STYLES["d2_staz_new"] = ringfill([1, 2, 3, 4, 6, 5, 9, 11], [25, 57, 57, 35], [35, 35])
STYLES["d2_staz_cont"] = ringfill([166, 168, 169, 170, 171, 175, 176], [129, 181, 181, 152], [152, 152])
STYLES["d2_staz_list"] = ringfill([215, 216, 218, 221, 226, 229], [240, 210, 210, 193], [193, 193])


# ---- a text font of this file: "d:<face>:<cap>:<squeeze>:<bold>[:<pitch>]" -------------------------------------------------
# Lines are separated by "|" and left aligned, `pitch` rows apart (baseline to baseline); a line may hold the symbols
# ◎ and × (drawn here, no font has them in this style) between words; everything else is ui_type.ttf_ink.
def _symbol(ch, cap, bold):
    """(ink, base) of ◎ or × drawn as capitals `cap` high: supersampled, 6 ink levels like ttf_ink."""
    from PIL import Image, ImageDraw
    k = 8
    size = int(cap) + 2
    big = Image.new("L", (size * k, size * k), 0)
    dr = ImageDraw.Draw(big)
    c = size * k / 2
    r = cap * k / 2
    w = max(1.0, (0.16 + 0.35 * bold) * cap) * k
    if ch == "◎":
        dr.ellipse((c - r, c - r, c + r, c + r), fill=255)
        dr.ellipse((c - r + w, c - r + w, c + r - w, c + r - w), fill=0)
        q = r * 0.42
        dr.ellipse((c - q, c - q, c + q, c + q), fill=255)
    else:                                           # ×
        r *= 0.8
        dr.line((c - r, c - r, c + r, c + r), fill=255, width=int(w * 1.1))
        dr.line((c - r, c + r, c + r, c - r), fill=255, width=int(w * 1.1))
    small = np.asarray(big.resize((size, size), Image.BOX), dtype=np.float32)
    ink = np.rint(small * 6 / 255).astype(int)
    ys, xs = np.nonzero(ink)
    ink = ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    return ink, ink.shape[0] - (1 if ch == "×" else 0)


def _line(text, face, cap, squeeze, bold):
    import re
    items = []
    for tok in re.split("([◎×])", text):
        if not tok:
            continue
        if tok in "◎×":
            items.append(_symbol(tok, cap * 0.95, bold))
        else:
            lead, trail = len(tok) - len(tok.lstrip(" ")), len(tok) - len(tok.rstrip(" "))
            if tok.strip():
                ink, base = ui_type.ttf_ink(tok.strip(), face, cap, 0.0, squeeze, bold)
            else:
                ink, base = np.zeros((1, 0), int), 1
            items.append((np.pad(ink, ((0, 0), (round(lead * cap * 0.3), round(trail * cap * 0.3)))), base))
    up = max(b for _, b in items)
    down = max(i.shape[0] - b for i, b in items)
    w = sum(i.shape[1] for i, _ in items) + 2 * (len(items) - 1)
    out = np.zeros((up + down, w), int)
    x = 0
    for ink, base in items:
        out[up - base:up - base + ink.shape[0], x:x + ink.shape[1]] = ink
        x += ink.shape[1] + 2
    return out, up


class _Words(dict):
    def __init__(self, spec):
        a = spec.split(":")
        self.face, self.cap, self.sq, self.bold = a[0], int(a[1]), float(a[2]), float(a[3])
        self.pitch = int(a[4]) if len(a) > 4 else 0

    def __contains__(self, text):
        return True

    def __getitem__(self, text):
        lines = [_line(t, self.face, self.cap, self.sq, self.bold) for t in text.split("|")]
        if len(lines) == 1:
            return lines[0]
        pitch = self.pitch or self.cap + 6
        w = max(i.shape[1] for i, _ in lines)
        h = pitch * (len(lines) - 1) + lines[-1][0].shape[0] + max(b for _, b in lines)
        out = np.zeros((h, w), int)
        base_last = 0
        for k, (ink, base) in enumerate(lines):
            y = k * pitch + max(b for _, b in lines) - base
            out[y:y + ink.shape[0], :ink.shape[1]] = np.maximum(out[y:y + ink.shape[0], :ink.shape[1]], ink)
            base_last = y + base
        ys = np.nonzero(out.any(1))[0]
        out = out[ys.min():ys.max() + 1]
        return out, base_last - ys.min()


class _Fonts(dict):
    def __missing__(self, name):
        if name.startswith("d:"):
            words = _Words(name[2:])
            return lambda project=None: {"words": words}
        raise KeyError(name)


if not isinstance(ui_type.FONTS, _Fonts):
    ui_type.FONTS = _Fonts(ui_type.FONTS)


def dfont(face, cap, squeeze=1.0, bold=0.4, pitch=0):
    return "d:%s:%d:%s:%s:%d" % (face, cap, squeeze, bold, pitch)
