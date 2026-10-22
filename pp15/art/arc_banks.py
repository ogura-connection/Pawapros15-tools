"""Find the sprite banks inside an .arc file: its symbols, palettes, texture pages and sprite part tables.

An .arc is an ELF object file whose symbols name the pieces of a group of pictures (a "bank"): `tex_<bank>NN` pages,
`pal_<bank>` colours and `opd_<bank>_NN` sprites (the format is written out in pp15/art/textures.py). This module reads
the symbol table and groups the symbols into banks; it does not decode any picture (that is pp15/art/page_codec.py).

  elf_symbols(d)           {symbol: (file offset, size)}
  banks(d, syms)           the sprite banks of a file, in file order (each a dict, see banks)
  bank_named(banks, ref)   look a bank up by name ("name") or by position ("name#k")
  pack_part(...)           the 10 bytes of one sprite part
  palette_colours(d, pal)  the RGBA colours of a bank's palette table
  Part                     one sprite part (named tuple)

Some files lump several sprite sets into one bank or file them one bank late; hand_over_pages, split_merged and the
functions they call put each set back with its own pages. The ones that apply only to named banks are listed in
SPLIT_BY_SET.
"""
import collections
import re
import struct

import numpy as np

from pp15.art.gx_pixels import rgb5a3_colours

def elf_symbols(d):
    """{name: (offset in file, size)} for the symbols of an ELF object with .data at its address."""
    if d[:4] != b"\x7fELF":
        return {}
    shoff = struct.unpack_from(">I", d, 0x20)[0]
    entsize, count, _ = struct.unpack_from(">HHH", d, 0x2E)
    secs = [struct.unpack_from(">10I", d, shoff + i * entsize) for i in range(count)]
    syms = {}
    for s in secs:
        if s[1] != 2:
            continue
        strtab = secs[s[6]]
        for k in range(s[5] // 16):
            name, value, size, _, _, shndx = struct.unpack_from(">IIIBBH", d, s[4] + k * 16)
            if name and 0 < shndx < count:
                end = d.index(b"\0", strtab[4] + name)
                sec = secs[shndx]
                syms[d[strtab[4] + name:end].decode("latin1")] = (value - sec[3] + sec[4], size)
    return syms


Part = collections.namedtuple("Part", "sprite page flags palette y x y0 x0 y1 x1 offset")


def banks(d, syms):
    """Sprite banks of an ELF object in file order:
    [{"name", "pal": (offset, size) or None, "pages": [(offset, size)], "sprites": {opd name: [Part]}}]; Part.offset = file offset of the 10 bytes.
    A bank is the run of opd_, pal_*_tbl, tex_ symbols that ends at its pal_ colour table."""
    out, cur = [], None
    for name in sorted(syms, key=lambda n: syms[n][1] and syms[n][0]):
        off, size = syms[name]
        kind = name[:4]
        if kind not in ("opd_", "pal_", "tex_"):
            continue
        if cur is None:
            cur = {"name": None, "pal": None, "pages": [], "sprites": {}, "page_names": []}
        if kind == "opd_":
            if size >= 20 and size == 10 + 10 * d[off]:
                cur["sprites"][name] = [
                    Part(name, d[o] & 0x3F, d[o] & 0xC0, d[o + 1], *struct.unpack_from(">hhBBBB", d, o + 2), o)
                    for o in range(off + 10, off + size, 10)]
        elif kind == "tex_":
            if not name.endswith("_tbl"):
                cur["pages"].append((off, size))
                cur["page_names"].append(name)
        elif name.endswith("_tbl"):
            cur["name"] = cur["name"] or name[4:-4]
        else:
            cur["pal"] = (off, size)
            if cur["sprites"]:
                cur["name"] = re.sub(r"_[0-9a-f]{2}$", "", next(iter(cur["sprites"]))[4:])
            else:
                cur["name"] = name[4:]
            out.append(cur)
            cur = None
    tail = None
    if cur and cur["pages"]:
        cur["name"] = cur["name"] or re.sub(r"\d\d$", "", cur["page_names"][0][4:])
        out.append(cur)
    elif cur and cur["sprites"]:                    # sprite tables behind the file's last palette (sct_a_sy.arc): a
        cur["name"] = re.sub(r"_[0-9a-f]{2}$", "", next(iter(cur["sprites"]))[4:])   # bank of sprites only, last
        tail = cur
    res = [s for b in hand_over_pages([b for b in out if b["pages"]]) for s in split_merged(b)]
    return res + [tail] if tail else res


def bank_named(banks, ref):
    """The bank `ref` names: "name" = the first bank of that name; "name#k" = banks[k] (k = place in the list
    banks() returns; for files whose sprite tables the reader files one bank too late, e.g. sct_comd.arc, where
    the sprites of bank k draw the pages of bank k - 1: a repack group then says "bank": "z4_eg_0#1",
    "sprites": "z4_egp_0#2")."""
    if "#" in ref:
        name, k = ref.rsplit("#", 1)
        b = banks[int(k)]
        if b["name"] != name:
            raise KeyError("bank %d is %s, not %s" % (int(k), b["name"], name))
        return b
    return next(x for x in banks if x["name"] == ref)


# merged gameplay.arc banks that are split by sprite set (split_by_prefix, hand_over_pages); other files are untouched
SPLIT_BY_SET = {"h3_tnm_0", "y4_dem_1", "g3_hk"}


def hand_over_pages(out):
    """A page group that ends one bank (gameplay.arc tex_g3_hk00, listed after the pages of y4_dem_1 / h3_dem_2)
    belongs to a sprite set of the next bank when no set of its own bank is named like it, a set of the next bank
    is named exactly like it (opd_g3_hk_00..) and that set uses exactly the pages 0..n-1 of the n moved pages:
    the group moves to the front of the next bank's pages."""
    for i in range(len(out) - 1):
        a, nxt = out[i], out[i + 1]
        if a["name"] not in SPLIT_BY_SET or nxt["name"] not in SPLIT_BY_SET or not a["sprites"] or len(a["page_names"]) < 2:
            continue
        pre = re.sub(r"\d\d$", "", a["page_names"][-1][4:])
        n = 0
        while n < len(a["page_names"]) - 1 and re.sub(r"\d\d$", "", a["page_names"][-1 - n][4:]) == pre:
            n += 1
        sets_a = {re.sub(r"_[0-9a-f]{2}$", "", k[4:]) for k in a["sprites"]}
        if any(s.startswith(pre) for s in sets_a) or any(re.sub(r"\d\d$", "", pn[4:]) == pre for pn in nxt["page_names"]):
            continue
        used = {p.page for k, ps in nxt["sprites"].items() if re.sub(r"_[0-9a-f]{2}$", "", k[4:]) == pre for p in ps}
        if not used or used != set(range(n)):
            continue
        nxt["pages"] = a["pages"][-n:] + nxt["pages"]
        nxt["page_names"] = a["page_names"][-n:] + nxt["page_names"]
        a["pages"], a["page_names"] = a["pages"][:-n], a["page_names"][:-n]
    return out


def split_merged(b):
    """The banks a merged bank really consists of: one per sprite set (see the two functions below), or [b] itself."""
    out = split_merged_old(b)
    if len(out) == 1 and out[0] is b:
        out = split_by_prefix(b)
    return out


def split_by_prefix(b):
    """The split for a bank whose page groups are each named after one sprite set (tex_h3_nxt00..07 for
    opd_h3_nxt_ps2, tex_h3_her00..06 for h3_her_0, tex_h3_rs00..06 for h3_rs_0) while one set has no pages of its
    own (h3_tnm_0: its page table is empty; the old reading, the next set's pages, is kept) or its pages were
    counted wrongly by split_by_order. Only when every page group is named by exactly one set, each such set uses
    pages inside its group, and the sets without a group are followed by a set with one (a set at the end
    without pages, gameplay.arc h3_cat_0 whose pages are stored under pal_ names, is dropped); else [b]."""
    groups = []
    for k, pn in enumerate(b["page_names"]):
        pre = re.sub(r"\d\d$", "", pn[4:])
        if groups and groups[-1][0] == pre:
            groups[-1][1].append(k)
        else:
            groups.append((pre, [k]))
    sets = {}
    for n in b["sprites"]:
        sets.setdefault(re.sub(r"_[0-9a-f]{2}$", "", n[4:]), []).append(n)
    if b["name"] not in SPLIT_BY_SET or len(sets) < 2 or len({g for g, _ in groups}) != len(groups):
        return [b]
    first = {s: min(p.offset for n in sets[s] for p in b["sprites"][n]) for s in sets}
    order = sorted(sets, key=first.get)
    owner = {}
    for s in order:
        fits = [i for i, (g, _) in enumerate(groups) if s.startswith(g)]
        if fits:
            owner[s] = max(fits, key=lambda i: len(groups[i][0]))
    if len(owner) == len(sets) or sorted(owner.values()) != list(range(len(groups))):
        return [b]
    for s, i in owner.items():
        used = [p.page for n in sets[s] for p in b["sprites"][n]]
        if used and max(used) >= len(groups[i][1]):
            return [b]
    pages_of = {}
    for k, s in enumerate(order):
        if s in owner:
            pages_of[s] = owner[s]
        else:
            later = [t for t in order[k + 1:] if t in owner]
            if later:
                pages_of[s] = owner[later[0]]
    out = []
    for s in order:
        if s not in pages_of:
            continue
        idx = groups[pages_of[s]][1]
        out.append(dict(b, name=s, pages=[b["pages"][k] for k in idx], page_names=[b["page_names"][k] for k in idx],
                        sprites={n: b["sprites"][n] for n in sets[s]}))
    return out if len(out) > 1 else [b]


def split_merged_old(b):
    """Some files merge several sprite sets into one bank (ore_ini.arc y3_mym + y3_mys + y3_myk + y3_kzo,
    gdt_ore.arc, ore_ren.arc): the pages run tex_<set1>00.., tex_<set2>00.., and the sprites of every set
    count their pages from 0 again. Such a bank is returned as one bank per set, each with its own pages;
    the palette is shared. A bank whose sprites number the pages straight through is left whole."""
    groups = []                                     # [(page prefix, [indices into the bank's pages])]
    for k, pn in enumerate(b["page_names"]):
        pre = re.sub(r"\d\d$", "", pn[4:])
        if groups and groups[-1][0] == pre:
            groups[-1][1].append(k)
        else:
            groups.append((pre, [k]))
    sets = {}
    for n in b["sprites"]:
        sets.setdefault(re.sub(r"_[0-9a-f]{2}$", "", n[4:]), []).append(n)
    if len(sets) < 2:
        return [b]
    owner = {}                                      # set -> group index (the longest page prefix of its name)
    for s in sets:
        fits = [i for i, (g, _) in enumerate(groups) if s.startswith(g)]
        if not fits:
            break
        owner[s] = max(fits, key=lambda i: len(groups[i][0]))
    if len(groups) < 2 or len({g for g, _ in groups}) != len(groups) or len(owner) != len(sets) \
            or sorted(owner.values()) != list(range(len(groups))):
        return split_by_order(b, sets)
    for s, i in owner.items():
        used = [p.page for n in sets[s] for p in b["sprites"][n]]
        start, count = groups[i][1][0], len(groups[i][1])
        if used and max(used) >= count:             # pages beyond the set's own: numbered straight through
            return [b]
        if i and used and min(used) >= start:       # fits both ways: keep the old reading
            return [b]
    out = []
    for i, (pre, idx) in sorted(enumerate(groups), key=lambda t: t[0]):
        s = next(s for s, j in owner.items() if j == i)
        out.append(dict(b, name=s, pages=[b["pages"][k] for k in idx], page_names=[b["page_names"][k] for k in idx],
                        sprites={n: b["sprites"][n] for n in sets[s]}))
    return out


def split_by_order(b, sets):
    """The same split when the page names do not tell the sets apart (gameplay.arc h3_ap_ps2: tex_h3_ap00..05 and
    ap08 for h3_ap_ps2, ap06 / ap07 for h3_sc_ps2, mmk00..02 for h3_mmk_0): the sets, in file order of their
    sprites, take the pages in file order, each as many as it uses. Only when every set uses each of its pages
    0..n-1 and the counts add up to the bank's pages exactly; otherwise the bank stays whole."""
    order = sorted(sets, key=lambda s: min(p.offset for n in sets[s] for p in b["sprites"][n]))
    counts = []
    for s in order:
        used = {p.page for n in sets[s] for p in b["sprites"][n]}
        if not used or used != set(range(max(used) + 1)):
            return [b]
        counts.append(max(used) + 1)
    if sum(counts) != len(b["pages"]) or counts[0] == len(b["pages"]):
        return [b]
    out, k = [], 0
    for s, c in zip(order, counts):
        out.append(dict(b, name=s, pages=b["pages"][k:k + c], page_names=b["page_names"][k:k + c],
                        sprites={n: b["sprites"][n] for n in sets[s]}))
        k += c
    return out


def pack_part(page, flags, palette, y, x, y0, x0, y1, x1):
    """The 10 bytes of a sprite part: page number (or-ed with the mirror `flags`), palette number, the screen offset
    (y, x) and the page rectangle rows y0 to y1, columns x0 to x1."""
    return struct.pack(">BBhhBBBB", page | flags, palette, y, x, y0, x0, y1, x1)


def palette_colours(d, pal):
    """RGBA colours (n, 4) of a bank's palette table; `pal` = (offset, size) as in bank["pal"], or None."""
    return rgb5a3_colours(np.frombuffer(d, dtype=">u2", count=pal[1] // 2, offset=pal[0])) if pal \
        else np.zeros((0, 4), np.uint8)
