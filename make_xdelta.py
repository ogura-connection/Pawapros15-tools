"""Release build: the English disc with Nintendo's layout kept, and an xdelta patch against the original ISO.

    python3 make_xdelta.py ORIGINAL.iso OUT.iso [PATCH.xdelta]

Why: Wii partition data is AES-encrypted in 2 MB groups (64 clusters of 0x8000: 0x400 hash block + 0x7C00 data).
A disc rebuilt by `wit copy` has a new layout, so nearly every group differs and an xdelta is game-sized. Here
the original ISO is copied and only the groups we touch are rewritten:
- every changed file (DATA/files vs the original in the ISO) is appended behind the last used byte of the data,
  from a group boundary on, and its FST entry is pointed there (old copies stay, unread);
- main.dol is written in place when it fits, else appended and boot.bin re-pointed;
- each dirty group is decrypted, patched, its H0/H1/H2 hashes recomputed and re-encrypted; the H3 table, the
  partition data size, the TMD content hash/size are updated and the TMD is fake-signed (as wit does).
Then `wit verify` and an extract compare check the result, and xdelta3 makes the patch.
"""
import hashlib, os, shutil, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
COMMON_KEY = "ebe42a225e8593e448d9c5457381aaf7"
CL, HB, CD = 0x8000, 0x400, 0x7C00
GROUP = 64
WIT = shutil.which("wit") or os.path.join(HERE, "..", "tools_dl", "wit", "wit-v3.05a-r8638-mac", "bin", "wit")


def aes(data, key, iv, decrypt):
    p = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-d" if decrypt else "-e", "-nopad", "-K", key.hex(),
                        "-iv", iv.hex()], input=data, capture_output=True, check=True)
    return p.stdout


def u32(b, o): return struct.unpack_from(">I", b, o)[0]


class Disc:
    def __init__(self, path):
        self.f = open(path, "r+b")
        f = self.f
        f.seek(0x40000); info = f.read(0x20)
        self.part = None
        for g in range(4):
            n, t = u32(info, g * 8), u32(info, g * 8 + 4) << 2
            for k in range(n):
                f.seek(t + 8 * k); e = f.read(8)
                if u32(e, 4) == 0:
                    self.part = u32(e, 0) << 2
        f.seek(self.part); self.hdr = bytearray(f.read(0x2C0))
        tik = self.hdr[:0x2A4]
        self.key = aes(bytes(tik[0x1BF:0x1CF]), bytes.fromhex(COMMON_KEY), bytes(tik[0x1DC:0x1E4]) + bytes(8), True)
        self.tmd_size, self.tmd_off = u32(self.hdr, 0x2A4), u32(self.hdr, 0x2A8) << 2
        self.h3_off = u32(self.hdr, 0x2B4) << 2
        self.data_off, self.data_size = u32(self.hdr, 0x2B8) << 2, u32(self.hdr, 0x2BC) << 2
        self.dirty = {}                       # group -> bytearray of 64 * CD decrypted data

    def cluster_raw(self, c):
        self.f.seek(self.part + self.data_off + c * CL); return self.f.read(CL)

    def group_data(self, g):
        if g not in self.dirty:
            buf = bytearray()
            for c in range(g * GROUP, (g + 1) * GROUP):
                if c * CL >= self.data_size:
                    buf += bytes(CD); continue
                raw = self.cluster_raw(c)
                buf += aes(raw[HB:], self.key, raw[0x3D0:0x3E0], True)
            self.dirty[g] = buf
        return self.dirty[g]

    def read(self, off, n):                   # logical (decrypted) partition data
        out = bytearray()
        while n:
            c, w = divmod(off, CD)
            k = min(n, CD - w)
            g = c // GROUP
            if g in self.dirty:
                b = self.dirty[g][(c % GROUP) * CD + w:(c % GROUP) * CD + w + k]
            else:
                raw = self.cluster_raw(c)
                b = aes(raw[HB:], self.key, raw[0x3D0:0x3E0], True)[w:w + k]
            out += b; off += k; n -= k
        return bytes(out)

    def write(self, off, data):
        i = 0
        while i < len(data):
            c, w = divmod(off + i, CD)
            g = c // GROUP
            k = min(len(data) - i, CD - w)
            buf = self.group_data(g)
            p = (c % GROUP) * CD + w
            buf[p:p + k] = data[i:i + k]
            i += k

    def flush(self):
        f = self.f
        f.seek(self.part + self.h3_off); h3 = bytearray(f.read(0x18000))
        for g, buf in sorted(self.dirty.items()):
            h0s = [b"".join(hashlib.sha1(buf[c * CD + i * HB:c * CD + (i + 1) * HB]).digest() for i in range(31))
                   for c in range(GROUP)]
            h1s = [b"".join(hashlib.sha1(h0s[s * 8 + j]).digest() for j in range(8)) for s in range(8)]
            h2 = b"".join(hashlib.sha1(h1s[s]).digest() for s in range(8))
            for c in range(GROUP):
                hb = h0s[c] + bytes(20) + h1s[c // 8] + bytes(32) + h2 + bytes(32)
                assert len(hb) == HB
                ehb = aes(hb, self.key, bytes(16), False)
                edata = aes(bytes(buf[c * CD:(c + 1) * CD]), self.key, ehb[0x3D0:0x3E0], False)
                f.seek(self.part + self.data_off + (g * GROUP + c) * CL); f.write(ehb + edata)
            h3[g * 20:(g + 1) * 20] = hashlib.sha1(h2).digest()
        f.seek(self.part + self.h3_off); f.write(h3)
        f.seek(self.part + self.tmd_off); tmd = bytearray(f.read(self.tmd_size))
        tmd[0x1E4 + 0x10:0x1E4 + 0x24] = hashlib.sha1(h3).digest()            # content 0 hash
        struct.pack_into(">Q", tmd, 0x1E4 + 0x8, self.data_size)              # content 0 size
        tmd[4:0x104] = bytes(0x100)                                          # fake signature
        for n in range(1 << 32):
            struct.pack_into(">I", tmd, 0x1AA, n)                             # reserved field
            if hashlib.sha1(tmd[0x140:]).digest()[0] == 0:
                break
        f.seek(self.part + self.tmd_off); f.write(tmd)
        f.seek(self.part + 0x2BC); f.write(struct.pack(">I", self.data_size >> 2))
        self.dirty = {}


def fst_files(fst):
    n = u32(fst, 8)
    names = n * 12
    out, stack = {}, [("", n)]
    i = 1
    def name(k):
        o = names + (u32(fst, k * 12) & 0xFFFFFF); return fst[o:fst.index(b"\0", o)].decode("shift_jis")
    path_end = [(n, "")]
    while i < n:
        while path_end and i >= path_end[-1][0]:
            path_end.pop()
        prefix = path_end[-1][1] if path_end else ""
        if fst[i * 12] == 1:
            path_end.append((u32(fst, i * 12 + 8), prefix + name(i) + "/")); i += 1; continue
        out[prefix + name(i)] = i
        i += 1
    return out


def main():
    src, dst = sys.argv[1], sys.argv[2]
    patch = sys.argv[3] if len(sys.argv) > 3 else None
    print("copying", src)
    shutil.copyfile(src, dst)
    d = Disc(dst)
    boot = d.read(0, 0x440)
    dol_off, fst_off, fst_size = u32(boot, 0x420) << 2, u32(boot, 0x424) << 2, u32(boot, 0x428) << 2
    fst = bytearray(d.read(fst_off, fst_size))
    files = fst_files(fst)
    used = max([fst_off + fst_size] + [(u32(fst, i * 12 + 4) << 2) + u32(fst, i * 12 + 8) for i in files.values()])
    gsize = GROUP * CD
    pos = (used + gsize - 1) // gsize * gsize                                 # new data from a group boundary
    origs = {}                                                                 # changed files have their original kept
    for od in ("orig", "orig_arc", "orig_sys"):
        for root, _, fs in os.walk(os.path.join(HERE, "_work", od)):
            for fn in fs:
                origs.setdefault(fn, os.path.join(root, fn))
    moved = 0
    for rel, i in sorted(files.items()):
        p = os.path.join(HERE, "DATA", "files", *rel.split("/"))
        base = rel.split("/")[-1]
        if base not in origs:
            continue
        new = open(p, "rb").read()
        old = open(origs[base], "rb").read()
        if new == old:
            continue
        old_off, old_size = u32(fst, i * 12 + 4) << 2, u32(fst, i * 12 + 8)
        assert old_size == len(old), (rel, "the kept original differs from the disc")
        d.write(pos, new)
        struct.pack_into(">II", fst, i * 12 + 4, pos >> 2, len(new))
        pos = (pos + len(new) + 0x1F) & ~0x1F
        moved += 1
    dol = open(os.path.join(HERE, "DATA", "sys", "main.dol"), "rb").read()
    old_dol = d.read(dol_off, len(dol))
    if old_dol != dol:
        # the DOL ends where its last section ends; space up to the next item (the FST) is free
        if dol_off + len(dol) <= fst_off:
            d.write(dol_off, dol)
        else:
            d.write(pos, dol); b = bytearray(boot); struct.pack_into(">I", b, 0x420, pos >> 2)
            d.write(0, bytes(b)); pos = (pos + len(dol) + 0x1F) & ~0x1F
    d.write(fst_off, bytes(fst))
    need = (pos + CD - 1) // CD * CL
    if need > d.data_size:
        d.data_size = (need + GROUP * CL - 1) // (GROUP * CL) * (GROUP * CL)
    disc_end = os.path.getsize(dst)
    assert d.part + d.data_off + d.data_size <= disc_end, "no room on the disc image"
    print("%d files moved behind 0x%X, %d groups rewritten" % (moved, used, len(d.dirty)))
    d.flush(); d.f.close()
    v = subprocess.run([WIT, "verify", dst], capture_output=True, text=True)
    print(v.stdout.strip().splitlines()[-1] if v.stdout.strip() else v.stderr.strip())
    if patch:
        subprocess.run(["xdelta3", "-e", "-9", "-f", "-s", src, dst, patch], check=True)
        print("patch %s: %.1f MB" % (patch, os.path.getsize(patch) / 1e6))


if __name__ == "__main__":
    main()
