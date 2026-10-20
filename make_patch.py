"""Build the release patch: release/patcher/pp15_english.patch (+ apply_patch.py next to it).

For every file of DATA/ that differs from its original (_work/orig, _work/orig_arc, _work/orig_sys), the patch
stores the new file XOR-ed with the original repeated as a key, zlib-compressed, with both SHA-1s. The patch holds
no game data in the clear: without the original disc it is noise. The player's side (apply_patch.py) extracts
their disc with wit, rebuilds each file from its original and checks both hashes, then builds the ISO with wit.

    python3 make_patch.py            write the patch and self-test it against the originals
"""
import hashlib, json, os, shutil, struct, sys, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "..", "release", "patcher")
ORIG_DIRS = [os.path.join(HERE, "_work", d) for d in ("orig", "orig_arc", "orig_sys")]
MAGIC = b"PP15ENG1"


def xor_key(new, orig):
    n, k = len(new), len(orig)
    key = (orig * (n // k + 1))[:n]
    return bytes(a ^ b for a, b in zip(new, key)) if n < 1 << 20 else \
        (int.from_bytes(new, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


def originals():
    out = {}
    for d in ORIG_DIRS:
        for root, _, fs in os.walk(d):
            for f in fs:
                out.setdefault(f, os.path.join(root, f))
    return out


def changed_files(origs):
    rows = []
    for top in ("files", "sys"):
        base = os.path.join(HERE, "DATA", top)
        for root, _, fs in os.walk(base):
            for f in sorted(fs):
                p = os.path.join(root, f)
                if f not in origs:
                    continue
                new, old = open(p, "rb").read(), open(origs[f], "rb").read()
                if new != old:
                    rows.append((os.path.relpath(p, os.path.join(HERE, "DATA")), new, old))
    return rows


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    origs = originals()
    rows = changed_files(origs)
    index, blobs, pos = [], [], 0
    for rel, new, old in rows:
        z = zlib.compress(xor_key(new, old), 9)
        index.append({"path": rel.replace(os.sep, "/"), "orig_sha1": hashlib.sha1(old).hexdigest(),
                      "orig_size": len(old), "new_sha1": hashlib.sha1(new).hexdigest(), "new_size": len(new),
                      "offset": pos, "length": len(z)})
        blobs.append(z)
        pos += len(z)
    head = json.dumps({"game": "RP5JA4 (Jikkyou Powerful Pro Yakyuu 15, Rev 1)", "files": index}).encode()
    out = os.path.join(OUT_DIR, "pp15_english.patch")
    with open(out, "wb") as f:
        f.write(MAGIC + struct.pack(">I", len(head)) + head)
        for b in blobs:
            f.write(b)
    shutil.copy(os.path.join(HERE, "apply_patch.py"), os.path.join(OUT_DIR, "apply_patch.py"))
    # self-test: rebuild every file from its original exactly as apply_patch.py does
    sys.path.insert(0, OUT_DIR)
    import apply_patch as A
    meta, data_off = A.read_header(out)
    for e in meta["files"]:
        old = open(origs[os.path.basename(e["path"])], "rb").read()
        assert A.rebuild(out, data_off, e, old) == open(os.path.join(HERE, "DATA", e["path"]), "rb").read(), e["path"]
    print("%d files, patch %.1f MB -> %s (self-test OK)" % (len(index), os.path.getsize(out) / 1e6, out))


if __name__ == "__main__":
    main()
