#!/usr/bin/env python3
"""Jikkyou Powerful Pro Yakyuu 15 (Wii, RP5JA4 Rev 1) - English patch.

    python3 apply_patch.py GAME.iso OUTPUT.iso [--wit PATH_TO_WIT]

GAME.iso: your own copy of the Japanese game as ISO or WBFS (an .rvz from Dolphin: right-click the game in
Dolphin > Convert File... > ISO first). Needs Python 3.8+ and Wiimms ISO Tools (wit, free: https://wit.wiimm.de)
on the PATH or given with --wit. About 10 GB of free disk space while it runs.
The patch file pp15_english.patch must be next to this script.
"""
import hashlib, json, os, shutil, struct, subprocess, sys, tempfile, zlib

MAGIC = b"PP15ENG1"
PATCH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pp15_english.patch")


def read_header(path):
    with open(path, "rb") as f:
        if f.read(8) != MAGIC:
            sys.exit("%s is not a PP15 English patch" % path)
        n = struct.unpack(">I", f.read(4))[0]
        return json.loads(f.read(n)), 12 + n


def rebuild(path, data_off, e, old):
    """The new file from its original and its patch entry; both SHA-1s are checked."""
    if hashlib.sha1(old).hexdigest() != e["orig_sha1"]:
        raise ValueError("%s: your file is not the original this patch expects (wrong game version or "
                         "already patched?)" % e["path"])
    with open(path, "rb") as f:
        f.seek(data_off + e["offset"])
        x = zlib.decompress(f.read(e["length"]))
    n = e["new_size"]
    key = (old * (n // len(old) + 1))[:n]
    new = (int.from_bytes(x, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")
    if hashlib.sha1(new).hexdigest() != e["new_sha1"]:
        raise ValueError("%s: patched file does not check out (damaged patch file?)" % e["path"])
    return new


def main():
    args = sys.argv[1:]
    wit = "wit"
    if "--wit" in args:
        k = args.index("--wit"); wit = args[k + 1]; del args[k:k + 2]
    if len(args) != 2:
        sys.exit(__doc__)
    src, dst = (os.path.abspath(a) for a in args)
    if shutil.which(wit) is None and not os.path.isfile(wit):
        sys.exit("wit not found: install Wiimms ISO Tools (https://wit.wiimm.de) or pass --wit /path/to/wit")
    meta, data_off = read_header(PATCH)
    work = tempfile.mkdtemp(prefix="pp15eng_", dir=os.path.dirname(dst) or ".")
    try:
        print("1/3 extracting the game with wit ...")
        subprocess.run([wit, "extract", src, os.path.join(work, "x"), "--psel", "data", "-q"], check=True)
        root = os.path.join(work, "x")
        if os.path.isdir(os.path.join(root, "DATA")):
            root = os.path.join(root, "DATA")
        print("2/3 patching %d files ..." % len(meta["files"]))
        for e in meta["files"]:
            p = os.path.join(root, *e["path"].split("/"))
            if not os.path.isfile(p):
                raise ValueError("%s missing from the extracted game" % e["path"])
            new = rebuild(PATCH, data_off, e, open(p, "rb").read())
            with open(p, "wb") as f:
                f.write(new)
        print("3/3 building %s ..." % dst)
        subprocess.run([wit, "copy", root, dst, "--iso", "--overwrite", "-q"], check=True)
        print("Done. Play %s in Dolphin or on a Wii (USB loader)." % dst)
    except (ValueError, subprocess.CalledProcessError) as err:
        sys.exit("Stopped: %s" % err)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
