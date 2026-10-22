"""Golden-output check: the build must keep producing exactly the files that were released.

    python3 tests/golden.py record    store the SHA-1 of every installed game file (DATA/files, DATA/sys)
    python3 tests/golden.py check     rebuild (python3 -m pp15 build) and compare with the stored hashes

Run `check` after every refactoring step. The hashes carry no game data, so the list is safe to keep in git.
"""
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pp15 import config

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GOLDEN = os.path.join(HERE, "golden_sha1.json")
FOLDERS = (config.DATA_FILES, config.DATA_SYS)
SKIP_SUFFIX = (".thp",)            # videos: never rebuilt, big


def hash_game_files():
    out = {}
    for folder in FOLDERS:
        for dirpath, _, names in os.walk(folder):
            for name in sorted(names):
                if name.endswith(SKIP_SUFFIX):
                    continue
                path = os.path.join(dirpath, name)
                digest = hashlib.sha1()
                with open(path, "rb") as f:
                    for block in iter(lambda: f.read(1 << 20), b""):
                        digest.update(block)
                out[os.path.relpath(path, config.DATA_ROOT)] = digest.hexdigest()
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else ""
    if mode == "record":
        hashes = hash_game_files()
        with open(GOLDEN, "w") as f:
            json.dump(hashes, f, indent=0, sort_keys=True)
        print("recorded", len(hashes), "files")
    elif mode == "check":
        build = subprocess.run([sys.executable, "-m", "pp15", "build"], cwd=ROOT,
                               capture_output=True, text=True)
        if build.returncode != 0:
            sys.exit("build failed:\n" + build.stdout[-2000:] + build.stderr[-2000:])
        golden = json.load(open(GOLDEN))
        now = hash_game_files()
        changed = sorted(p for p in golden if now.get(p) != golden[p])
        extra = sorted(set(now) - set(golden))
        if changed or extra:
            print("DIFFERENT:", changed[:20], "NEW:", extra[:10])
            sys.exit(1)
        print("golden check passed:", len(golden), "files identical")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
