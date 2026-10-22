"""The existing round-trip check of the build: every module is parsed and re-emitted without changes, and the font,
the memory plan and the dialog block of main.dol must come out identical. Changes no file.

    python3 tests/test_roundtrip.py      (also collected by pytest)
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_build_check():
    run = subprocess.run([sys.executable, "-m", "pp15", "build-check"], cwd=ROOT, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    assert "FAILED" not in run.stdout


if __name__ == "__main__":
    test_build_check()
    print("build-check passed")
