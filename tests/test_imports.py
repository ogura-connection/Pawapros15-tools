"""Import every module of the pp15 package, including the art style modules.

    python3 tests/test_imports.py        (also collected by pytest)

A module that needs an optional third-party package (pycryptodome for the ISO tools, capstone for `scan xref`) is
reported as skipped, not failed.
"""
import importlib
import os
import pkgutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pp15

OPTIONAL = {"Crypto": "pycryptodome", "capstone": "capstone", "lz4": "lz4"}


def module_names():
    return sorted(m.name for m in pkgutil.walk_packages(pp15.__path__, "pp15."))


def test_every_module_imports():
    failed, skipped = [], []
    for name in module_names():
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as e:
            if e.name in OPTIONAL:
                skipped.append((name, OPTIONAL[e.name]))
            else:
                failed.append((name, repr(e)))
        except Exception as e:
            failed.append((name, repr(e)))
    for name, package in skipped:
        print("skipped %s (needs %s)" % (name, package))
    assert not failed, failed


def test_every_style_is_registered():
    from pp15.art import typeset
    styles = [m for m in module_names() if m.startswith("pp15.art.styles.") and not m.endswith(".common")]
    assert len(styles) == 37 and len(typeset.RENDER) == 25665, (len(styles), len(typeset.RENDER))


if __name__ == "__main__":
    test_every_module_imports()
    test_every_style_is_registered()
    print("all %d modules import" % len(module_names()))
