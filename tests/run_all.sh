#!/bin/sh
# Every regression test of the repository, in the order of cost: imports, build round trip, golden output.
# Needs the game data (DATA/, _work/); see README.md. Run from anywhere.
set -e
cd "$(dirname "$0")/.."
echo "== imports";     python3 tests/test_imports.py
echo "== style registry"; python3 tests/test_registry.py
echo "== build unit tests"; python3 tests/test_build.py
echo "== build-check"; python3 -m pp15 build-check > /dev/null && echo "build-check passed"
echo "== golden";      python3 tests/golden.py check
echo "all tests passed"
