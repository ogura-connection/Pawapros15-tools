"""Lets `python3 -m pp15 COMMAND` run the `pp15` command (see pp15/cli.py)."""
import sys

from pp15.cli import main

if __name__ == "__main__":
    sys.exit(main())
