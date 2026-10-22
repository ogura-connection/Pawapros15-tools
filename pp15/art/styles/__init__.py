"""The lettering styles, one module per screen or game mode.

Each module has a dict STYLES = {style name: style}; pp15/art/typeset.py imports every module of this folder and merges
the dicts into typeset.RENDER. No style name is defined twice (tests/test_registry.py checks this). common.py holds the
drawing helpers that several modules share. docs/styles_map.md says which module covers which sprite files.
"""
