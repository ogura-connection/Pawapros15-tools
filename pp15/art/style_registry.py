"""The tables of styles and fonts, filled on first use instead of when the program starts.

The lettering tool has three lookup tables that the style modules of pp15/art/styles/ add to:
  RENDER   style name -> style function (25,575 entries once everything is loaded)
  FONTS    font name -> font function
  TTF      font name -> (font file, face index) for system fonts
Importing the 32 style modules takes about half a second, and most runs (a unit test, `pp15 art boxes`) never look up a
style. So these tables are `OnDemandDict`s: the first time one is read, every module in pp15/art/styles/ is imported
(in file-name order) and the dictionary `STYLES` of each is merged into RENDER; the modules register their own fonts in
FONTS and TTF while they are imported.

Writing to a table does not load anything, so a style module can register a font while it is being imported without
loading itself again. Reading from inside the loading (a style module looking up another style) works as usual.

  OnDemandDict            a dict that calls load_style_modules() before it is first read
  load_style_modules()    import the style modules once; safe to call again
  RENDER                  the style table, starting with the base styles of pp15/art/named_styles.py
"""
import importlib
import pkgutil

from pp15.art.named_styles import BASE_STYLES

_state = {"done": False, "running": False}      # loading finished? loading in progress (reads then pass straight through)?


class OnDemandDict(dict):
    """A dict that loads the style modules before it is first read (see the module docstring)."""


def _read_method(name: str):
    """A copy of the dict method `name` that makes sure the style modules are loaded first."""
    plain = getattr(dict, name)

    def method(self, *args, **kwargs):
        load_style_modules()
        return plain(self, *args, **kwargs)
    method.__name__ = name
    method.__doc__ = "dict.%s, after loading the style modules" % name
    return method


# Reads load the tables; writes (__setitem__, update, ...) do not, so that a style module can register a font while it
# is being imported. setdefault and update also read nothing the module could depend on.
for _name in ("__getitem__", "__contains__", "__iter__", "__len__", "__repr__", "__eq__", "__ne__", "get", "keys",
              "values", "items", "copy", "pop", "popitem"):
    setattr(OnDemandDict, _name, _read_method(_name))

RENDER = OnDemandDict(BASE_STYLES)


def load_style_modules() -> None:
    """Import every module of pp15/art/styles/ and merge its STYLES into RENDER, once.

    A module that is still being imported higher up the call stack (someone imported it directly and it read a table
    during its own import) is skipped; it is merged by the next call, after it has finished."""
    if _state["done"] or _state["running"]:
        return
    _state["running"] = True
    try:
        from pp15.art import styles            # the folder; imported here because the style modules import typeset
        complete = True
        for info in sorted(pkgutil.iter_modules(styles.__path__), key=lambda m: m.name):
            module = importlib.import_module(styles.__name__ + "." + info.name)
            if getattr(getattr(module, "__spec__", None), "_initializing", False):
                complete = False
                continue
            dict.update(RENDER, getattr(module, "STYLES", {}))
        _state["done"] = complete
    finally:
        _state["running"] = False
