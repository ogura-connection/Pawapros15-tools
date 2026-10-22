"""Registry identity test: `typeset.RENDER` must keep the same style names, each with the same style.

    python3 tests/test_registry.py record     write tests/render_registry.json from the current code
    python3 tests/test_registry.py             compare the current code with it (also collected by pytest)

A style is a function (usually a closure made by a helper such as `banded` or `ringfill`). Its fingerprint is a SHA-1 of
its byte code, constants, default arguments, closure cell contents and the module-level values it reads, so it does not
depend on the module the style lives in, on line numbers or on file names. `no_duplicate_keys` checks that no two style
modules define the same name (a later module used to override an earlier one, in file-name order).
"""
import dis
import hashlib
import importlib
import json
import os
import pkgutil
import re
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
REGISTRY = os.path.join(ROOT, "tests", "render_registry.json")
FONT_REGISTRY = os.path.join(ROOT, "tests", "font_registry.json")
# Styles whose code was edited on purpose after the registry was recorded (name -> new fingerprint): the ones that used
# to read the original .arc through helper scripts in the scratch folder _work, and now use pp15/art/original_arc.py.
CHANGES = os.path.join(ROOT, "tests", "render_registry_changes.json")
MIN_STYLES = 25575


def _clean(text):
    return re.sub(r" at 0x[0-9a-f]+", "", text)


def _global_names(code):
    """The names a code object (and the code objects inside it) reads from module level."""
    names = set()
    todo = [code]
    while todo:
        c = todo.pop()
        for ins in dis.get_instructions(c):
            if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME"):
                names.add(ins.argval)
        todo.extend(k for k in c.co_consts if isinstance(k, types.CodeType))
    return names


def _strings(o, out, depth=0):
    """Every string inside o (strings, containers of strings): the keys a style might look up in STYLES."""
    if isinstance(o, str):
        out.add(o)
    elif depth < 4 and isinstance(o, (list, tuple, set, frozenset)):
        for x in o:
            _strings(x, out, depth + 1)
    elif depth < 4 and isinstance(o, dict):
        for k, v in o.items():
            _strings(k, out, depth + 1)
            _strings(v, out, depth + 1)


def fingerprint(obj, stack=None, memo=None):
    """A string that identifies `obj` by what it does, not by where it lives.

    Module-level names that a function reads are part of its fingerprint, except the module's own STYLES dictionary: only
    the entries whose names occur in the function's closure or constants count (a style that reads STYLES[name] at call time)."""
    stack = [] if stack is None else stack
    memo = {} if memo is None else memo
    cut = [False]

    def fp(o):
        if isinstance(o, (type(None), bool, int, float, complex, str, bytes)):
            return repr(o)
        if isinstance(o, types.ModuleType):
            return "stylemodule" if ".styles" in o.__name__ or o.__name__.startswith("old_styles") else "module:" + o.__name__
        if isinstance(o, (list, tuple, set, frozenset, dict)) or hasattr(o, "tobytes"):
            if id(o) in memo:
                return memo[id(o)][1]
            if id(o) in stack:
                cut[0] = True
                return "cycle"
            stack.append(id(o))
            before = cut[0]
            cut[0] = False
            text = container(o)
            stack.pop()
            if not cut[0]:
                memo[id(o)] = (o, text)          # keeps o alive, so that its id cannot be reused
            cut[0] = cut[0] or before
            return text
        if isinstance(o, types.CodeType):
            return code_fp(o)
        return other(o)

    def code_fp(c):
        """The byte code as a list of instructions with the compiler's choices of calling convention (PUSH_NULL, the
        method-call form of LOAD_ATTR) and the jump offsets left out, so that moving a function to another module (where
        the import statements differ) does not change it."""
        ins = [i for i in dis.get_instructions(c, adaptive=False) if i.opname not in ("PUSH_NULL", "NOP", "CACHE")]
        index = {}
        for n, i in enumerate(ins):
            index[i.offset] = n
        ordered = sorted(index)
        def at(off):                     # index of the first kept instruction at or after a byte offset
            for o2 in ordered:
                if o2 >= off:
                    return index[o2]
            return len(ins)
        toks = []
        for i in ins:
            if i.opcode in dis.hasjump or i.opname.startswith("JUMP") or "JUMP" in i.opname or i.opname in ("FOR_ITER", "SEND", "END_ASYNC_FOR"):
                toks.append("%s>%d" % (i.opname, at(i.argval) if isinstance(i.argval, int) else -1))
            elif i.opname == "LOAD_CONST":
                toks.append("LOAD_CONST:" + fp(i.argval))
            elif isinstance(i.argval, types.CodeType):
                toks.append("%s:%s" % (i.opname, code_fp(i.argval)))
            else:
                rep = re.sub(r" \+ NULL(\|self)?$", "", i.argrepr)
                toks.append("%s:%s" % (i.opname, rep if i.argrepr else repr(i.argval)))
        table = []
        try:
            for e in dis._parse_exception_table(c):
                table.append("%d-%d>%d/%d/%s" % (at(e.start), at(e.end), at(e.target), e.depth, e.lasti))
        except Exception:
            table.append(c.co_exceptiontable.hex())
        consts = [x for x in c.co_consts if not isinstance(x, types.CodeType)]
        return "code(" + ",".join([c.co_name, str(c.co_argcount), str(c.co_flags), str(c.co_kwonlyargcount), fp(c.co_varnames),
                                   fp(c.co_freevars), fp(c.co_cellvars), fp(consts[:1]), ";".join(toks), "|".join(table)]) + ")"

    def container(o):
        if isinstance(o, (list, tuple, set, frozenset)):
            items = [fp(x) for x in o]
            if isinstance(o, (set, frozenset)):
                items.sort()
            return type(o).__name__ + "[" + ",".join(items) + "]"
        if isinstance(o, dict):
            return "dict{" + ",".join(sorted(fp(k) + ":" + fp(v) for k, v in o.items())) + "}"
        if hasattr(o, "tobytes") and hasattr(o, "shape"):                         # numpy array
            return "array%s%s:%s" % (o.shape, o.dtype, hashlib.sha1(o.tobytes()).hexdigest())
        raise TypeError

    def other(o):
        if isinstance(o, types.FunctionType):
            key = id(o)
            if key in memo:
                return memo[key][1]
            if key in stack:
                cut[0] = True
                return "cycle:" + o.__name__
            stack.append(key)
            before = cut[0]
            cut[0] = False
            code = o.__code__
            cells = []
            for cell in (o.__closure__ or ()):
                try:
                    cells.append(fp(cell.cell_contents))
                except ValueError:
                    cells.append("empty")
            used = {}
            wanted = set()
            for n in sorted(_global_names(code)):
                if n not in o.__globals__:
                    continue
                v = o.__globals__[n]
                if isinstance(v, dict) and n in ("STYLES", "S") and v is o.__globals__.get("STYLES"):
                    _strings([c.cell_contents for c in (o.__closure__ or ()) if _filled(c)], wanted)
                    _strings(code.co_consts, wanted)
                    _strings(o.__defaults__, wanted)
                    used[n] = "styles{" + ",".join(k + "=" + fp(v[k]) for k in sorted(wanted) if k in v) + "}"
                else:
                    used[n] = fp(v)
            text = "fn(" + ",".join([fp(code), fp(o.__defaults__), fp(o.__kwdefaults__), "cells[" + ",".join(cells) + "]",
                                     "globals{" + ",".join(n + "=" + v for n, v in used.items()) + "}"]) + ")"
            stack.pop()
            if not cut[0]:
                memo[key] = (o, text)
            cut[0] = cut[0] or before
            return text
        if isinstance(o, type):
            return "class:" + o.__module__.split(".")[0] + "." + o.__qualname__
        return type(o).__name__ + ":" + _clean(repr(o))

    return fp(obj)


def _filled(cell):
    try:
        cell.cell_contents
        return True
    except ValueError:
        return False


def current():
    """name -> SHA-1 fingerprint of every entry of typeset.RENDER."""
    from pp15.art import typeset
    memo = {}
    return {name: hashlib.sha1(fingerprint(style, memo=memo).encode()).hexdigest()
            for name, style in sorted(typeset.RENDER.items())}


def current_fonts():
    """The fonts the style modules register in typeset.TTF (name -> file) and typeset.FONTS (name -> fingerprint)."""
    from pp15.art import typeset
    memo = {}
    fonts = {name: hashlib.sha1(fingerprint(f, memo=memo).encode()).hexdigest()
             for name, f in sorted(typeset.FONTS.items())}
    ttf = {name: repr(v) for name, v in sorted(typeset.TTF.items())}
    return {"ttf": ttf, "fonts": fonts}


def style_modules():
    from pp15.art import typeset, styles            # typeset first: the style modules import it
    return sorted(m.name for m in pkgutil.iter_modules(styles.__path__))


def duplicate_keys():
    """name -> list of style modules that define it (only names defined more than once)."""
    from pp15.art import styles
    seen = {}
    for name in style_modules():
        module = importlib.import_module(styles.__name__ + "." + name)
        for key in getattr(module, "STYLES", {}):
            seen.setdefault(key, []).append(name)
    return {k: v for k, v in seen.items() if len(v) > 1}


def test_registry_unchanged():
    saved = json.load(open(REGISTRY))
    now = current()
    assert len(now) >= MIN_STYLES and len(saved) == len(now), (len(saved), len(now))
    assert set(saved) == set(now), (sorted(set(saved) - set(now))[:10], sorted(set(now) - set(saved))[:10])
    if os.path.exists(CHANGES):
        saved.update(json.load(open(CHANGES)))
    changed = sorted(k for k in saved if saved[k] != now[k])
    assert not changed, "%d styles differ, e.g. %s" % (len(changed), changed[:10])


def test_fonts_unchanged():
    saved = json.load(open(FONT_REGISTRY))
    now = current_fonts()
    for part in ("ttf", "fonts"):
        assert set(saved[part]) == set(now[part]), (part, sorted(set(saved[part]) ^ set(now[part]))[:10])
        changed = sorted(k for k in saved[part] if saved[part][k] != now[part][k])
        assert not changed, "%s differ: %s" % (part, changed[:10])


def test_no_duplicate_keys():
    dup = duplicate_keys()
    assert not dup, "%d style names defined twice, e.g. %s" % (len(dup), list(dup.items())[:5])


if __name__ == "__main__":
    if sys.argv[1:] == ["record"]:
        data = current()
        json.dump(data, open(REGISTRY, "w"), indent=0, sort_keys=True)
        print("recorded %d styles in %s" % (len(data), REGISTRY))
        fonts = current_fonts()
        json.dump(fonts, open(FONT_REGISTRY, "w"), indent=0, sort_keys=True)
        print("recorded %d TTF and %d font entries" % (len(fonts["ttf"]), len(fonts["fonts"])))
    else:
        test_registry_unchanged()
        print("registry unchanged")
        test_fonts_unchanged()
        print("fonts unchanged")
        test_no_duplicate_keys()
        print("no duplicate keys")
