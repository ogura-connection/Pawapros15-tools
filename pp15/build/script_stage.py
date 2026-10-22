"""Build stage: write every story script out again with its English text.

What it is for: the first thing the build does with the translation is lay out the scripts, because everything else
(pointers, memory plan, name tables behind them) depends on where the text ends up. Three kinds of script exist:
  - the four Success Mode scripts (scs_main.rel, scs_sce1/2/3.rel): the section grows and the data behind moves;
  - "block" scripts of other modes (Eikan Nine, ...): laid out again inside the bytes they already have;
  - the My Life script: laid out again in place, the pieces that do not fit go to an annex in ore_work.rel.

Public functions:
    lay_out_scripts(state, pad)   fill state.remaps, state.new_secs, state.inplace, state.block_data, state.ores
"""
import sys

from pp15.build.memory_plan import ORE_WORK_ADDR
from pp15.build.ore_script import emit_ore
from pp15.build.script_emit import SECTION_ALIGN, Remap, emit_block, emit_script
from pp15.script import scan


def _lay_out_my_life(state, script, replacements: dict) -> None:
    """The My Life script: stretches in place, overflow into the annex behind the data of ore_work.rel."""
    host = next(m for m in state.orig.values() if m.name == scan.ORE_ANNEX_MODULE)
    section, data_end = script.spec["annex_section"], script.spec["annex_from"]
    if host.sections[section]["size"] != data_end or data_end % SECTION_ALIGN:
        sys.exit("%s: its data section is not the %d bytes the annex expects" % (host.name, data_end))
    base = ORE_WORK_ADDR + host.sections[section]["offset"] + data_end + len(state.annexes) + 8
    segs, annex, remap, (kept, room) = emit_ore(script, replacements, base,
                                                script.spec.get("annex_magic", scan.ORE_ANNEX_MAGIC))
    state.ores.append({"sc": script, "segs": segs, "remap": remap, "annex": annex, "host": host})
    state.annexes += annex
    if state.annexes:
        state.remaps[(host.mod_id, section)] = Remap(data_end // 2, data_end // 2, {}, len(state.annexes))
        state.new_secs[host.mod_id] = (section, host.sec_data(section) + state.annexes)
    print("%-13s %5d runs replaced, %d pieces stay in place (%d bytes left there), %d bytes go to the "
          "annex in %s" % (script.rel.name, len(replacements), kept, room, len(annex), host.name))


def _lay_out_block(state, script, replacements: dict) -> None:
    """A block script laid out again inside its own bytes."""
    data, remap, room = emit_block(script, replacements)
    state.inplace[(script.rel.mod_id, script.sec)] = remap
    state.block_data[script.rel.mod_id] = (script.sec, script.region[0], data)
    print("%-13s %5d runs replaced, script laid out again in its 0x%X bytes (%d bytes left)"
          % (script.rel.name, len(replacements), len(data), room))


def lay_out_scripts(state, pad: dict | None = None) -> None:
    """Write out again every script that has English text (or an extra `pad` of empty bytes, a test option).

    `pad` = {module name: extra zero bytes} for the memory-headroom tests of `pp15 build --pad`.
    """
    for script in state.blocks:
        replacements = state.repl.get(script.rel.name, {})
        if not replacements:
            continue
        if script.spec.get("engine") == "ore":
            _lay_out_my_life(state, script, replacements)
        else:
            _lay_out_block(state, script, replacements)
    for script in state.scripts:
        replacements = state.repl.get(script.rel.name, {})
        extra = (pad or {}).get(script.rel.name, 0)
        if not replacements and not extra:
            continue
        data, remap = emit_script(script, replacements, extra)
        state.remaps[(script.rel.mod_id, script.sec)] = remap
        state.new_secs[script.rel.mod_id] = (script.sec, data)
        print("%-13s %5d runs replaced, script section 0x%X -> 0x%X bytes (data behind it moves %+d)"
              % (script.rel.name, len(replacements), script.rel.sections[script.sec]["size"], len(data), remap.growth))
