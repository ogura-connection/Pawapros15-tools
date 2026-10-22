"""The hand-found lists that steer how fixed-slot strings are found and translated (see pp15/text/strings.py).

Finding menu text in the game's data is mostly automatic, but a few dozen places need a human decision: a slot that may
borrow the cell behind it, a box whose line width the rule gets wrong, a table of numbers that only looks like text.
Those decisions are kept here as plain data, one list per kind. Every entry is identified by
(module file, section, offset): "section" is the index of the data section inside the module and "offset" the byte
position in it (docs/GLOSSARY.md, "REL"). Nothing in this file runs.

Also here: the constants of the dialog block in main.dol (the blue save prompts and system notices).
"""
import os

from pp15 import config

END = 0xFFFF            # closes a fixed-slot string
# Help texts of vs.rel (Exhibition menu, control setups): lines split by HELP_NL, closed by HELP_END (not 0xFFFF), a
# coloured first line allowed. English: "|" between lines, {c:...} for colour. Cells = units in front of HELP_END.
HELP_FILES = {"vs.rel", "gameplay.rel", "sct_card.rel", "sct_a_sy.rel"}   # also 0xFFFF strings with a HELP_NL inside
HELP_NL, HELP_END = 0x1FFE, 0x1FFF

# Slots that may also use the alignment cell behind their 0xFFFF (a glyph 0 that ends on a 4-byte boundary): the
# pitching / batting form names of main_prg.rel, whose English needs 9-10 letters, and the same kind of label slots in
# namein.rel and are_main.rel. The build moves the 0xFFFF one cell on.
WIDE_SLOTS = {("main_prg.rel", 5, o) for o in (
    150532, 150688, 150736, 150748, 151000, 151024, 151756, 151860, 151920, 152152, 152256, 152852, 152900, 152936,
    153040, 153052, 153076, 153192, 153216, 153328, 153512, 153536, 154288)}
WIDE_SLOTS |= {("namein.rel", 5, o) for o in (24344, 24356, 24888, 24900, 24912, 25256, 25264, 25272, 25304, 25316, 25500, 25512, 26196, 26208, 26220, 26232, 26252, 26656, 26668, 27020, 27028, 27056, 27088, 27100, 27112, 27120, 27128, 27136, 27148, 27216, 27228, 27240, 27252, 27288, 27300, 27408, 27420, 27432, 27444, 27628, 28088, 28100, 28148, 28224, 28236, 28248, 28260, 28320, 28340, 28360, 28380, 28400, 28420, 28440, 28544, 28560, 28656, 28668, 28680, 28864, 28876, 29024, 29032, 29056, 29068, 29280, 29292, 29304, 29568, 29580, 29656, 29872, 29884, 30040, 30048, 30080, 30092, 30104, 30116, 30128, 30160, 30172, 30184, 30196, 30360, 30372, 30428, 30440, 30452, 30568, 30792, 30804, 30984, 30996, 31024, 31096, 31776, 31784, 31952, 31964, 32112, 32124, 32200, 32212, 32240, 32252, 32264, 32276, 32288, 32308, 32328, 32340, 32352, 32364, 32376, 32516, 32592, 32604, 32616, 32628, 32728, 32740, 32936, 32948, 32968, 33376, 33388, 33412, 33424, 33436, 33540, 33552, 33664, 33880, 33892, 33904, 33916, 33928, 33940, 33952, 34000, 34012, 34048, 34060, 34072, 34084, 34320,)}
WIDE_SLOTS |= {("are_main.rel", 5, o) for o in (124256, 124268, 124800, 124812, 124824, 125168, 125176, 125184, 125216, 125228, 125412, 125424, 126108, 126120, 126132, 126144, 126164, 126568, 126580, 126932, 126940, 126968, 127000, 127012, 127024, 127032, 127040, 127048, 127060, 127128, 127140, 127152, 127164, 127200, 127212, 127320, 127332, 127344, 127356, 127540, 128000, 128012, 128060, 128136, 128148, 128160, 128172, 128232, 128252, 128272, 128292, 128312, 128332, 128352, 128456, 128472, 128568, 128580, 128592, 128776, 128788, 128936, 128944, 128968, 128980, 129192, 129204, 129216, 129480, 129492, 129568, 129784, 129796, 129952, 129960, 129992, 130004, 130016, 130028, 130040, 130072, 130084, 130096, 130108, 130272, 130284, 130340, 130352, 130364, 130480, 130704, 130716, 130896, 130908, 130936, 131008, 131688, 131696, 131864, 131876, 132024, 132036, 132112, 132124, 132152, 132164, 132176, 132188, 132200, 132220, 132240, 132252, 132264, 132276, 132288, 132428, 132504, 132516, 132528, 132540, 132640, 132652, 132848, 132860, 132880, 133288, 133300, 133324, 133336, 133348, 133452, 133464, 133576, 133792, 133804, 133816, 133828, 133840, 133852, 133864, 133912, 133924, 133960, 133972, 133984, 133996, 134232,)}
WIDE_SLOTS |= {("scs_rens.rel", 5, o) for o in (12376, 12396, 12404, 12412)}   # Success cast names

# Line width overrides. (file, cells of the slot) -> cells per line: verified in the game.
LINE_CELLS = {("scs_sys.rel", 36): 18, ("scs_titl.rel", 32): 16, ("scs_rens.rel", 28): 14,
              ("scs_main.rel", 51): 17, ("scs_main.rel", 33): 18, ("scs_main.rel", 44): 18}
# (file, section, offset) -> cells per line of one string, 0 = one line. For strings whose width the rule cannot know.
LINE_WIDTH = {("main_prg.rel", 5, 90372): 23}   # boot controller screen: 23 cells a line
TABLE_GAP = 64      # bytes between two strings of the same table, at most
NEAR = 8            # how many strings away a neighbour may be
MIN_WIDTH = 8       # padding that ends before this cell is not line padding
MAX_LINES = 4       # a slot that would need more lines is not a text box
# (file, section, offset as found) -> cells in front of the text that are other data. A module pointer into some of
# these slots points at the cell where the text really starts.
START_TRIM = {("scs_data.rel", 5, 106): 3, ("scs_data.rel", 5, 2148): 38,
              ("main_prg.rel", 5, 174930): 7, ("school_g.rel", 5, 162498): 3, ("scs_end.rel", 5, 918): 9,
              ("arr_chg.rel", 5, 2972): 2, ("pn_fa.rel", 5, 106): 3,
              ("sct_a_pd.rel", 5, 106): 3}      # the Eikan Nine player card's throwing hand, behind 3 cells of data
# tables of glyph numbers that look like strings but are not text (for example name-entry grids)
NOT_TEXT = {("scs_data.rel", 5, 1164), ("scs_data.rel", 5, 10002), ("scs_data.rel", 5, 17864),
            ("scs_data.rel", 5, 18946), ("scs_item.rel", 5, 1474), ("scs_item.rel", 5, 3822)}

# Blocks of strings that the build lays out again: "table" = section offset of the pointer table, "count" its
# entries, "max" = cells one entry may take (the schedule column holds about 15 before the game icon)
BLOCKS = {"scs_data.rel": [{"section": 5, "start": 22308, "end": 22752, "table": 22756, "count": 24, "max": 15}]}

# Strings of one character, which the search would not take for text: the month and week marks of the schedule's date
# column, and the position letters (pitcher, catcher, first base, ...) of the Eikan Nine player card.
SHORT_TEXT = {("scs_data.rel", 5, 13824), ("scs_data.rel", 5, 13828)} | \
    {("sct_a_pd.rel", 5, o) for o in range(184, 212, 4)}

# Strings that end a longer glyph run (a symbol table in front of them): their own slot from this offset to the 0xFFFF.
TAIL_SLOTS = {("sct_card.rel", 5, 3272)}                # a short label ending a symbol table (Eikan Nine command help)

# ── main.dol: the blue system dialogs ─────────────────────────────────────
DOL = "main.dol"
DOL_SHA1 = "cd096d3bbfb5418316dad6e3035cba34a028f718"     # of the untouched file; strings are only read from that
DOL_SOURCE = os.path.join(config.DATA_SYS, DOL)
DOL_ORIG = os.path.join(config.ORIG_SYS_DIR, DOL)
DOL_BLOCK = (0x143AA0, 0x145ACE)    # file offsets of the dialog strings, end exclusive
DOL_ADDRESS = 0x80003F00            # memory address minus file offset in that part of main.dol
DOL_GLYPH, DOL_CTRL = 0x1000, 0x1FFD    # a dialog unit is 0x1000 | glyph number; 0x1FFD is the blank "{}" cell
DOL_STRINGS = 264                   # number of strings in the block
DOL_OVER = 3                        # cells a line may be longer than its Japanese without a warning
