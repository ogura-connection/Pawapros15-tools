"""Put English lettering into the picture files (.arc) of the Pawapuro 15 menus.

Most menu and screen lettering of the game is painted into pictures, not stored as text, so translating it means
redrawing it. The tools here read those pictures, draw English words in matching styles and write the pages back.
Start with pp15/art/spec_cli.py (the `pp15 art` commands) or the README of the repository.

Reading the files
  arc_banks.py     the symbols of an .arc: texture pages, palettes, sprite part tables ("banks")
  page_codec.py    decoding and encoding one 128x128 page (raw and packed)
  gx_pixels.py     the Wii's tiled index data and RGB5A3 colours
  textures.py      page images, import/export, the `pp15 textures` command, and the names the others import
  original_arc.py  the untouched Japanese files, for styles that copy a piece of the old art

Drawing words
  labels.py            cutting lettering out of MLB label sheets and fitting it into a space
  lettering_fonts.py   letter shapes: the MLB command font, the tag font, system TrueType fonts
  lettering_styles.py  recipes for outlines, shadows, plates and gradients (factories)
  named_styles.py      the named styles built from them; pp15/art/styles/ holds the styles of each screen
  style_registry.py    the style / font tables, filled when first read
  typeset.py           typeset(text, font) -> ink; the entry point of the lettering tool
  pixel_ops.py         grow / shift of pixel masks

Putting words on pages
  repack.py        lay words out again on a page and re-point the sprites
  sheet.py         lettering in a picture cut over several pages
  strips.py        names in a text atlas used by sprites of another file
  spec_io.py       read a spec (specs/*.json)
  spec_render.py   draw a whole spec onto the pages of its .arc
  spec_cli.py      `pp15 art` / `apply-art` / `restore-art`
"""
