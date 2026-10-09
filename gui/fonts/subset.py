"""Rebuild the bundled font subsets.

Inputs are the upstream variable fonts from github.com/google/fonts (SIL OFL 1.1):
  ofl/inter/Inter[opsz,wght].ttf
  ofl/jetbrainsmono/JetBrainsMono[wght].ttf

Usage (needs fontTools):  python subset.py <Inter.ttf> <JetBrainsMono.ttf> <outdir>

Each face is instanced to a static weight, stripped of hinting, and subset to
Latin + Latin-1 + Latin Extended-A + Cyrillic + common punctuation/symbols.
Only the GPOS 'kern' feature is kept (oos-ui reads pair kerning from GPOS).
"""
import sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools import subset

UNICODES = (
    list(range(0x20, 0x7F)) +          # ASCII
    list(range(0xA0, 0x100)) +         # Latin-1
    list(range(0x100, 0x180)) +        # Latin Extended-A
    list(range(0x400, 0x460)) +        # Cyrillic
    [0x490, 0x491] +                   # Ґ ґ
    list(range(0x2010, 0x2028)) +      # dashes, quotes, bullet, ellipsis
    list(range(0x2030, 0x203B)) +      # per mille, guillemets
    [0x20AC, 0x20BD, 0x2116, 0x2122, 0x2212, 0x00D7, 0x2026] +
    list(range(0x2190, 0x2196)) +      # arrows
    [0x2713, 0x2715, 0x2318, 0x21E7, 0x2325, 0x25B2, 0x25B6, 0x25BC, 0x25C0, 0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518, 0x2588]
)

def build(src, axes, out):
    f = TTFont(src)
    f = instancer.instantiateVariableFont(f, axes, updateFontNames=False)
    opts = subset.Options()
    opts.layout_features = ["kern"]
    opts.hinting = False
    opts.name_IDs = [0, 1, 2, 3, 4, 5, 6, 13, 14]
    opts.notdef_outline = True
    opts.glyph_names = False
    opts.drop_tables += ["STAT", "DSIG", "meta", "MVAR", "HVAR", "GDEF"]
    s = subset.Subsetter(opts)
    s.populate(unicodes=UNICODES)
    s.subset(f)
    f.save(out)

if __name__ == "__main__":
    inter, mono, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    build(inter, {"wght": 400, "opsz": 14}, outdir + "/Inter-Regular.ttf")
    build(inter, {"wght": 600, "opsz": 14}, outdir + "/Inter-SemiBold.ttf")
    build(mono, {"wght": 400}, outdir + "/JetBrainsMono-Regular.ttf")
