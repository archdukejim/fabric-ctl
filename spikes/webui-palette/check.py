"""Purpose: measure every colour pair the console draws, for each palette in palettes.css, against WCAG 2.2 AA
(manual 2.3.8.4): 4.5:1 for text, 3:1 for the parts of controls and graphics (1.4.11). Spike tool (global Rule 4).
Usage: python3 spikes/webui-palette/check.py [--table]   (exit 1 when a palette other than "today" fails a pair)"""
import re
import sys
from pathlib import Path

# (foreground, background, minimum, what it is in the console)
PAIRS = [
    ("text", "bg", 4.5, "body text on the page"),
    ("text", "surface", 4.5, "body text in a card"),
    ("text", "surface-2", 4.5, "text on a hovered row, the active nav page"),
    ("muted", "surface", 4.5, "secondary text in a card"),
    ("muted", "bg", 4.5, "secondary text on the page"),
    ("muted", "surface-2", 4.5, "secondary text on a hovered row"),
    ("accent", "surface", 4.5, "a link in a card"),
    ("accent", "bg", 4.5, "a link on the page"),
    ("accent", "accent-soft", 4.5, "the active tab or step"),
    ("on-accent", "accent", 4.5, "a primary button's label"),
    ("on-accent", "accent-hover", 4.5, "a primary button's label, hovered"),
    ("ok", "surface", 4.5, "ok text"),
    ("warn", "surface", 4.5, "warning text"),
    ("bad", "surface", 4.5, "error text"),
    ("ok", "ok-soft", 4.5, "ok notice"),
    ("warn", "warn-soft", 4.5, "warning notice"),
    ("bad", "bad-soft", 4.5, "error notice"),
    ("text", "warn-soft", 4.5, "body text in a warning notice"),
    ("on-banner", "banner", 4.5, "the dev preview banner"),
    ("border-strong", "surface", 3.0, "a field's or button's edge in a card"),
    ("border-strong", "bg", 3.0, "a field's edge on the page"),
    ("focus", "surface", 3.0, "the focus ring in a card"),
    ("focus", "bg", 3.0, "the focus ring on the page"),
    ("ok", "surface", 3.0, "a green status light"),
    ("warn", "surface", 3.0, "an amber status light"),
    ("bad", "surface", 3.0, "a red status light"),
    ("seg-gateway", "surface", 3.0, "address bar: gateway"),
    ("seg-static", "surface", 3.0, "address bar: static"),
    ("seg-dhcp", "surface", 3.0, "address bar: DHCP pool"),
    ("seg-reserved", "surface", 3.0, "address bar: reserved"),
    ("chart-queries", "surface", 3.0, "hours chart: queries"),
    ("chart-blocked", "surface", 3.0, "hours chart: blocked"),
]


def luminance(hex_colour):
    """Return the relative luminance of #rrggbb (WCAG 2.2)."""
    h = hex_colour.lstrip("#")
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a, b):
    """Return the contrast ratio of two #rrggbb colours."""
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def palettes(css):
    """Return {(palette, theme): {token: #hex}} from palettes.css; a dark block inherits its light block's tokens."""
    out = {}
    for sel, body in re.findall(r'(\[data-palette="[^"]+"\](?:\[data-theme="dark"\])?)\{([^}]*)\}', css):
        name = re.search(r'data-palette="([^"]+)"', sel).group(1)
        theme = "dark" if "dark" in sel else "light"
        tokens = dict(out.get((name, "light"), {}))
        tokens.update(dict(re.findall(r"--([\w-]+):(#[0-9a-fA-F]{6})", body)))
        out[(name, theme)] = tokens
    return out


def main():
    """Print each palette's lowest pairs and failures; exit 1 when a candidate fails."""
    found = palettes(Path(__file__).with_name("palettes.css").read_text())
    failed = False
    for (name, theme), t in found.items():
        rows = [(fg, bg, need, what, ratio(t[fg], t[bg])) for fg, bg, need, what in PAIRS]
        bad = [r for r in rows if r[4] < r[2]]
        if bad and name != "today":
            failed = True
        print(f"{name} {theme}: {len(rows) - len(bad)}/{len(rows)} pass")
        if "--table" in sys.argv:
            for fg, bg, need, what, r in rows:
                print(f"  {'ok  ' if r >= need else 'FAIL'} {r:5.2f} (>= {need}) {fg} on {bg}: {what}")
        else:
            for fg, bg, need, what, r in bad:
                print(f"  FAIL {r:5.2f} (>= {need}) {fg} on {bg}: {what}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
