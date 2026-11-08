#!/usr/bin/env python3
"""Draw the pictures of web-guided setup's finish (manual 1.3.6.6, decision 2.1.8.47: fabric's own drawings, not OS
screenshots, so they do not go out of date when an OS changes its screens and carry no vendor's artwork). Each is three
plain panels. A change to a picture is made here and the files regenerated.

    python3 scripts/docs/draw_setup_site.py        write static/setup-site/*.svg
"""
import html
import os

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(REPO, "static", "setup-site")
CERT, STORE, BROWSER, NAMES, RULE, SERVER = "cert", "store", "browser", "names", "rule", "server"
TRUST = (("You have", CERT), ("It goes in", STORE), ("Your browser", BROWSER))
DNS = (("You ask for", NAMES), ("A rule says", RULE), ("It answers", SERVER))
PICTURES = {
    "trust-windows": (TRUST, ("root-ca.cer", "from the host"), ("Trusted Root", "Local Machine store"), ("trusts fabric:", "no warning")),  # noqa: E501
    "trust-macos": (TRUST, ("root-ca.crt", "from the host"), ("System keychain", "Always Trust"), ("trusts fabric:", "no warning")),  # noqa: E501
    "trust-ubuntu": (TRUST, ("root-ca.crt", "from the host"), ("ca-certificates", "update-ca-certificates"), ("trusts fabric:", "no warning")),  # noqa: E501
    "dns-windows": (DNS, ("names under", "your domain"), ("a resolution rule", "Add-DnsClientNrptRule"), ("fabric's DNS", "the rest as before")),  # noqa: E501
    "dns-macos": (DNS, ("names under", "your domain"), ("a resolver file", "/etc/resolver/<domain>"), ("fabric's DNS", "the rest as before")),  # noqa: E501
    "dns-ubuntu": (DNS, ("names under", "your domain"), ("systemd-resolved", "Domains=~<domain>"), ("fabric's DNS", "the rest as before")),  # noqa: E501
}
INK, BLUE = "#7f8a9b", "#2f7de1"
ICONS = {
    CERT: f'<rect x="-22" y="-16" width="44" height="32" rx="3" fill="none" stroke="{INK}" stroke-width="2"/>'
          f'<path d="M-14 -6 h20 M-14 2 h14" stroke="{INK}" stroke-width="2"/><circle cx="12" cy="8" r="6" fill="{BLUE}"/>',  # noqa: E501
    STORE: f'<path d="M0 -20 L18 -12 V2 C18 12 8 18 0 21 C-8 18 -18 12 -18 2 V-12 Z" fill="none" stroke="{BLUE}" stroke-width="2"/>'  # noqa: E501
           f'<path d="M-8 0 l6 7 l11 -13" fill="none" stroke="{BLUE}" stroke-width="3"/>',
    BROWSER: f'<rect x="-26" y="-18" width="52" height="36" rx="3" fill="none" stroke="{INK}" stroke-width="2"/>'
             f'<path d="M-26 -8 h52" stroke="{INK}" stroke-width="2"/><path d="M-9 5 l6 6 l12 -13" fill="none" stroke="{BLUE}" stroke-width="3"/>',  # noqa: E501
    NAMES: f'<circle r="20" fill="none" stroke="{INK}" stroke-width="2"/><ellipse rx="9" ry="20" fill="none" stroke="{INK}" stroke-width="2"/>'  # noqa: E501
           f'<path d="M-20 0 h40" stroke="{INK}" stroke-width="2"/>',
    RULE: f'<path d="M0 -20 L20 0 L0 20 L-20 0 Z" fill="none" stroke="{BLUE}" stroke-width="2"/><path d="M-9 0 h14 m-5 -6 l6 6 l-6 6" fill="none" stroke="{BLUE}" stroke-width="2"/>',  # noqa: E501
    SERVER: f'<rect x="-22" y="-18" width="44" height="15" rx="2" fill="none" stroke="{INK}" stroke-width="2"/>'
            f'<rect x="-22" y="3" width="44" height="15" rx="2" fill="none" stroke="{INK}" stroke-width="2"/>'
            f'<circle cx="-13" cy="-10" r="2.5" fill="{BLUE}"/><circle cx="-13" cy="11" r="2.5" fill="{BLUE}"/>',
}


def panel(x, title, icon, lines):
    """Purpose: one panel of a picture: a heading, a small drawing, two lines of words.
    Inputs:  x — left edge; title — str; icon — key of ICONS; lines — two str.
    Returns: str, SVG.
    Fails:   never.
    Feeds:   picture."""
    words = "".join(f'<text x="{x + 92}" y="{y}" text-anchor="middle" font-size="13">{html.escape(t)}</text>'
                    for y, t in zip((142, 160), lines))
    return (f'<rect x="{x}" y="8" width="184" height="170" rx="8" fill="none" stroke="{INK}" stroke-width="1.5"/>'
            f'<text x="{x + 92}" y="32" text-anchor="middle" font-size="14" font-weight="600">{html.escape(title)}</text>'  # noqa: E501
            f'<g transform="translate({x + 92} 84)">{ICONS[icon]}</g>' + words)


def arrow(x):
    """Purpose: the arrow between two panels.
    Inputs:  x — where it starts.
    Returns: str, SVG.
    Fails:   never.
    Feeds:   picture."""
    return (f'<path d="M{x} 93 h10" stroke="{BLUE}" stroke-width="3"/>'
            f'<path d="M{x + 10} 86 l9 7 l-9 7 z" fill="{BLUE}"/>')


def picture(heads, first, second, third):
    """Purpose: one whole picture.
    Inputs:  heads — three (title, icon); first, second, third — each panel's two lines.
    Returns: str, the SVG file.
    Fails:   never.
    Feeds:   main."""
    panels = [panel(x, h[0], h[1], words) for x, h, words in zip((6, 228, 450), heads, (first, second, third))]
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 186" width="640" height="186" '
            'font-family="sans-serif" fill="#6b7686" role="img">\n'
            + panels[0] + arrow(197) + panels[1] + arrow(419) + panels[2] + "\n</svg>\n")


def main():
    """Purpose: write every picture.
    Inputs:  none.
    Returns: 0.
    Fails:   OSError.
    Feeds:   by hand, when a picture changes."""
    for name, parts in PICTURES.items():
        with open(os.path.join(OUT, f"{name}.svg"), "w", encoding="utf-8", newline="\n") as f:
            f.write(picture(*parts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
