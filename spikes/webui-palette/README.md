# spikes/webui-palette

The console's clean-up and colours for 0.9.1 (global Rule 4 spike; manual 2.3.8.4): three candidate palettes, each
light and dark, drawn on static mockups of three real pages with the layout fixes of the audit applied. Throwaway:
the owner picks a palette, then the winner's tokens and the layout rules move into `static/webui-app/app.css` and the
templates, built from the manual.

| File | What |
|---|---|
| `index.html` | Open it: the mockups with a switcher (palette, light/dark/both, page, desktop/phone width) and the measured contrast. Self-contained, nothing fetched. Generated: do not edit |
| `mockups.src.html` | The source of `index.html`: the settings page, the DNS filter's overview and the Overview's health, as the clean-up would draw them |
| `palettes.css` | The palettes as CSS custom properties: today's (for the baseline), A Harbor, B Graphite, C Sandstone. The winner's light block becomes `:root`, its dark block the `prefers-color-scheme: dark` `:root` |
| `mockup.css` | The stylesheet as the clean-up would leave it, drawn only from the tokens |
| `check.py` | Every colour pair the console draws, measured against WCAG 2.2 AA (4.5:1 text, 3:1 edges, focus, lights, charts); `--table` prints each |
| `build.py` | Writes `index.html` from `mockups.src.html` with the two stylesheets inlined |

```bash
python3 spikes/webui-palette/check.py --table
python3 spikes/webui-palette/build.py
```

**Outcome (2026-10-31):** the owner picked **C, Sandstone**, light and dark both (decision 2.1.8.34; manual
2.3.8.4.7). It is built in 0.9.1 (2.1.1.72, manual 1.8.8.6). A Harbor and B Graphite stay here for reference.
