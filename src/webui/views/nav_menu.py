from webui.views.constants import NAV


def nav_menu(perms, page, pending=None):
    """Purpose: The navigation down the left for one person on one page (manual 1.8.6.4): the entries they may see,
             each with the pages they may see, the entry of the page shown open.
    Inputs:  perms — set of the person's permissions; page — the path of the navigation page shown (None: none);
             pending — {page path: number of the person's pending changes there} (None: none), marked on each page.
    Returns: [{"id", "label", "href" (its first visible page), "open" (holds the page shown), "pending" (the sum of
             its pages'), "pages": [{"href", "label", "active", "pending"}]}]; an entry none of whose pages the
             person may see is left out.
    Fails:   never.
    Feeds:   render_page (the frame in base.html)."""
    pending = pending or {}
    out = []
    for entry, label, pages in NAV:
        shown = [{"href": href, "label": plabel, "active": href == page, "pending": int(pending.get(href) or 0)}
                 for href, plabel, need in pages if not need or any(p in perms for p in need)]
        if not shown:
            continue
        out.append({"id": entry, "label": label, "href": shown[0]["href"], "pages": shown,
                    "open": any(p["active"] for p in shown), "pending": sum(p["pending"] for p in shown)})
    return out
