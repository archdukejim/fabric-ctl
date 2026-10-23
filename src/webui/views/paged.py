from webui.views.constants import PER_PAGE


def paged(rows, keys, query):
    """Purpose: A long list's search and paging (manual 1.8.6.3): the rows holding every word of the search in any of
             the given columns, and the page of them asked for.
    Inputs:  rows — list of dicts; keys — the columns searched; query — dict: q (the search), page (1-based; past the
             end shows the last, not a number the first).
    Returns: {"rows": the page's rows, "total": rows matched, "at": the page shown, "pages": how many, "search": the
             search as shown (lower case, words joined by one space)}; PER_PAGE rows a page.
    Fails:   never.
    Feeds:   people, groups."""
    words = str(query.get("q") or "").lower().split()
    found = [r for r in rows if all(w in " ".join(str(r.get(k) or "") for k in keys).lower() for w in words)]
    pages = max(1, -(-len(found) // PER_PAGE))
    try:
        at = min(max(1, int(query.get("page") or 1)), pages)
    except ValueError:
        at = 1
    return {"rows": found[(at - 1) * PER_PAGE:at * PER_PAGE], "total": len(found), "at": at,
            "pages": pages, "search": " ".join(words)}
