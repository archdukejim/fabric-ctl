"""The numbers of the function reference (manual 1.17.1.2): given once, never reused."""
import os

from product_code import REPO

REGISTRY = os.path.join(REPO, "scripts", "docs", "lib_doc_numbers.tsv")
FIRST_PAGE = 2                      # 1.17.1 is the hand-written chapter about the reference
HEADER = "# fabric: numbers of the function reference (manual 1.17.1.2). Written by gen_lib_doc.py; never edit.\n"


def _duplicates(rows):
    """Purpose: every number given twice at one level (two pages, two files of one page, two functions of one file),
             as two branches merged together, each numbering a new item next, can leave it.
    Inputs:  rows — {(kind, key): (number, removed)} as number_items reads them.
    Returns: list of str, one per clash, naming the number and its items (empty: none).
    Fails:   never.
    Feeds:   number_items."""
    seen = {}
    for (kind, key), (num, _) in rows.items():
        scope = "" if kind == "page" else key.rsplit("|", 1)[0]
        seen.setdefault((kind, scope, num), []).append(key)
    return [f"{kind} {num} given to {' and '.join(sorted(keys))}"
            for (kind, _, num), keys in sorted(seen.items()) if len(keys) > 1]


def number_items(pages, removed_on, path=REGISTRY):
    """Purpose: give every page, file and function of the reference its number, keeping every number ever given.
    Inputs:  pages — {page: {source path: [function qualname, ...]}} as the code is now; removed_on — the text a
             removal note carries ("<version> / <date>") for items found gone now; path — the registry file
             (tab-separated: kind, key, number, removed; kinds page, file, function).
    Returns: (rows, text): rows — {(kind, key): (number, removed or "")} for everything ever numbered, with new
             items numbered after the highest number ever used at their level and missing ones marked removed;
             text — the registry file's new content.
    Fails:   OSError / ValueError if the registry exists but cannot be read or parsed; ValueError if it gives one
             number twice at one level (a merge of two branches: delete the later-added item's row and run
             gen_lib_doc.py again, which gives it the next free number).
    Feeds:   gen_lib_doc.main."""
    rows = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            kind, key, num, removed = (line.rstrip("\n").split("\t") + [""])[:4]
            rows[(kind, key)] = (int(num), removed)
    clashes = _duplicates(rows)
    if clashes:
        raise ValueError(f"{path} gives a number twice (manual 1.17.1.2: never reused): " + "; ".join(clashes)
                         + ". Delete the later-added item's row and run scripts/docs/gen_lib_doc.py again")

    def give(kind, key, siblings_prefix):
        if (kind, key) in rows:
            num, removed = rows[(kind, key)]
            if removed:                                   # a returning item gets a new number (5.7: no reuse)
                del rows[(kind, key)]
                rows[(kind, f"{key} (gone {removed})")] = (num, removed)
            else:
                return
        used = [n for (k, kk), (n, _) in rows.items() if k == kind and kk.startswith(siblings_prefix)]
        start = FIRST_PAGE if kind == "page" else 1
        rows[(kind, key)] = (max(used + [start - 1]) + 1, "")

    present = set()
    for page in sorted(pages):
        give("page", page, "")
        present.add(("page", page))
        for src in sorted(pages[page]):
            fkey = f"{page}|{src}"
            give("file", fkey, f"{page}|")
            present.add(("file", fkey))
            for qual in pages[page][src]:
                key = f"{fkey}|{qual}"
                give("function", key, f"{fkey}|")
                present.add(("function", key))
    for key, (num, removed) in list(rows.items()):
        if key not in present and not removed:
            rows[key] = (num, removed_on)
    text = HEADER + "".join(f"{k}\t{kk}\t{n}\t{r}\n" for (k, kk), (n, r) in
                            sorted(rows.items(), key=lambda x: (x[0][0], x[0][1])))
    return rows, text
