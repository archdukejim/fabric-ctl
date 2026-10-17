#!/usr/bin/env python3
"""The function reference's numbers are given once (manual 1.17.1.2, 5.7: never reused): scripts/docs/
lib_doc_registry.number_items refuses a registry that gives one number twice at one level (two pages, two files of
one page, two functions of one file), as a merge of two branches that each numbered a new item next can leave it,
and numbers a new item after the highest ever used. The repository's own registry is checked too. Pure logic.
    python3 tests/docs/lib_doc_registry_test.py"""
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "scripts", "docs"))
from lib_doc_registry import REGISTRY, number_items  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def run(lines, pages=None):
    with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False, encoding="utf-8") as f:
        f.write("".join(f"{line}\n" for line in lines))
    try:
        return number_items(pages or {}, "0.0.0 / test", path=f.name), None
    except ValueError as e:
        return None, str(e)
    finally:
        os.remove(f.name)


GOOD = ["page\tweb\t2\t", "page\tlib\t3\t", "file\tweb|a.py\t1\t", "file\tweb|b.py\t2\t", "file\tlib|a.py\t1\t",
        "function\tweb|a.py|f\t1\t", "function\tweb|b.py|f\t1\t", "file\tweb|old.py (gone 0.1 / x)\t3\t0.1 / x"]
got, why = run(GOOD)
check("a registry with each number once at its level is read (the same number on other levels is fine)",
      why is None, why)
got, why = run(GOOD, {"web": {"a.py": ["f"], "b.py": ["f"], "c.py": ["g"]}, "lib": {"a.py": []}})
check("a new file is numbered after the highest ever used on its page, a removed one's included",
      why is None and got[0][("file", "web|c.py")] == (4, ""), (why, got and got[0]))

got, why = run(GOOD + ["file\tweb|c.py\t2\t"])
check("negative: two files of one page with one number: refused, naming both and saying how to fix it",
      why and "file 2 given to web|b.py and web|c.py" in why and "Delete the later-added item's row" in why, why)
got, why = run(GOOD + ["function\tweb|a.py|g\t1\t"])
check("negative: two functions of one file with one number: refused", why and "function 1 given to" in why, why)
got, why = run(GOOD + ["page\tother\t3\t"])
check("negative: two pages with one number: refused", why and "page 3 given to lib and other" in why, why)
got, why = run(GOOD + ["file\tweb|new.py\t3\t"])
check("negative: a removed item's number given again: refused (never reused)", why and "file 3 given to" in why, why)

try:
    number_items({}, "0.0.0 / test", path=REGISTRY)
    why = None
except ValueError as e:
    why = str(e)
check("the repository's registry (scripts/docs/lib_doc_numbers.tsv) gives every number once", why is None, why)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
