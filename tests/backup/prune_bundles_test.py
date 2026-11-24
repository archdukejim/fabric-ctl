#!/usr/bin/env python3
"""Keeping the newest scheduled bundles (backup/prune_bundles, list_bundles; manual 1.3.7.5): files in a temporary
folder.

    python3 tests/backup/prune_bundles_test.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.list_bundles import list_bundles  # noqa: E402
from fabriclib.backup.prune_bundles import prune_bundles  # noqa: E402

FAILED = 0


def check(name, got, want):
    global FAILED
    FAILED += got != want
    print(("PASS " if got == want else "FAIL ") + name + ("" if got == want else f"  -> {got!r}"))


tmp = tempfile.mkdtemp()
names = [f"fabric-h-2026111{d}T030000Z-scheduled.fabric.tar" for d in range(1, 10)]
names += ["fabric-h-20261101T120000Z-manual.fabric.tar", "fabric-h-20261102T120000Z-uninstall.fabric.tar",
          "notes.txt"]
for n in names:
    with open(os.path.join(tmp, n), "w") as f:
        f.write("x")
rows = list_bundles(tmp)
check("positive: the bundles are listed newest first, other files left out",
      [r["file"] for r in rows][:2], [names[8], names[7]])
check("negative: a file named as a bundle but not one is listed with its error", bool(rows[0]["error"]), True)
removed = prune_bundles(7, tmp)
check("positive: the two oldest scheduled bundles are removed", sorted(removed), sorted(names[:2]))
left = sorted(os.listdir(tmp))
check("negative: bundles made by hand or at uninstall are never removed",
      {"fabric-h-20261101T120000Z-manual.fabric.tar", "fabric-h-20261102T120000Z-uninstall.fabric.tar"} <= set(left),
      True)
check("positive: a second run removes nothing", prune_bundles(7, tmp), [])
try:
    prune_bundles(0, tmp)
    check("negative: keep 0 is refused", False, True)
except ValueError:
    check("negative: keep 0 is refused", True, True)
check("negative: a missing folder lists nothing", list_bundles(os.path.join(tmp, "none")), [])
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
