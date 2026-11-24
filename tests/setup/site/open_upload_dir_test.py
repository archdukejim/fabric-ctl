#!/usr/bin/env python3
"""Restore from a backup's upload folder (setup/site/open_upload_dir, close_upload_dir; manual 1.3.6.7, 1.3.7.10): made
fresh, 0700 and given to the listener's uid inside a 0755 parent that need not exist yet; what an earlier site left is
removed; closing removes it with its contents and its parent when empty, and a planted link is removed, never followed.
The chown is stood in for (as root the listener's uid is 649: tests/setup/site/upload_test.py).

    python3 tests/setup/site/open_upload_dir_test.py
"""
import os
import stat
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.setup.site.close_upload_dir import close_upload_dir  # noqa: E402
from fabriclib.setup.site.open_upload_dir import open_upload_dir  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


top = tempfile.mkdtemp()
path = os.path.join(top, "fabric-setup", "upload")
owned = []
out = open_upload_dir(path, uid=649, chown=lambda p, u, g: owned.append((p, u, g)))
check("made with its parent, which did not exist: 0700, given to the listener's uid and gid",
      out == path and os.path.isdir(path) and owned == [(path, 649, 649)]
      and (os.name == "nt" or stat.S_IMODE(os.stat(path).st_mode) == 0o700), (owned, os.path.isdir(path)))
open(os.path.join(path, "fabric-x-20261122T030000Z-manual.fabric.tar"), "w").write("left by an earlier site")
open_upload_dir(path, uid=649, chown=lambda p, u, g: None)
check("opened again: what an earlier site left is gone", os.listdir(path) == [], os.listdir(path))
close_upload_dir(path)
check("closed: the folder and its empty parent gone", not os.path.exists(os.path.dirname(path)))
close_upload_dir(path)
check("closed twice: nothing to do, no error", not os.path.exists(path))
if hasattr(os, "symlink"):
    os.makedirs(os.path.dirname(path))
    target = os.path.join(top, "kept")
    os.makedirs(target)
    open(os.path.join(target, "a"), "w").close()
    try:
        os.symlink(target, path)
        linked = True
    except OSError:
        linked = False
    if linked:
        close_upload_dir(path)
        check("negative: a link in its place: the link removed, what it points at kept",
              not os.path.lexists(path) and os.path.exists(os.path.join(target, "a")))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
