#!/usr/bin/env python3
"""lab_secret (manual 3.1.5.3, decision 2.1.1.99.2): the lab passwords on the build VM. Generated once into an
owner-only file (folder 0700, file 0600), reused after, a wider mode tightened; refused when the folder or file is a
link or not a plain folder or file. Real files in a temporary folder; the passwords are never printed."""
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "scripts", "lab", "seeds"))
from lab_secret import lab_password  # noqa: E402

FAILED = 0
PASSED = 0


def check(name, cond, detail=""):
    global FAILED, PASSED
    FAILED += not cond
    PASSED += bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def refused(path):
    """The SystemExit message lab_password raised, or None when it returned."""
    try:
        lab_password(path)
    except SystemExit as e:
        return str(e)
    return None


if not hasattr(os, "getuid"):
    print("SKIP lab_secret: needs a POSIX system (it runs on the build VM)")
    sys.exit(0)

with tempfile.TemporaryDirectory() as tmp:
    lab = os.path.join(tmp, "fabric-lab")
    path = os.path.join(lab, "windows-admin.txt")
    first = lab_password(path)
    check("a password is generated: 20 characters, every class Windows asks for",
          len(first) == 20 and any(c.islower() for c in first) and any(c.isupper() for c in first)
          and any(c.isdigit() for c in first) and any(c in "-_.+=" for c in first))
    check("its folder is 0700 and its file 0600", mode(lab) == 0o700 and mode(path) == 0o600,
          f"{mode(lab):o} {mode(path):o}")
    check("a second run reuses it", lab_password(path) == first)

    os.chmod(path, 0o644)
    os.chmod(lab, 0o755)
    check("a wider mode is tightened, and the password kept",
          lab_password(path) == first and mode(lab) == 0o700 and mode(path) == 0o600,
          f"{mode(lab):o} {mode(path):o}")

    other = os.path.join(lab, "pve-root.txt")
    check("a second name gets its own password", lab_password(other) != first)

    target = os.path.join(tmp, "elsewhere.txt")
    with open(target, "w") as f:
        f.write("x\n")
    link = os.path.join(lab, "linked.txt")
    os.symlink(target, link)
    msg = refused(link)
    check("a password file that is a link is refused, saying why", msg is not None and "not a plain file" in msg,
          msg)

    os.mkdir(os.path.join(lab, "a-folder.txt"))
    msg = refused(os.path.join(lab, "a-folder.txt"))
    check("a password path that is a folder is refused, saying why", msg is not None and "not a plain file" in msg,
          msg)

    real = os.path.join(tmp, "real-lab")
    os.mkdir(real, 0o700)
    linked_lab = os.path.join(tmp, "linked-lab")
    os.symlink(real, linked_lab)
    msg = refused(os.path.join(linked_lab, "windows-admin.txt"))
    check("a passwords folder that is a link is refused, and nothing is written in it",
          msg is not None and "not a plain folder" in msg and os.listdir(real) == [], msg)

print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
