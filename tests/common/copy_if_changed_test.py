"""One file installed by the deploy engine when its content differs (`common/copy_if_changed`): a missing or changed
file copied with its mode and reported, an unchanged one not; a same-size change within one mtime tick copied
(2.3.1.29: `filecmp.cmp`'s cache missed it). Real files in a temporary folder.
    python3 tests/common/copy_if_changed_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.copy_if_changed import copy_if_changed  # noqa: E402

PASS = FAIL = 0
UID, GID = os.getuid(), os.getgid()


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


with tempfile.TemporaryDirectory() as t:
    src, dst = os.path.join(t, "unit.service"), os.path.join(t, "installed.service")
    write(src, "ExecStart=a\n")
    check("positive: a missing file is installed, with its mode",
          copy_if_changed(src, dst, 0o644, UID, GID) and open(dst).read() == "ExecStart=a\n"
          and oct(os.stat(dst).st_mode & 0o777) == "0o644")
    check("negative: the same content again: not replaced", copy_if_changed(src, dst, 0o644, UID, GID) is False)
    before = os.stat(src)
    write(src, "ExecStart=b\n")
    os.utime(src, ns=(before.st_atime_ns, before.st_mtime_ns))
    check("positive: a same-size change in the same mtime tick is installed",
          copy_if_changed(src, dst, 0o644, UID, GID) and open(dst).read() == "ExecStart=b\n")
    os.utime(src, ns=(before.st_atime_ns + 5 * 10**9, before.st_mtime_ns + 5 * 10**9))
    check("negative: only the mtime moved: not replaced", copy_if_changed(src, dst, 0o644, UID, GID) is False)
    write(src, "ExecStart=longer\n")
    check("positive: a change of size is installed",
          copy_if_changed(src, dst, 0o600, UID, GID) and open(dst).read() == "ExecStart=longer\n"
          and oct(os.stat(dst).st_mode & 0o777) == "0o600")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
