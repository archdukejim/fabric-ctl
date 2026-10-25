"""A tree copied by the deploy engine (`common/copy_tree_with_perms`): new and changed files copied and reported,
unchanged ones not; a same-size change within one mtime tick copied (2.3.1.29: `filecmp.cmp`'s cache missed it).
Real files in a temporary folder.
    python3 tests/common/copy_tree_with_perms_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.copy_tree_with_perms import copy_tree_with_perms  # noqa: E402

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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


with tempfile.TemporaryDirectory() as t:
    src, dst = os.path.join(t, "src"), os.path.join(t, "dst")
    write(f"{src}/app/oidc.py", "x = 1\n")
    write(f"{src}/app/README.md", "web\n")
    check("positive: a new tree is copied and reported changed",
          copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755) and os.path.exists(f"{dst}/app/oidc.py"))
    check("negative: copied again unchanged: not reported", copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755)
          is False)
    write(f"{src}/app/oidc.py", "x = 2\n")
    check("positive: a changed file is copied and reported, with its mode",
          copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755) and open(f"{dst}/app/oidc.py").read() == "x = 2\n"
          and oct(os.stat(f"{dst}/app/oidc.py").st_mode & 0o777) == "0o644")
    # 2.3.1.29: a same-size rewrite inside one mtime tick, made deterministic by setting the old mtime back
    before = os.stat(f"{src}/app/oidc.py")
    check("negative: copied again unchanged (filecmp would have cached the files' signatures)",
          copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755) is False)
    write(f"{src}/app/oidc.py", "x = 3\n")
    os.utime(f"{src}/app/oidc.py", ns=(before.st_atime_ns, before.st_mtime_ns))
    check("positive: a same-size change in the same mtime tick is copied and reported",
          copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755) and open(f"{dst}/app/oidc.py").read() == "x = 3\n")
    os.utime(f"{src}/app/README.md", ns=(before.st_atime_ns + 5 * 10**9, before.st_mtime_ns + 5 * 10**9))
    check("negative: only the mtime moved, the content is the same: not copied, not reported",
          copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755) is False)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
