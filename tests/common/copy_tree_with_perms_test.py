"""A tree copied by the deploy engine (`common/copy_tree_with_perms`): new and changed files copied and reported,
unchanged ones not; Python's bytecode caches never copied nor counted (2.3.10.11.16: a `.pyc` a host process wrote
into fabric's code rebuilt and restarted the web console at the next apply). Real files in a temporary folder.
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
    check("positive: copied again unchanged: not reported", copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755)
          is False)
    write(f"{src}/app/__pycache__/oidc.cpython-312.pyc", "bytecode")
    write(f"{src}/app/stray.pyc", "bytecode")
    changed = copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755)
    check("negative: bytecode caches written into the source are not copied and not a change",
          changed is False and not os.path.exists(f"{dst}/app/__pycache__")
          and not os.path.exists(f"{dst}/app/stray.pyc"), changed)
    write(f"{src}/app/oidc.py", "x = 2\n")
    check("positive: a changed file is copied and reported, with its mode",
          copy_tree_with_perms(src, dst, UID, GID, 0o644, 0o755) and open(f"{dst}/app/oidc.py").read() == "x = 2\n"
          and oct(os.stat(f"{dst}/app/oidc.py").st_mode & 0o777) == "0o644")
    # 2.3.10.11.19: a same-size rewrite inside one mtime tick, made deterministic by setting the old mtime back.
    before = os.stat(f"{src}/app/oidc.py")
    check("positive: copied again unchanged (caches the files' signatures)",
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
