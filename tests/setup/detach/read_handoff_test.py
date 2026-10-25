"""read_handoff (manual 1.3.2.3.4): the unit reads the handed-over secrets once, removing the file, and refuses one
that is not a 0600 regular file of the expected owner (root in the unit; here the uid running the suite).
    python3 tests/setup/detach/read_handoff_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.read_handoff import read_handoff  # noqa: E402
from fabriclib.setup.detach.write_handoff import write_handoff  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0
ME = os.getuid()


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def refused(path, owner=ME):
    try:
        read_handoff(path, owner)
        return None
    except SetupError as e:
        return str(e)


with tempfile.TemporaryDirectory() as d:
    path = write_handoff("r1", {"admin_password": "Good-Pass-1234", "join_invitation": "fabric-join-1.abc"}, d)
    got = read_handoff(path, ME)
    check("the secrets are read", got == {"admin_password": "Good-Pass-1234", "join_invitation": "fabric-join-1.abc"},
          got)
    check("…and the file is gone once read", not os.path.exists(path))
    msg = refused(path)
    check("negative: read a second time (the run started already): refused, saying to run setup again",
          msg and "sudo fabricctl setup" in msg, msg)
    path = write_handoff("r2", {"admin_password": "x"}, d)
    os.chmod(path, 0o644)
    msg = refused(path)
    check("negative: a file others can read is refused, and removed",
          msg and "0600" in msg and not os.path.exists(path), msg)
    path = write_handoff("r3", {"admin_password": "x"}, d)
    msg = refused(path, owner=ME + 1)
    check("negative: a file of another owner is refused, and removed", msg and not os.path.exists(path), msg)
    target = write_handoff("r4", {"admin_password": "x"}, d)
    link = os.path.join(d, "setup-r5.handoff")
    os.symlink(target, link)
    msg = refused(link)
    check("negative: a symlink is refused (not followed), the link removed, its target left",
          msg and not os.path.lexists(link) and os.path.exists(target), msg)
    bad = os.path.join(d, "setup-r6.handoff")
    fd = os.open(bad, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"- not\n- a mapping\n")
    os.close(fd)
    msg = refused(bad)
    check("negative: content that is not the secrets mapping is refused, and removed",
          msg and not os.path.exists(bad), msg)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
