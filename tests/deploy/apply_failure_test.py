"""What a job says when its apply did not finish (decision 2.1.8.31): the apply's last 10 lines, where its last line
alone ("Error deploying configurations! Exit code 1") hid the cause, and the full output kept in a root-only log
whose path the message names; and a page's Apply (agent/post_pending) raising it as its job's error.
Pure: the logs go to a temporary folder, the apply itself is stood in for (the sandbox runs real applies).
    python3 tests/deploy/apply_failure_test.py"""
import datetime
import os
import stat
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.system.apply_changes as ac  # noqa: E402
import fabriclib.system.apply_failure as af  # noqa: E402
from agent.post_pending import _finish  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


OUTPUT = "\n".join(f"line {n}" for n in range(1, 31)) + "\nTraceback: the cause\nError deploying configurations! Exit code 1"
at = datetime.datetime(2026, 10, 24, 12, 0, 0, tzinfo=datetime.timezone.utc)

with tempfile.TemporaryDirectory() as d:
    logs = os.path.join(d, "apply-failed")
    msg = af.apply_failure(OUTPUT, log_dir=logs, now=at)
    lines = msg.splitlines()
    check("positive: the error keeps the apply's last 10 lines, the cause among them, not only its last",
          lines[0] == "the apply did not finish:" and lines[1:11] == OUTPUT.splitlines()[-10:]
          and "Traceback: the cause" in msg and "line 22" not in msg, msg)
    path = os.path.join(logs, "apply-20261024T120000.000000Z.log")
    check("positive: the error names the log of the full output", lines[-1] == f"(the full output: {path})", msg)
    with open(path) as f:
        kept = f.read()
    check("positive: the log holds the full output", kept == OUTPUT + "\n", kept[:200])
    check("positive: root-only: the log 0600 in a 0700 folder",
          stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(logs).st_mode) == 0o700,
          (oct(os.stat(path).st_mode), oct(os.stat(logs).st_mode)))

    for n in range(25):
        af.apply_failure("boom", log_dir=logs, now=at + datetime.timedelta(seconds=n + 1))
    kept = sorted(os.listdir(logs))
    check("negative: no more than the newest 20 logs are kept", len(kept) == af.KEEP
          and kept[0] == "apply-20261024T120006.000000Z.log" and kept[-1] == "apply-20261024T120025.000000Z.log", kept)

    check("negative: an apply that printed nothing says so and names no log",
          af.apply_failure("  \n", log_dir=os.path.join(d, "none")) == "the apply did not finish (it printed nothing)"
          and not os.path.exists(os.path.join(d, "none")))

    blocker = os.path.join(d, "a-file")
    open(blocker, "w").close()
    msg = af.apply_failure(OUTPUT, log_dir=os.path.join(blocker, "logs"), now=at)
    check("negative: a log that cannot be written is said, the tail still kept",
          "(the full output could not be kept:" in msg and "Traceback: the cause" in msg
          and "(the full output: " not in msg, msg)

    # a page's Apply: the password policy's finish raises the tail as its job's error
    af_default = af.apply_failure.__defaults__
    af.apply_failure.__defaults__ = (logs, None)
    what, write = _finish("policies", [("domain", "password-policy")])
    ac.apply_changes = lambda actor, source="cli": (False, OUTPUT)
    try:
        write("alice")
        why = ""
    except ValidationError as e:
        why = str(e)
    check("negative: a page's Apply whose apply fails: its job's error has the last 10 lines and the log",
          "Traceback: the cause" in why and "(the full output: " + logs in why, why)
    ac.apply_changes = lambda actor, source="cli": (True, OUTPUT)
    try:
        write("alice")
        why = ""
    except ValidationError as e:
        why = str(e)
    check("positive: a page's Apply whose apply finishes raises nothing", why == "", why)
    af.apply_failure.__defaults__ = af_default
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
