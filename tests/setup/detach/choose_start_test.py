"""choose_start (decision 2.1.2.26, manual 1.3.2.3.3): a full setup follows the running unit, resumes an unfinished
run from its first unfinished step, or starts anew. Pure.
    python3 tests/setup/detach/choose_start_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.choose_start import choose_start  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


STEPS = ["preflight", "host", "deploy", "certs", "start", "ready"]
failed = {"id": "r1", "state": "failed", "done": ["preflight", "host", "deploy"], "current": "certs"}

got = choose_start(True, failed, STEPS, start_over=True)
check("the unit still running: follow it, whatever else is given (no questions, no new run)", got == ("attach", []), got)
got = choose_start(False, failed, STEPS)
check("a failed run: resume from the first step not done", got == ("resume", ["certs", "start", "ready"]), got)
got = choose_start(False, {**failed, "state": "running"}, STEPS)
check("a run recorded as running with no unit (its process died, the host restarted): resume",
      got == ("resume", ["certs", "start", "ready"]), got)
got = choose_start(False, {**failed, "done": ["preflight", "deploy"]}, STEPS)
check("the steps left follow STEPS' order, so one a newer release added is not skipped",
      got == ("resume", ["host", "certs", "start", "ready"]), got)
got = choose_start(False, failed, STEPS, start_over=True)
check("negative: --restart, --file or --join start over though the run did not finish", got == ("new", STEPS), got)
got = choose_start(False, {**failed, "state": "done"}, STEPS)
check("negative: a finished run is not resumed: setup behaves as before (a new run)", got == ("new", STEPS), got)
got = choose_start(False, None, STEPS)
check("negative: no record (a first install): a new run", got == ("new", STEPS), got)
got = choose_start(False, {**failed, "done": STEPS}, STEPS)
check("negative: every step done though not marked done: nothing to resume, a new run", got == ("new", STEPS), got)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
