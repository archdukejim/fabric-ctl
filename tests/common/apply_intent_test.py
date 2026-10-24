#!/usr/bin/env python3
"""The apply intent (decision 2.1.10.45, manual 1.10.4.42) on a real file lock, across real processes: applies and
the changes an apply follows hold it together; the plan poll can hold it alone only when none does, never waits for
it, and an apply waits only while the poll holds it.

    python3 tests/common/apply_intent_test.py
"""
import os
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.apply_intent import apply_intent  # noqa: E402
from fabriclib.common.try_apply_alone import try_apply_alone  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def holder(path, mode, seconds):
    """Another process holding the intent: "shared" (an apply) or "alone" (the poll), for some seconds."""
    code = ("import sys, time; sys.path.insert(0, sys.argv[1])\n"
            "from fabriclib.common.apply_intent import apply_intent\n"
            "from fabriclib.common.try_apply_alone import try_apply_alone\n"
            "if sys.argv[3] == 'shared':\n"
            "    with apply_intent(sys.argv[2]):\n"
            "        print('held', flush=True); time.sleep(float(sys.argv[4]))\n"
            "else:\n"
            "    lock = try_apply_alone(sys.argv[2]); print('held' if lock else 'none', flush=True)\n"
            "    time.sleep(float(sys.argv[4]))\n")
    proc = subprocess.Popen([sys.executable, "-c", code, os.path.join(REPO, "src"), path, mode, str(seconds)],
                            stdout=subprocess.PIPE, text=True)
    return proc, proc.stdout.readline().strip()


with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "config", ".apply.intent")
    lock = try_apply_alone(path)
    check("nothing holds the intent: the poll holds it alone (the folder made)", lock is not None
          and os.path.isfile(path), path)
    lock.close()
    proc, said = holder(path, "shared", 3)
    started = time.time()
    check("an apply in another process holds it: the poll cannot hold it alone, and does not wait",
          said == "held" and try_apply_alone(path) is None and time.time() - started < 1, said)
    with apply_intent(path):
        check("a second apply or change holds it beside the first at once (shared)", time.time() - started < 1)
    proc.wait()
    lock = try_apply_alone(path)
    check("once the apply's process ended, the poll holds it alone again", lock is not None)
    lock.close()
    proc = subprocess.Popen([sys.executable, "-c", "import os, sys, time; sys.path.insert(0, sys.argv[1])\n"
                             "from fabriclib.common.apply_intent import apply_intent\n"
                             "with apply_intent(sys.argv[2]):\n    print('held', flush=True); os._exit(9)",
                             os.path.join(REPO, "src"), path], stdout=subprocess.PIPE, text=True)
    proc.stdout.readline()
    proc.wait()
    lock = try_apply_alone(path)
    check("an apply that crashed leaves nothing stale: the lock went with its process", proc.returncode == 9
          and lock is not None)
    lock.close()
    proc, said = holder(path, "alone", 1.5)
    started = time.time()
    with apply_intent(path):
        waited = time.time() - started
    proc.wait()
    check("the poll holds it alone (rendering Kea): an apply waits for it, then goes on", said == "held"
          and 1.0 < waited < 5, (said, waited))
    try:
        with apply_intent(path):
            raise RuntimeError("the body failed")
    except RuntimeError:
        pass
    lock = try_apply_alone(path)
    check("a body that raises lets the intent go", lock is not None)
    lock.close()

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
