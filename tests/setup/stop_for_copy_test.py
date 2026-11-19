"""The stop before a cold copy (2.3.1.53; setup/stop_for_copy, used by a cold backup bundle, 1.3.7.4): it returns only
once the stack has really stopped; a container still running, or Docker not answering, refuses, so there is no copy.
Pure logic: systemd and Docker stood in for. The sandbox runs the real one, and restores from its bundle.
    python3 tests/setup/stop_for_copy_test.py"""
import os
import subprocess
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.stop_for_copy as sfc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def run_stop(ps_replies, ps_rc=0, stop_error=None):
    """stop_for_copy on a stood-in host, then "copy" when it returned: docker ps says each of ps_replies in turn, then
    the last: (steps, error)."""
    steps, replies = [], list(ps_replies)

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "ps"]:
            steps.append("ps")
            out = replies.pop(0) if len(replies) > 1 else replies[0]
            return subprocess.CompletedProcess(cmd, ps_rc, stdout=out, stderr="no docker" if ps_rc else "")
        if cmd[0] == "systemctl":
            steps.append("timers" if "fabric-grants.timer" in cmd else "systemctl")
        return subprocess.CompletedProcess(cmd, 0, stdout="1K\tx\n", stderr="")

    def fake_stop(verb):
        steps.append(f"stack {verb}")
        if stop_error:
            raise ValidationError(stop_error)
        return []

    sfc.subprocess = SimpleNamespace(run=fake_run)
    sfc.control_stack = fake_stop
    sfc.STOP_WAIT = 2
    sfc.time = SimpleNamespace(time=real_time.time, sleep=lambda s: real_time.sleep(0.01), strftime=real_time.strftime)
    sfc.DIRS = ("postgres",)
    try:
        sfc.stop_for_copy("/opt")
        steps.append("cp")
        error = ""
    except ValidationError as exc:
        error = str(exc)
    return steps, error


real_time = sfc.time
steps, error = run_stop([""])
check("a stack that has stopped: timers first, every unit, Docker asked, then the copy", not error
      and steps.index("timers") < steps.index("stack stop") < steps.index("ps") < steps.index("cp"), (steps, error))


# what the probe measured: the stop returns, Postgres still running; the copy waits for it to be gone
sfc._real_still = sfc._still_running
ps = {"n": 0}


def stopping(base):
    ps["n"] += 1
    return ["postgres"] if ps["n"] < 3 else []


sfc._still_running = stopping
steps, error = run_stop([""])
check("Postgres still going down when the stop returns: the copy waits until it is gone", not error and ps["n"] == 3 and "cp" in steps, (ps, steps, error))
sfc._still_running = lambda base: ["postgres"]
steps, error = run_stop([""])
check("negative: a container still running after the wait: refused, naming it, nothing copied",
      "postgres still running" in error and "cp" not in steps, (steps, error))
sfc._still_running = sfc._real_still
steps, error = run_stop([""], ps_rc=1)
check("negative: Docker cannot say what runs: refused, nothing copied", "could not ask Docker" in error and "cp" not in steps, (steps, error))
steps, error = run_stop([""], stop_error="systemctl stop fabric.target failed: x")
check("negative: the stop itself failed: refused, nothing copied", "stop fabric.target failed" in error and "cp" not in steps, (steps, error))

# whose containers: this install's alone, by the folder Compose records


def listing(out):
    sfc.subprocess = SimpleNamespace(run=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=""))
    return sfc._still_running("/opt")


check("this install's containers are counted, by Compose's folder", listing("postgres\t/opt/postgres\n") == ["postgres"])
check("negative: another project, in the same base or not, and a plain container are not",
      listing("mine\t/opt/mine\nrecords-db\t/srv/records\nplain\t\n") == [])
print("all passed" if not FAILED else f"FAILED ({FAILED})")
sys.exit(1 if FAILED else 0)
