"""The export's stop (2.3.1.53): nothing is copied until the stack has really stopped; a container still running, or Docker not
answering, refuses with no copy; a copy that fails says so instead of a traceback. Pure logic: systemd, Docker and cp stood in
for. The sandbox runs the real one, and restores from it.
    python3 tests/setup/export_install_test.py"""
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.export_install as ei  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def run_export(ps_replies, cp_rc=0, ps_rc=0, stop_error=None):
    """export_install on a stood-in host: docker ps says each of ps_replies in turn, then the last: (steps, error)."""
    steps, replies = [], list(ps_replies)

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "ps"]:
            steps.append("ps")
            out = replies.pop(0) if len(replies) > 1 else replies[0]
            return subprocess.CompletedProcess(cmd, ps_rc, stdout=out, stderr="no docker" if ps_rc else "")
        if cmd[0] == "cp":
            steps.append("cp")
            return subprocess.CompletedProcess(cmd, cp_rc, stdout="", stderr="cannot stat postmaster.pid" if cp_rc else "")
        if cmd[0] == "systemctl":
            steps.append("timers" if "fabric-grants.timer" in cmd else "systemctl")
        return subprocess.CompletedProcess(cmd, 0, stdout="1K\tx\n", stderr="")

    def fake_stop(verb):
        steps.append(f"stack {verb}")
        if stop_error:
            raise ValidationError(stop_error)
        return []

    ei.subprocess = SimpleNamespace(run=fake_run)
    ei.control_stack = fake_stop
    ei.secrets_in_openbao = lambda f: False
    ei.STOP_WAIT = 2
    ei.time = SimpleNamespace(time=real_time.time, sleep=lambda s: real_time.sleep(0.01), strftime=real_time.strftime)
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "opt")
        os.makedirs(os.path.join(base, "postgres"))
        ei.DIRS = ("postgres",)
        ctx = SimpleNamespace(vars={}, secrets_file="", deploy_base=base, path=lambda n: os.path.join(base, n))
        os_chown, os.chown = os.chown, lambda *a: None
        try:
            ei.export_install(ctx, os.path.join(d, "export"))
            error = ""
        except ValidationError as exc:
            error = str(exc)
        finally:
            os.chown = os_chown
    return steps, error


real_time = ei.time
steps, error = run_export([""])
check("a stack that has stopped: timers first, every unit, Docker asked, then the copy", not error
      and steps.index("timers") < steps.index("stack stop") < steps.index("ps") < steps.index("cp"), (steps, error))


# what the probe measured: the stop returns, Postgres still running; the copy waits for it to be gone
ei._real_still = ei._still_running
ps = {"n": 0}


def stopping(base):
    ps["n"] += 1
    return ["postgres"] if ps["n"] < 3 else []


ei._still_running = stopping
steps, error = run_export([""])
check("Postgres still going down when the stop returns: the copy waits until it is gone", not error and ps["n"] == 3 and "cp" in steps, (ps, steps, error))
ei._still_running = lambda base: ["postgres"]
steps, error = run_export([""])
check("negative: a container still running after the wait: refused, naming it, nothing copied",
      "postgres still running" in error and "cp" not in steps, (steps, error))
ei._still_running = ei._real_still
steps, error = run_export([""], ps_rc=1)
check("negative: Docker cannot say what runs: refused, nothing copied", "could not ask Docker" in error and "cp" not in steps, (steps, error))
steps, error = run_export([""], stop_error="systemctl stop fabric.target failed: x")
check("negative: the stop itself failed: refused, nothing copied", "stop fabric.target failed" in error and "cp" not in steps, (steps, error))
steps, error = run_export([""], cp_rc=1)
check("negative: a copy that fails: says what, that nothing was uninstalled, and what to do; no traceback",
      "could not copy" in error and "cannot stat" in error and "nothing was uninstalled" in error, (steps, error))

# whose containers: this install's alone, by the folder Compose records


def listing(out):
    ei.subprocess = SimpleNamespace(run=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=""))
    return ei._still_running("/opt")


check("this install's containers are counted, by Compose's folder", listing("postgres\t/opt/postgres\n") == ["postgres"])
check("negative: another project, in the same base or not, and a plain container are not",
      listing("mine\t/opt/mine\nrecords-db\t/srv/records\nplain\t\n") == [])
print("all passed" if not FAILED else f"FAILED ({FAILED})")
sys.exit(1 if FAILED else 0)
