"""run_setup's routing of a full run (decision 2.1.2.26): with fabric-setup.service running it only follows it; with
an unfinished run it resumes; --restart, --file and --join start over; --worker runs only the recorded run; --step
stays in the session. The unit and the units it calls are stubbed.
    python3 tests/setup/run_setup_test.py"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.run_setup as rsu  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


def quiet(fn):
    saved = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = io.StringIO()
    try:
        return fn(), sys.stdout.getvalue()
    finally:
        sys.stdout, sys.stderr = saved


class Asked(Exception):
    """the questions started"""


def no_questions(ctx):
    raise Asked()


rsu.choose_mode = no_questions
calls = []
rsu.follow_run = lambda config_dir: calls.append(("follow", config_dir)) or 7
rsu.resume_run = lambda ctx, steps, last, remaining, join=None: calls.append(("resume", remaining)) or 5

with tempfile.TemporaryDirectory() as d:
    config = os.path.join(d, "fabric", "config")
    write_run(config, {"id": "r1", "state": "failed", "done": ["preflight", "host"], "current": "docker"})
    rsu.unit_running = lambda: True
    code, out = quiet(lambda: rsu.main(["--deploy-base", d, "--file", "x.yaml"]))
    check("the unit running: setup only follows it (no questions), its result the exit status, saying options are "
          "not used", code == 7 and calls[-1] == ("follow", config) and "already running" in out, (code, calls, out))
    rsu.unit_running = lambda: False
    code, out = quiet(lambda: rsu.main(["--deploy-base", d]))
    check("an unfinished run and no unit: resumed from its first unfinished step, no questions",
          code == 5 and calls[-1][0] == "resume" and calls[-1][1][0] == "docker", (code, calls))
    for args, why in ((["--restart"], "--restart"), (["--file", os.path.join(d, "none.yaml")], "--file"),
                      (["--join", "@" + os.path.join(d, "missing")], "--join")):
        calls.clear()
        try:
            code, out = quiet(lambda: rsu.main(["--deploy-base", d, *args]))
            started_over = code == 1 and "cannot read the invitation" in out   # --join reads its file first
        except Asked:
            started_over = True
        check(f"negative: {why} starts over (the questions) instead of resuming", started_over and not calls,
              (calls, why))
    write_run(config, {"id": "r1", "state": "done", "done": []})
    try:
        quiet(lambda: rsu.main(["--deploy-base", d]))
        check("negative: a finished run is not resumed: the questions, as before", False)
    except Asked:
        check("negative: a finished run is not resumed: the questions, as before", not calls, calls)
    code, out = quiet(lambda: rsu.main(["--deploy-base", d, "--worker", "not-the-run"]))
    check("negative: --worker with a run that is not the one recorded as running: exit 1, nothing run",
          code == 1 and "nothing to do" in out, (code, out))
    ran = []
    rsu.run_steps = lambda ctx, steps, selected, guided=False: ran.append(selected) or 0
    rsu.ask_consent = lambda *a, **k: {}
    rsu.plan_host_changes = lambda *a, **k: {}
    rsu.ufw_active = lambda: False
    write_run(config, {"id": "r2", "state": "failed", "done": []})
    code, out = quiet(lambda: rsu.main(["--deploy-base", d, "--step", "certs", "--non-interactive"]))
    check("--step stays in the session and never resumes or follows: just that step", code == 0 and ran == [["certs"]]
          and not calls, (code, ran, calls, out))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
