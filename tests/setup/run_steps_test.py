"""run_steps (decision 2.1.2.26, manual 1.3.2.3.3): the step loop shared by the unit, a run in the session and
--step; with a run record it is kept after each step (done, the step running, the services to restart), before deploy
the settings are saved to fabric.yaml, and the end is recorded. The steps are stubbed.
    python3 tests/setup/run_steps_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import yaml  # noqa: E402

import fabriclib.setup.run_steps as rs  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


rs.print_first_steps = lambda ctx, guided=False: print(f"first steps (guided={guided})")
ran, saved = [], []


def step(name, effect=None):
    def run(ctx):
        ran.append(name)
        if effect:
            effect(ctx)
    return (name, run, name)


def deploy(ctx):
    ctx.restart_services.add("bind9")
    with open(ctx.vars_file, "w") as f:
        yaml.safe_dump({"rendered": True}, f)


def join(ctx):
    ctx.vars["org_domain"] = "org.test"


def fails(ctx):
    raise SetupError("the CA did not answer")


def new_ctx(d):
    ctx = SetupContext(deploy_base=d)
    os.makedirs(ctx.config_dir, exist_ok=True)
    ctx.vars = {"domain": "lan.test"}
    return ctx


def save(record):
    saved.append({k: (list(v) if isinstance(v, list) else v) for k, v in record.items()})


STEPS = [step("preflight"), step("join", join), step("deploy", deploy), step("certs"), step("start"),
         step("ready")]
NAMES = [n for n, _, _ in STEPS]

with tempfile.TemporaryDirectory() as d:
    ctx, record = new_ctx(d), {"id": "r1", "state": "running", "done": [], "options": {}}
    code = rs.run_steps(ctx, STEPS, NAMES, guided=True, record=record, save=save)
    check("every selected step runs in order, the run ends done (0)", code == 0 and ran == NAMES
          and record["state"] == "done" and record["result"] == 0 and record["done"] == NAMES, (code, ran, record))
    check("the record is saved with the step running before each step and with it done after",
          [s.get("current") for s in saved[:2]] == ["preflight", "preflight"] and saved[1]["done"] == ["preflight"],
          saved[:3])
    check("before deploy the settings are kept in fabric.yaml (the join step's too), so a resume starts from them",
          yaml.safe_load(open(os.path.join(ctx.config_dir, "fabric.yaml"))).get("org_domain") == "org.test")
    check("after deploy the rendered vars are loaded, and the services to restart are recorded",
          ctx.vars == {"rendered": True} and record["restart_services"] == ["bind9"], (ctx.vars, record))

ran.clear()
saved.clear()
with tempfile.TemporaryDirectory() as d:
    ctx = new_ctx(d)
    steps = [step("preflight"), step("deploy", deploy), ("certs", fails, "certs"), step("start")]
    record = {"id": "r2", "state": "running", "done": [], "options": {}}
    code = rs.run_steps(ctx, steps, [n for n, _, _ in steps], record=record, save=save)
    check("negative: a step's SetupError stops the run: exit 1, recorded failed at that step, the steps before it "
          "done, none after it run", code == 1 and record["state"] == "failed" and record["current"] == "certs"
          and record["done"] == ["preflight", "deploy"] and "start" not in ran, (code, record, ran))

ran.clear()
with tempfile.TemporaryDirectory() as d:
    ctx = new_ctx(d)
    with open(ctx.vars_file, "w") as f:
        yaml.safe_dump({"rendered": True}, f)
    ctx.restart_services = {"bind9"}
    record = {"id": "r3", "state": "running", "done": ["preflight", "join", "deploy"], "options": {}}
    code = rs.run_steps(ctx, STEPS, ["certs", "start", "ready"], record=record, save=save)
    check("a resumed run runs only the steps left, keeps the services still to restart, and writes no fabric.yaml "
          "(deploy is behind it)", code == 0 and ran == ["certs", "start", "ready"]
          and record["restart_services"] == ["bind9"]
          and not os.path.exists(os.path.join(ctx.config_dir, "fabric.yaml")), (ran, record))


def interrupted(ctx):
    raise KeyboardInterrupt


def broken(ctx):
    raise RuntimeError("a bug")


with tempfile.TemporaryDirectory() as d:
    record = {"id": "r4", "state": "running", "done": [], "options": {}}
    code = rs.run_steps(new_ctx(d), [("start", interrupted, "start")], ["start"], record=record, save=save)
    check("negative: interrupted: exit 130, recorded failed with 130", code == 130 and record["result"] == 130, record)
    record = {"id": "r5", "state": "running", "done": [], "options": {}}
    try:
        rs.run_steps(new_ctx(d), [("start", broken, "start")], ["start"], record=record, save=save)
        check("negative: an unexpected error propagates (a traceback), the run recorded failed first", False)
    except RuntimeError:
        check("negative: an unexpected error propagates (a traceback), the run recorded failed first",
              record["state"] == "failed" and record["result"] == 1, record)

ran.clear()
saved.clear()
with tempfile.TemporaryDirectory() as d:
    ctx = new_ctx(d)
    code = rs.run_steps(ctx, STEPS, ["certs"])
    check("a --step run (no record) runs just that step and records nothing", code == 0 and ran == ["certs"]
          and not saved and not os.path.exists(os.path.join(ctx.config_dir, "setup-run.yaml")), (ran, saved))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
