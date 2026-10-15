"""run_worker (decision 2.1.2.26, manual 1.3.2.3): `setup --worker <run>` inside the unit runs the recorded run's
steps not yet done, with the settings the questions saved and the secrets they handed over, and nothing for a run that
is not the one recorded as running. The steps are stubbed.
    python3 tests/setup/detach/run_worker_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
import yaml  # noqa: E402

import fabriclib.setup.run_steps as rs  # noqa: E402
from fabriclib.setup.detach.read_run import read_run  # noqa: E402
from fabriclib.setup.detach.run_worker import run_worker  # noqa: E402
from fabriclib.setup.detach.write_handoff import write_handoff  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


rs.print_first_steps = lambda ctx, guided=False: None
seen = []


def step(name):
    def run(ctx):
        seen.append((name, ctx.admin_password, ctx.join_invitation, ctx.non_interactive, ctx.offline,
                     sorted(ctx.restart_services), dict(ctx.vars)))
    return (name, run, name)


STEPS = [step(n) for n in ("preflight", "join", "deploy", "certs", "admin", "ready")]


def read_own(path):
    from fabriclib.setup.detach.read_handoff import read_handoff
    return read_handoff(path, os.getuid())


def setup(d, record, secrets=None):
    config = os.path.join(d, "fabric", "config")
    os.makedirs(config, exist_ok=True)
    with open(os.path.join(config, "fabric.yaml"), "w") as f:
        yaml.safe_dump({"domain": "lan.test"}, f)
    with open(os.path.join(config, "vars.yaml"), "w") as f:
        yaml.safe_dump({"domain": "lan.test", "rendered": True}, f)
    if secrets:
        record["handoff"] = write_handoff(record["id"], secrets, os.path.join(d, "run"))
    write_run(config, record)
    return config


with tempfile.TemporaryDirectory() as d:
    config = setup(d, {"id": "r1", "state": "running", "done": [], "options": {"offline": True}},
                   {"admin_password": "Good-Pass-1234", "join_invitation": "fabric-join-1.x"})
    handoff = read_run(config)["handoff"]
    code = run_worker("r1", d, STEPS, read_secrets=read_own)
    first = seen[0]
    check("the recorded run's steps all run and it ends done", code == 0 and [s[0] for s in seen] ==
          [n for n, _, _ in STEPS] and read_run(config)["state"] == "done", (code, seen, read_run(config)))
    check("the steps get the handed-over secrets, the recorded options, and no terminal (unattended answers)",
          first[1] == "Good-Pass-1234" and first[2] == "fabric-join-1.x" and first[3] is True and first[4] is True,
          first)
    check("…the settings the questions saved (fabric.yaml) before deploy",
          first[6] == {"domain": "lan.test"}, first[6])
    check("the hand-off file is gone, and the record no longer names it",
          not os.path.exists(handoff) and read_run(config)["handoff"] is None, read_run(config))
    check("negative: no secret is written into the run record",
          "Good-Pass-1234" not in open(os.path.join(config, "setup-run.yaml")).read())

seen.clear()
with tempfile.TemporaryDirectory() as d:
    config = setup(d, {"id": "r2", "state": "running", "done": ["preflight", "join", "deploy"],
                       "restart_services": ["nginx"], "options": {}})
    code = run_worker("r2", d, STEPS, read_secrets=read_own)
    check("a resumed run: only the steps not done, with the rendered vars and the services still to restart",
          code == 0 and [s[0] for s in seen] == ["certs", "admin", "ready"] and seen[0][5] == ["nginx"]
          and seen[0][6].get("rendered") is True, seen)

seen.clear()
with tempfile.TemporaryDirectory() as d:
    config = setup(d, {"id": "r3", "state": "running", "done": [], "options": {}})
    code = run_worker("someone-else", d, STEPS, read_secrets=read_own)
    check("negative: a run id that is not the one recorded: exit 1, nothing run, the record untouched",
          code == 1 and not seen and read_run(config)["state"] == "running", (code, seen))
    write_run(config, {"id": "r3", "state": "done", "done": []})
    code = run_worker("r3", d, STEPS, read_secrets=read_own)
    check("negative: a run that has finished is not run again", code == 1 and not seen, (code, seen))

with tempfile.TemporaryDirectory() as d:
    config = setup(d, {"id": "r4", "state": "running", "done": [], "options": {}}, {"admin_password": "x"})

    def refuse(path):
        os.remove(path)
        raise SetupError(f"refused {path}: not a regular file of uid 0 with mode 0600")
    code = run_worker("r4", d, STEPS, read_secrets=refuse)
    check("negative: refused hand-off secrets: exit 1, nothing run, the run recorded failed",
          code == 1 and not seen and read_run(config)["state"] == "failed", (code, read_run(config)))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
