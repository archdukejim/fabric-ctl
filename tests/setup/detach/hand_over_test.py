"""hand_over (decision 2.1.2.26, manual 1.3.2.3): after the last question the settings are saved, the secrets
handed over in a root-only file (never in the record, the command line or the environment), the run recorded, the
unit started and followed; a unit that cannot start leaves no secret behind; without systemd the steps run here.
systemd-run and the following are stubbed.
    python3 tests/setup/detach/hand_over_test.py"""
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
import yaml  # noqa: E402

import fabriclib.setup.run_steps as rs  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.detach.hand_over import hand_over  # noqa: E402
from fabriclib.setup.detach.read_run import read_run  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


rs.print_first_steps = lambda ctx, guided=False: None
ran = []
STEPS = [(n, (lambda n: lambda ctx: ran.append(n))(n), n) for n in ("preflight", "deploy", "certs")]


def new_ctx(d):
    ctx = SetupContext(deploy_base=d)
    ctx.vars = {"domain": "lan.test", "install_webui": True}
    ctx.admin_password, ctx.join_invitation = "Good-Pass-1234", None
    return ctx


launched = []


def launch(run_id, base, log):
    rec = read_run(os.path.join(base, "fabric", "config"))
    launched.append((run_id, base, log, rec, dict(yaml.safe_load(open(rec["handoff"])))))


with tempfile.TemporaryDirectory() as d:
    ctx, run_dir = new_ctx(d), os.path.join(d, "run")
    os.makedirs(run_dir)
    stale = os.path.join(run_dir, "setup-old.handoff")
    open(stale, "w").write("admin_password: old\n")
    old_log = os.path.join(ctx.config_dir, "setup-run.log")
    os.makedirs(ctx.config_dir)
    open(old_log, "w").write("the run before\n")
    code = hand_over(ctx, STEPS, {"options": {"guided": True}}, launch=launch, follow=lambda c: 0,
                     detach=lambda: True, handoff_dir=run_dir)
    run_id, base, log, rec, secrets = launched[-1]
    check("the unit is started for the recorded run, with its log, and the console's result is the follow's",
          code == 0 and run_id == rec["id"] and rec["state"] == "running" and base == d
          and log == old_log and not ran, (code, launched))
    check("the settings are saved to fabric.yaml first (the unit reads them, as deploy does)",
          yaml.safe_load(open(os.path.join(ctx.config_dir, "fabric.yaml"))) == ctx.vars)
    check("the secrets typed in the questions are in the hand-off file, 0600",
          secrets == {"admin_password": "Good-Pass-1234"}
          and stat.S_IMODE(os.stat(rec["handoff"]).st_mode) == 0o600, (secrets, rec))
    check("negative: no secret in the run record", "Good-Pass-1234" not in open(
        os.path.join(ctx.config_dir, "setup-run.yaml")).read())
    check("a hand-off file an earlier run left is removed", not os.path.exists(stale))
    check("the previous run's log is kept as setup-run.log.1, the new one empty and 0600",
          open(old_log + ".1").read() == "the run before\n" and os.path.getsize(old_log) == 0
          and stat.S_IMODE(os.stat(old_log).st_mode) == 0o600)


def cannot(run_id, base, log):
    raise SetupError("could not start fabric-setup.service: refused")


with tempfile.TemporaryDirectory() as d:
    ctx, run_dir = new_ctx(d), os.path.join(d, "run")
    try:
        hand_over(ctx, STEPS, {"options": {}}, launch=cannot, follow=lambda c: 0, detach=lambda: True,
                  handoff_dir=run_dir)
        check("negative: a unit that cannot start: SetupError", False)
    except SetupError:
        rec = read_run(ctx.config_dir)
        check("negative: a unit that cannot start: SetupError, the hand-off file removed, the run recorded failed",
              not os.listdir(run_dir) and rec["state"] == "failed" and rec["handoff"] is None, (os.listdir(run_dir), rec))

with tempfile.TemporaryDirectory() as d:
    ctx, run_dir = new_ctx(d), os.path.join(d, "run")
    ctx.admin_password = None
    launched.clear()
    code = hand_over(ctx, STEPS, {"options": {}}, launch=lambda *a: launched.append(a), follow=lambda c: 0,
                     detach=lambda: True, handoff_dir=run_dir)
    check("no secret to hand over: no hand-off file at all", code == 0 and read_run(ctx.config_dir)["handoff"] is None
          and (not os.path.exists(run_dir) or not os.listdir(run_dir)), read_run(ctx.config_dir))

with tempfile.TemporaryDirectory() as d:
    ctx, run_dir = new_ctx(d), os.path.join(d, "run")
    launched.clear()
    ran.clear()
    code = hand_over(ctx, STEPS, {"options": {}}, launch=lambda *a: launched.append(a), follow=lambda c: 9,
                     detach=lambda: False, handoff_dir=run_dir)
    check("negative: a host not booted with systemd: no unit, the steps run in this session, still recorded",
          code == 0 and not launched and ran == ["preflight", "deploy", "certs"]
          and read_run(ctx.config_dir)["state"] == "done", (code, ran))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
