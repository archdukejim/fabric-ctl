"""resume_run (decision 2.1.2.26, manual 1.3.2.3.3): the last unfinished run goes on from its first unfinished
step without the questions; only a secret a step ahead needs is asked again (the first admin's password, the join
invitation), and unattended without it the resume is refused before anything starts. The hand-over is stubbed.
    python3 tests/setup/detach/resume_run_test.py"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
import yaml  # noqa: E402

import fabriclib.setup.detach.resume_run as rr  # noqa: E402
from fabriclib.samba.check_password_policy import DEFAULT_POLICY  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


STEPS = [(n, None, n) for n in ("preflight", "join", "deploy", "certs", "admin", "ready")]
SETTINGS = {"domain": "lan.test", "webui_admin_user": "pat.admin", "webui_admin_name": "Pat Example",
            "webui_admin_email": "pat@lan.test", "ad_password_policy": dict(DEFAULT_POLICY)}
handed = []


def hand(ctx, steps, record):
    handed.append((ctx, record))
    return 0


def new_ctx(d, **kw):
    ctx = SetupContext(deploy_base=d, **kw)
    os.makedirs(ctx.config_dir, exist_ok=True)
    for name in ("fabric.yaml", "vars.yaml"):
        with open(os.path.join(ctx.config_dir, name), "w") as f:
            yaml.safe_dump({**SETTINGS, "from": name}, f)
    return ctx


def quiet(fn):
    saved = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return fn(), sys.stdout.getvalue()
    finally:
        sys.stdout = saved


with tempfile.TemporaryDirectory() as d:
    last = {"id": "r1", "state": "failed", "current": "certs", "done": ["preflight", "join", "deploy"],
            "restart_services": ["nginx"], "options": {"offline": True, "guided": True, "admin_password": False}}
    ctx = new_ctx(d)
    (code, out) = quiet(lambda: rr.resume_run(ctx, STEPS, last, ["certs", "admin", "ready"], hand=hand))
    c, record = handed[-1]
    check("resumed without questions: a new run with the same options, the steps done and the services to restart",
          code == 0 and record["done"] == ["preflight", "join", "deploy"] and record["options"]["offline"] is True
          and record["options"]["guided"] is True and record["restart_services"] == ["nginx"]
          and c.restart_services == {"nginx"} and c.offline is True, record)
    check("…saying where it stopped and how to start over", "stopped at [certs]" in out and "resuming from [certs]" in out
          and "--restart" in out, out)
    check("…after deploy, from the rendered vars", c.vars.get("from") == "vars.yaml", c.vars)

with tempfile.TemporaryDirectory() as d:
    last = {"id": "r2", "state": "running", "current": "join", "done": ["preflight"],
            "options": {"join": True, "admin_password": True}}
    ctx = new_ctx(d)
    rr.read_join_invitation = lambda value, non_interactive: f"invitation({value!r},{non_interactive})"
    asked = []
    rr.ask_first_admin = lambda ctx, needed=None: asked.append(needed) or setattr(ctx, "admin_password", "typed")
    quiet(lambda: rr.resume_run(ctx, STEPS, last, ["join", "deploy", "certs", "admin", "ready"], hand=hand))
    c, record = handed[-1]
    check("a join and the first admin still ahead: the invitation and the password are asked again (memory only)",
          c.join_invitation == "invitation('',False)" and asked == [True] and c.admin_password == "typed", (c, asked))
    check("…before deploy, from the settings the questions saved (fabric.yaml)", c.vars.get("from") == "fabric.yaml")

with tempfile.TemporaryDirectory() as d:
    from fabriclib.setup.ask_first_admin import ask_first_admin
    rr.ask_first_admin = ask_first_admin
    handed.clear()
    last = {"id": "r3", "state": "failed", "current": "admin", "done": ["preflight", "join", "deploy", "certs"],
            "options": {"admin_password": True}}
    ctx = new_ctx(d, non_interactive=True)
    try:
        quiet(lambda: rr.resume_run(ctx, STEPS, last, ["admin", "ready"], hand=hand))
        check("negative: unattended, the first admin's password needed and no file: refused before the hand-over", False)
    except SetupError as e:
        check("negative: unattended, the first admin's password needed and no file: refused before the hand-over, "
              "naming --admin-password-file", "--admin-password-file" in str(e) and not handed, e)
    pw = os.path.join(d, "pw")
    open(pw, "w").write("Good-Pass-1234\n")
    last["options"]["admin_password_file"] = pw
    ctx = new_ctx(d, non_interactive=True)
    quiet(lambda: rr.resume_run(ctx, STEPS, last, ["admin", "ready"], hand=hand))
    c, record = handed[-1]
    check("…the run's --admin-password-file is read again when given then", c.admin_password == "Good-Pass-1234"
          and record["options"]["admin_password_file"] == pw, (c.admin_password, record))
    handed.clear()
    last = {"id": "r4", "state": "failed", "current": "admin", "done": ["preflight", "deploy", "certs"],
            "options": {"admin_password": False}}
    ctx = new_ctx(d, non_interactive=True)
    quiet(lambda: rr.resume_run(ctx, STEPS, last, ["admin", "ready"], hand=hand))
    check("negative: a run that had no password asks none on resume", handed and handed[-1][0].admin_password is None)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
