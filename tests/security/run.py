"""The `security` suite (manual 2.3.6.2.6.4, 2.1.6.24): fabric's sign-in layers changed on a scratch install's settings —
raises, lowerings only when asked for and recorded until raised back, Kerberos both ways, the audit entries, the
relaxations status shows, setup refusing a lowering, and `fabricctl security` refusing a lowering without its typed
confirmation. No services: the apply itself is the keycloak and host suites'.
    python3 tests/security/run.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
import fabriclib.security.set_signin_layer as ssl_mod  # noqa: E402
import fabriclib.security.run_security_command as cmd_mod  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.security.check_signin_lowering import check_signin_lowering  # noqa: E402
from fabriclib.security.signin_layers import LOWERED_FILE, signin_rows  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402

W = tempfile.mkdtemp(prefix="fabric-security-")
VARS = os.path.join(W, "config", "vars.yaml")
os.makedirs(os.path.dirname(VARS))
with open(VARS, "w") as f:
    yaml.safe_dump({"install_keycloak": True, "signin_kerberos": True, "signin_admin_second_factor": "none",
                    "signin_everyone_second_factor": "none", "webui_client_cert": False}, f)
AUDIT = []
ssl_mod.write_audit = lambda actor, action, detail, source="cli": AUDIT.append((actor, action, detail, source))
ssl_mod.vars_lock = lambda: contextlib.nullcontext()
cmd_mod.apply_signin = lambda actor, source="cli": (True, "applied")
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))


def state():
    with open(VARS) as f:
        return yaml.safe_load(f)


def lowered():
    path = os.path.join(W, "config", LOWERED_FILE)
    return json.load(open(path)) if os.path.exists(path) else {}


def refused(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return False
    except ValidationError as e:
        return str(e)


set_layer = ssl_mod.set_signin_layer
rows = {r["layer"]: r for r in signin_rows(state(), {})}
check("status by default (2.1.6.23): no second factor, no certificate, Kerberos on; raising offers the stronger values",
      rows["admin-2fa"]["value"] == "none" and rows["client-cert"]["value"] == "off"
      and rows["kerberos"]["value"] == "on" and rows["admin-2fa"]["choices"] == ["any", "totp", "passkey"])
check("status lists the password-only default as a relaxation (Rule 10, 2.1.6.23)",
      any(r["setting"].startswith("signin_admin_second_factor: none")
          for r in relaxed_settings(state(), os.path.dirname(VARS))))
res = set_layer("alice", "admin-2fa", "totp", "web", vars_file=VARS)
check("raise: admin-2fa none -> totp is saved and audited as a raise from the web",
      res["changed"] and state()["signin_admin_second_factor"] == "totp"
      and AUDIT[-1] == ("alice", "SECURITY_RAISE", "admin-2fa: none -> totp", "web"), (res, AUDIT[-1:]))
check("raise: the web console no longer counts as a relaxation once a second factor is on",
      not relaxed_settings(state(), os.path.dirname(VARS)))
msg = refused(set_layer, "alice", "admin-2fa", "none", "web", vars_file=VARS)
check("refused: lowering without asking for it (the message points to the host's command)",
      msg and "sudo fabricctl security lower admin-2fa none" in msg and state()["signin_admin_second_factor"] == "totp",
      msg)
check("refused: 'any' after 'totp' is a lowering too (any < totp < passkey)",
      refused(set_layer, "alice", "admin-2fa", "any", "web", vars_file=VARS))
check("refused: lower=True for a change that is not a lowering",
      refused(set_layer, "root", "admin-2fa", "passkey", "cli", lower=True, vars_file=VARS))
res = set_layer("root (sudo by jim)", "admin-2fa", "none", "cli", lower=True, vars_file=VARS)
low = lowered().get("admin-2fa") or {}
check("lower: saved, audited as a lowering by root and the sudo user, recorded with the level it had",
      state()["signin_admin_second_factor"] == "none" and AUDIT[-1][1] == "SECURITY_LOWER"
      and AUDIT[-1][0] == "root (sudo by jim)" and low.get("from") == "totp" and low.get("to") == "none", (low, AUDIT))
relaxed = relaxed_settings(state(), os.path.dirname(VARS))
check("a lowered layer is a relaxation status, doctor and the Overview show",
      any(r["setting"] == "admin-2fa lowered: totp -> none" for r in relaxed), relaxed)
set_layer("alice", "admin-2fa", "any", "web", vars_file=VARS)
check("a raise short of the old level keeps the lowering on record",
      (lowered().get("admin-2fa") or {}).get("to") == "any")
set_layer("alice", "admin-2fa", "passkey", "web", vars_file=VARS)
check("raising back to the old level or above clears it", "admin-2fa" not in lowered(), lowered())
res = set_layer("alice", "admin-2fa", "passkey", "web", vars_file=VARS)
check("the same value again changes nothing and is not audited", not res["changed"] and AUDIT[-1][2].endswith("passkey"))
set_layer("alice", "client-cert", "on", "web", vars_file=VARS)
check("client-cert: on is a raise", state()["webui_client_cert"] is True and AUDIT[-1][1] == "SECURITY_RAISE")
check("refused: client-cert off from the web", refused(set_layer, "alice", "client-cert", "off", "web",
                                                         vars_file=VARS))
set_layer("root", "kerberos", "off", "cli", vars_file=VARS)
off = state()["signin_kerberos"] is False and AUDIT[-1][1] == "SECURITY_SET"
set_layer("alice", "kerberos", "on", "web", vars_file=VARS)
check("Kerberos is a way to sign in, not a layer: off and on again, never recorded as lowered",
      off and state()["signin_kerberos"] is True and "kerberos" not in lowered())
check("refused: an unknown layer or value",
      refused(set_layer, "alice", "root-2fa", "totp", vars_file=VARS)
      and refused(set_layer, "alice", "admin-2fa", "sms", vars_file=VARS))

# setup refuses to lower a layer of an existing install (a --file or a re-run): only the command lowers
current = state()
msg = refused(check_signin_lowering, current, {**current, "signin_admin_second_factor": "totp"})
# covers: setting:signin_admin_second_factor -
check("setup refuses a lowering from its settings and names the command", msg and "fabricctl security lower" in msg,
      msg)
check("setup accepts the same or stronger values, and a fresh install takes any",
      check_signin_lowering(current, {**current, "webui_client_cert": True}) is None
      and check_signin_lowering({}, {"signin_admin_second_factor": "none"}) is None)


# the command: a lowering only with the layer's name typed back at a terminal; --yes never confirms it
def run_cmd(argv, typed=None, tty=True):
    out, err = io.StringIO(), io.StringIO()
    stdin = io.StringIO(typed or "")
    stdin.isatty = lambda: tty
    old = sys.stdin
    sys.stdin = stdin
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cmd_mod.run_security_command(argv, vars_file=VARS)
    finally:
        sys.stdin = old
    return code, out.getvalue() + err.getvalue()


code, out = run_cmd(["lower", "admin-2fa", "--yes"])
check("fabricctl security lower --yes is refused", code == 1 and "never by --yes" in out, out)
code, out = run_cmd(["lower", "admin-2fa"], tty=False)
check("fabricctl security lower without a terminal is refused", code == 1 and "needs a terminal" in out, out)
code, out = run_cmd(["lower", "admin-2fa"], typed="admin\n")
check("a wrong name typed back: not lowered", code == 2 and state()["signin_admin_second_factor"] == "passkey", out)
code, out = run_cmd(["lower", "admin-2fa", "totp"], typed="admin-2fa\n")
check("the name typed back: lowered, then applied", code == 0 and state()["signin_admin_second_factor"] == "totp"
      and "applying" in out and "Every sign-in this covers is weaker" in out, out)
code, out = run_cmd([])
check("status shows the lowered layer", code == 0 and "lowered from passkey" in out, out)
code, out = run_cmd(["raise", "admin-2fa"])
check("raise without a value goes to the next level up", code == 0 and state()["signin_admin_second_factor"] ==
      "passkey", out)
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
