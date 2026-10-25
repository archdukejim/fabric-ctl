"""print_first_steps (manual 3.3.2): setup's last words name who signs in: the first Directory Administrator setup
made, or, on a site that joined a domain (no webui_admin_user), the domain's Directory Administrators; never an empty
name, and no client certificate file named after nobody.
    python3 tests/setup/print_first_steps_test.py"""
import contextlib
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.print_first_steps as pfs  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


tmp = tempfile.mkdtemp()
pfs.sudo_owner = lambda: ("someone", tmp, 1000, 1000)
pfs.wizard_finished = lambda config_dir: {"finished": True}
ctx = SetupContext(deploy_base=tmp)
os.makedirs(ctx.path("nginx", "www", "certs"))
with open(ctx.path("nginx", "www", "certs", "ca-certs.json"), "w") as f:
    json.dump({"root-ca": {"sha256": "AA:BB"}}, f)
BASE = {"install_webui": True, "host_ip": "10.0.0.5", "hostname_mgr": "fabric-ctl.lan.test",
        "hostname_stepca": "ca.lan.test", "webui_client_cert": True}


def said(v):
    ctx.vars = v
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        pfs.print_first_steps(ctx)
    return out.getvalue()


# a joined site first: no login kit (the first administrator's) in the home of the account that ran setup
text = said(dict(BASE))
check("a joined site (no first administrator of its own): the domain's Directory Administrators sign in",
      "as one of the domain's Directory Administrators (directory-admins), with their own password" in text, text)
check("...never an empty name, nor a client certificate named after nobody",
      " as ," not in text and "/.p12" not in text and "chose in setup" not in text, text)
check("...and never as fabric-admin", "never as fabric-admin" in text, text)
check("...nor a login kit it does not have (no README.txt, no root-ca.crt in it)",
      "README.txt" not in text and "root-ca.crt" not in text and "http://10.0.0.5/certs/" in text, text)
kit = os.path.join(tmp, "fabric-admin")
os.makedirs(kit)
for name in ("README.txt", "root-ca.crt"):
    open(os.path.join(kit, name), "w").close()
text = said({**BASE, "webui_admin_user": "jane.doe"})
check("a new install: sign in as the first Directory Administrator, with the password chosen in setup",
      "as jane.doe, with the password you chose in setup" in text and "jane.doe.p12" in text, text)
check("...the login kit named: its README.txt and the same root certificate",
      f"{kit}/README.txt" in text and f"{kit}/root-ca.crt" in text, text)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
