"""Who may sign in per OU at a read-only DC's site (2.1.6.52, revised 2026-10-13; 2.3.6.9.4 point 4): the read-only
DC never writes the site's log-on GPOs, so `fabricctl domain logon set|clear` (and the console, through the same
functions) refuse there before anything is read or saved, saying to make the change at the site above, as Group
Policy edits do; `domain logon show` and status flag per-OU policies saved before the refusal as never applied.
Pure logic: the settings, the directory and the apply are stand-ins.
    python3 tests/samba/logon_read_only_test.py"""
import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.samba.refuse_at_read_only_dc import refuse_at_read_only_dc  # noqa: E402
import fabriclib.samba.set_logon_policy as setmod  # noqa: E402
import fabriclib.samba.clear_logon_policy as clearmod  # noqa: E402
import fabriclib.samba.logon_overview as overmod  # noqa: E402
import fabriclib.samba.run_domain_command as cli  # noqa: E402

PASS = FAIL = 0
RODC = {"site_name": "lab", "ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"}
WRITABLE = {"site_name": "lab", "ad_dc_type": "dc"}
SAVED = {"machines": {"console": ["lab-machine-admins"], "remote": ["lab-machine-admins"]}}
touched = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return ""
    except ValidationError as e:
        return str(e)


def no_touch(name):
    def f(*a, **kw):
        touched.append(name)
        raise AssertionError(f"{name} must not be called")
    return f


# the one check
check("refuse_at_read_only_dc: nothing at a writable DC's site, or with nothing known",
      refused(refuse_at_read_only_dc, WRITABLE, "x is") == "" and refused(refuse_at_read_only_dc, None, "x is") == "")
why = refused(refuse_at_read_only_dc, RODC, "who may sign in is")
check("...at a read-only DC's site: refused, saying to make it at the site above", "read-only" in why
      and "site above" in why and "nothing was changed" in why, why)

# set and clear refuse before the settings or the directory are touched
setmod.load_vars, setmod.save_vars, setmod.run_op = no_touch("load_vars"), no_touch("save_vars"), no_touch("run_op")
why = refused(setmod.set_logon_policy, RODC, "tester", "machines", ["lab-users"], None)
check("negative: logon set at a read-only DC's site: refused, nothing read or saved", "who may sign in is" in why
      and not touched, (why, touched))
clearmod.save_vars = no_touch("save_vars")
why = refused(clearmod.clear_logon_policy, "tester", "machines", v=RODC)
check("negative: logon clear at a read-only DC's site: refused, nothing saved", "site above" in why and not touched,
      (why, touched))
clearmod.load_vars = lambda: {**RODC, "logon_policies": SAVED}
why = refused(clearmod.clear_logon_policy, "tester", "machines")
check("negative: logon clear from the console's path (the settings say read-only): refused, nothing saved",
      "site above" in why and not touched, (why, touched))
clearmod.vars_lock = contextlib.nullcontext         # no lock file written by a test
clearmod.load_vars = lambda: {**WRITABLE, "logon_policies": None}
why = refused(clearmod.clear_logon_policy, "tester", "machines", v=WRITABLE)
check("a writable DC's site: clear goes on as before (here: no per-OU policies yet)", "no per-OU log-on policies"
      in why, why)

# the command: refused, exit 1, no apply
applied = []
cli.apply_changes = lambda *a, **kw: applied.append(a) or (True, "")
cli.set_logon_policy, cli.clear_logon_policy = setmod.set_logon_policy, clearmod.clear_logon_policy


def run(v, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.run_domain_command(v, ["logon", *args])
    return code, out.getvalue()


# covers: cli:domain.logon -
code, out = run(RODC, "set", "machines", "--console", "lab-users")
check("negative: `fabricctl domain logon set` at a read-only DC's site: refused, exit 1, no apply",
      code == 1 and out.startswith("refused") and "site above" in out and not applied, out)
code, out = run(RODC, "clear", "machines")
check("negative: `fabricctl domain logon clear` there: refused, exit 1, no apply",
      code == 1 and "site above" in out and not applied, out)

# show and status: flagged
overmod.run_op = lambda *a, **kw: {"legacy": ["lab-users"]}
o = overmod.logon_overview({**RODC, "logon_policies": SAVED}, secrets={})
check("logon_overview: a read-only DC's site with saved per-OU policies is flagged unapplied",
      o["read_only"] and o["unapplied"], o)
o = overmod.logon_overview(RODC, secrets={})
check("...without them: read-only, nothing unapplied", o["read_only"] and not o["unapplied"], o)
o = overmod.logon_overview({**WRITABLE, "logon_policies": SAVED}, secrets={})
check("...a writable DC's site: neither", not o["read_only"] and not o["unapplied"], o)
cli.logon_overview = overmod.logon_overview
code, out = run({**RODC, "logon_policies": SAVED}, "show")
check("`fabricctl domain logon show` warns that the saved policies are never applied",
      code == 0 and "never applies them" in out and "have no effect" in out, out)
code, out = run(RODC, "show")
check("...and without saved ones says where they are changed", "changed at the site above" in out
      and "never applies" not in out, out)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
