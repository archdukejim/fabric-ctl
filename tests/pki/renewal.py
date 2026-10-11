#!/usr/bin/env python3
"""Certificate renewal and its warnings (manual 2.1.5.4–2.1.5.7), without containers: when a certificate is due,
the lifetime settings and their refusals, how a service takes a renewed certificate, the renewal run's record,
`fabricctl certs`' flags, the warnings for status, doctor and the web console, and the CA's lifetime (the Advanced
question, a changed value refused on an existing CA). Certificates are made with openssl; time is moved by passing
"now".

    python3 tests/pki/renewal.py            (openssl; no Docker, no root)
"""
import builtins
import contextlib
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.pki import pick_up_cert as pick  # noqa: E402
from fabriclib.pki.cert_warnings import cert_warnings  # noqa: E402
from fabriclib.pki.check_cert_lifetimes import check_cert_lifetimes  # noqa: E402
from fabriclib.pki.needs_renewal import needs_renewal  # noqa: E402
from fabriclib.setup import choose_plan  # noqa: E402
from fabriclib.setup import renew_service_certs as rsc  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.init_pki import _check_root_lifetime  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp()
NOW = datetime.datetime.now(datetime.timezone.utc)
DAY = datetime.timedelta(days=1)


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(*cmd):
    subprocess.run(cmd, check=True, capture_output=True)


def ca(name, days):
    """A self-signed CA (cert, key) valid for days."""
    crt, key = os.path.join(W, f"{name}.crt"), os.path.join(W, f"{name}.key")
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key,
       "-out", crt, "-days", str(days), "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE")
    return crt, key


def leaf(name, days, issuer, sans=("svc.example.test",)):
    """A leaf signed by issuer (cert, key), valid for days, with DNS SANs."""
    key, csr, crt = (os.path.join(W, f"{name}.{x}") for x in ("key", "csr", "crt"))
    ext = os.path.join(W, f"{name}.ext")
    with open(ext, "w") as f:
        f.write("subjectAltName=" + ",".join(f"DNS:{s}" for s in sans) + "\n")
    sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", csr,
       "-subj", f"/CN={sans[0]}")
    sh("openssl", "x509", "-req", "-in", csr, "-CA", issuer[0], "-CAkey", issuer[1], "-CAcreateserial", "-out", crt,
       "-days", str(days), "-extfile", ext)
    return crt


root = ca("root", 3650)
other = ca("other-root", 3650)
svc = leaf("svc", 47, root)
long = leaf("long", 5475, root)
chain = (root[0], root[0])

print("--- when a service certificate is due (2.1.5.4, 2.1.5.7)")
check("a fresh 47-day certificate is not due", not needs_renewal(svc, ["svc.example.test"], chain, 30, 47, now=NOW))
check("29 days old: not due yet", not needs_renewal(svc, [], None, 30, 47, now=NOW + 29 * DAY))
check("30 days old: due (renewed with 17 days left)", needs_renewal(svc, [], None, 30, 47, now=NOW + 30 * DAY))
check("a 5475-day certificate (0.6.2's) is re-issued at once under the 47-day setting",
      needs_renewal(long, [], None, 30, 47, now=NOW))
check("…but not when the setting allows its lifetime", not needs_renewal(long, [], None, 30, 6000, now=NOW))
check("expired: due", needs_renewal(svc, [], None, 30, 47, now=NOW + 48 * DAY))
check("negative: a missing file is due", needs_renewal(os.path.join(W, "none.crt"), [], None, 30, 47, now=NOW))
check("negative: a name it lacks makes it due", needs_renewal(svc, ["other.example.test"], None, 30, 47, now=NOW))
check("negative: a certificate from another CA is due", needs_renewal(svc, [], (other[0], other[0]), 30, 47, now=NOW))
garbage = os.path.join(W, "garbage.crt")
open(garbage, "w").write("not a certificate\n")
check("negative: an unreadable certificate is due", needs_renewal(garbage, [], None, 30, 47, now=NOW))
check("without a renewal age (client certificates): due with under 30 days left, not before",
      not needs_renewal(svc, [], None, now=NOW + 16 * DAY) and needs_renewal(svc, [], None, now=NOW + 18 * DAY))

print("--- the lifetime settings (2.1.5.4, 2.1.5.6)")


def refused(settings):
    try:
        check_cert_lifetimes({"cert_service_days": 47, "cert_renew_after_days": 30, "cert_root_ca_days": 3650,
                              **settings})
    except ValidationError as e:
        return str(e)
    return ""


check("the defaults pass", refused({}) == "")
check("90 days renewed at 30 passes", refused({"cert_service_days": 90}) == "")
check("negative: renewal leaving under 7 days is refused, saying how long to make the certificate",
      "leave at least 7" in refused({"cert_service_days": 35}) and "at least 37" in refused({"cert_service_days": 35}))
check("negative: a renewal age of 0 is refused", "at least a day" in refused({"cert_renew_after_days": 0}))
check("negative: a root under a year is refused", "at least 365" in refused({"cert_root_ca_days": 300}))
check("negative: a lifetime that is not a whole number of days is refused, naming the setting",
      "cert_service_days must be a whole number" in refused({"cert_service_days": "47d"})
      and "cert_renew_after_days must be" in refused({"cert_renew_after_days": True}))

print("--- how a service takes its renewed certificate (the reload table)")
calls = []
real_run = pick.subprocess.run


def fake_run(cmd, **kw):
    calls.append(cmd)
    return subprocess.CompletedProcess(cmd, 3 if cmd[:3] == ["systemctl", "is-active", "--quiet"] and
                                       cmd[3] == "kea" else 0)


pick.subprocess.run = fake_run
got = {u: pick.pick_up_cert(u) for u in ("nginx", "postgres", "openbao", "keycloak", "samba", "bind9", "kea")}
pick.subprocess.run = real_run
check("nginx, Postgres and OpenBao reload (a HUP, no restart: OpenBao stays unsealed)",
      all(got[u] == "reloaded" for u in ("nginx", "postgres", "openbao"))
      and ["docker", "kill", "--signal", "HUP", "openbao"] in calls
      and ["systemctl", "restart", "openbao"] not in calls, got)
check("Keycloak picks it up itself; the DC and BIND restart", got["keycloak"] == "picks it up itself"
      and got["samba"] == got["bind9"] == "restarted" and ["systemctl", "restart", "keycloak"] not in calls, got)
check("negative: a service that is not running is left for its next start", got["kea"] == "not running"
      and not any(c[:2] == ["systemctl", "restart"] and c[2] == "kea" for c in calls), got)

print("--- the renewal run, recorded for status and doctor")


class Ctx:
    def __init__(self, changed=(), fail=None):
        self.restart_services, self.force_certs, self._changed, self._fail = set(), False, changed, fail

    def load_state(self):
        return self


record = os.path.join(W, "renewal.json")
real_mint, real_pick = rsc.mint_service_certs.run, rsc.pick_up_cert


def mint(ctx):
    if ctx._fail:
        raise RuntimeError(ctx._fail)
    ctx.restart_services.update(ctx._changed)


rsc.mint_service_certs.run, rsc.pick_up_cert = mint, lambda unit: "reloaded"
with contextlib.redirect_stdout(io.StringIO()):
    code = rsc.renew_service_certs(Ctx(changed={"nginx"}), scheduled=True, record=record)
done = json.load(open(record))
check("a scheduled run renews, reloads, and records it (exit 0)",
      code == 0 and done["ok"] and done["services"] == {"nginx": "reloaded"} and done["scheduled"], done)
with contextlib.redirect_stdout(io.StringIO()):
    code = rsc.renew_service_certs(Ctx(fail="step-ca refused"), scheduled=True, record=record)
done = json.load(open(record))
check("negative: a failed run is recorded with its error and exits 1 (the timer shows failed)",
      code == 1 and not done["ok"] and "step-ca refused" in done["error"], done)
rsc.mint_service_certs.run, rsc.pick_up_cert = real_mint, real_pick

print("--- certs.<domain> is gone (1.5.1.5): no certificate issued for it, the old one deleted")
msc = rsc.mint_service_certs
_names = {k: f"{k}.lan.test" for k in ("hostname_bind9", "hostname_stepca", "hostname_landing", "hostname_openbao",
                                       "hostname_dc")}


class TCtx:
    def __init__(self, base, **extra):
        self.vars = {**_names, "hostname": "fab", "domain": "LAN.test", "ad_domain": "ad.lan.test",
                     "host_ip": "192.0.2.1", **extra}
        self.base = base

    def path(self, *parts):
        return os.path.join(self.base, *parts)


tb = os.path.join(W, "retire")
old_dir = os.path.join(tb, "nginx", "certs", "certs.lan.test")
os.makedirs(old_dir)
open(os.path.join(old_dir, "fullchain.pem"), "w").write("old")
tctx = TCtx(tb)
targets = msc._targets(tctx)
check("no service certificate for certs.<domain> any more", all(not cn.startswith("certs.") for cn, *_ in targets),
      [cn for cn, *_ in targets])
check("the old certs.<domain> certificate folder is found (run deletes it)",
      msc._old_certs_host(tctx, targets) == old_dir)
os.rename(old_dir, old_dir + ".gone")
check("…and once gone, nothing to do (idempotent)", msc._old_certs_host(tctx, targets) is None)
os.rename(old_dir + ".gone", old_dir)
tctx = TCtx(tb, hostname_landing="certs.lan.test")
check("negative: a name still in use (the info page named certs) keeps its certificate",
      msc._old_certs_host(tctx, msc._targets(tctx)) is None)

print("--- the warnings (status, doctor, the web console)")
base = os.path.join(W, "opt")
nginx_dir = os.path.join(base, "nginx", "certs", "svc.example.test")
os.makedirs(nginx_dir)
subprocess.run(["cp", svc, os.path.join(nginx_dir, "fullchain.pem")], check=True)
os.makedirs(os.path.join(base, "stepca", "data", "certs"))
subprocess.run(["cp", root[0], os.path.join(base, "stepca", "data", "certs", "root_ca.crt")], check=True)
short_ca = ca("short-ca", 100)
subprocess.run(["cp", short_ca[0], os.path.join(base, "stepca", "data", "certs", "intermediate_ca.crt")], check=True)
ledger = os.path.join(W, "issued.jsonl")
end = lambda d: (NOW + d * DAY).strftime("%b %d %H:%M:%S %Y GMT")      # noqa: E731
with open(ledger, "w") as f:
    for days in (10, 400, -5, -300):                    # expiring soon, valid, just expired, long expired
        f.write(json.dumps({"subject": "CN=x", "serial": "1", "not_after": end(days), "sha256": "x"}) + "\n")
ok_record = os.path.join(W, "ok.json")
json.dump({"ok": True}, open(ok_record, "w"))
v = {"deploy_base_dir": base}
w = cert_warnings(v, now=NOW, record=ok_record, ledger=ledger)
check("all well but what is coming: the intermediate within 180 days, issued certificates counted (warn only)",
      [x["level"] for x in w] == ["warn", "warn"] and "intermediate CA expires in" in w[0]["what"]
      and "1 expiring within 30 days, 1 expired in the last 30 days" in w[1]["what"], w)
w = cert_warnings(v, now=NOW + 42 * DAY, record=record, ledger=os.path.join(W, "none.jsonl"))
fails = [x["what"] for x in w if x["level"] == "fail"]
check("negative: a failed last run and a service certificate with 5 days left both fail (doctor fails)",
      any("renewal of" in f and "step-ca refused" in f for f in fails)
      and any("fullchain.pem: 5 day(s) left" in f for f in fails), w)
check("negative: nothing installed yet: no warnings", cert_warnings({"deploy_base_dir": os.path.join(W, "empty")},
                                                                   record=os.path.join(W, "x.json"),
                                                                   ledger=os.path.join(W, "y.jsonl")) == [])

print("--- `fabricctl certs`' flags")
for argv, want in ((["certs", "--bogus"], 2), (["certs", "--force", "--scheduled"], 2)):
    res = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, 'src'); from fabriclib.cli import main; "
                          f"sys.exit(main({argv!r}))"], cwd=REPO, capture_output=True, text=True)
    check(f"negative: fabricctl {' '.join(argv)} is refused with the usage (exit {want})",
          res.returncode == want and "usage: fabricctl certs" in res.stderr, (res.returncode, res.stderr[-300:]))

print("--- the CA's lifetime (2.1.5.6)")


def lifetime_refused(days, byoc=False, config=None):
    certs = os.path.join(base, "stepca", "data", "certs")
    config = config or os.path.join(W, "cfg-chosen")
    os.makedirs(config, exist_ok=True)
    try:
        _check_root_lifetime({"cert_root_ca_days": days, "byoc": byoc}, certs, config)
    except SetupError as e:
        return str(e)
    return ""


chosen = os.path.join(W, "cfg-chosen")
os.makedirs(chosen, exist_ok=True)
with open(os.path.join(chosen, "ca-lifetime"), "w") as f:      # a CA made by 0.6.3 or later: its lifetime chosen
    f.write("3650\n")
check("the existing root's own lifetime passes", lifetime_refused(3650) == "")
check("negative: a changed lifetime on an existing CA is refused, saying the root's and what to do",
      "made for 3650 days" in lifetime_refused(1825) and "cannot change" in lifetime_refused(1825))
check("a brought-in root's lifetime is its own: not checked", lifetime_refused(1825, byoc=True) == "")
# a CA from before 0.6.3: 0.6.2 saved a default of 1825 that never shaped its root (found by the upgrade test)
old_cfg = os.path.join(W, "cfg-0.6.2")
os.makedirs(old_cfg, exist_ok=True)
with open(os.path.join(old_cfg, "fabric.yaml"), "w") as f:
    yaml.safe_dump({"domain": "lan.test", "cert_root_ca_days": 1825}, f)
v_old = {"cert_root_ca_days": 1825}
_check_root_lifetime(v_old, os.path.join(base, "stepca", "data", "certs"), old_cfg)
check("upgrade from 0.6.2: the CA's own lifetime is adopted (setting and fabric.yaml), not refused",
      v_old["cert_root_ca_days"] == 3650
      and yaml.safe_load(open(os.path.join(old_cfg, "fabric.yaml")))["cert_root_ca_days"] == 3650
      and open(os.path.join(old_cfg, "ca-lifetime")).read().strip() == "3650", v_old)
check("...once: a change after that is refused", "cannot change" in lifetime_refused(1825, config=old_cfg))


class PlanCtx:
    def __init__(self, base_dir):
        self.vars, self._base = {}, base_dir

    def path(self, *parts):
        return os.path.join(self._base, *parts)


answers = iter(["abc", "0", "31", "5"])
real_input = builtins.input
builtins.input = lambda prompt="": next(answers)
pc = PlanCtx(os.path.join(W, "fresh"))
with contextlib.redirect_stdout(io.StringIO()) as out:
    choose_plan._ask_ca_lifetime(pc)
check("Advanced asks the root's lifetime in years; refuses text, 0 and over 30 with the reason, then takes 5",
      pc.vars.get("cert_root_ca_days") == 5 * 365 and out.getvalue().count("a whole number of years") == 3,
      (pc.vars, out.getvalue()))
os.makedirs(os.path.join(base, "stepca", "data", "config"), exist_ok=True)
open(os.path.join(base, "stepca", "data", "config", "ca.json"), "w").write("{}")
pc = PlanCtx(base)
builtins.input = lambda prompt="": (_ for _ in ()).throw(AssertionError("asked"))
choose_plan._ask_ca_lifetime(pc)
builtins.input = real_input
check("negative: with a CA already made, the question is not asked", "cert_root_ca_days" not in pc.vars, pc.vars)

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
