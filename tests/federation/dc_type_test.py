#!/usr/bin/env python3
"""A site's DC type change (decision 2.1.9.23; manual 1.9.8.20, 4.9.1.2), container-free: the request from a site above
(refused from the site itself, a sibling, a site below, a read-only DC, with replication unhealthy, for "none" and for
the type the site has), the change token redeemed at the site above (one use, its kind never a join invitation), the
site's plan (no request, a token for another change or organisation, no writable DC answering — each one named —,
replication unhealthy, an FSMO role) and the change carried out step by step (each recorded; a second run carries on
from the first not done; a site already of the type only has its request removed); the command line and its
questions. The real DCs: tests/samba/dc.py (written, not run).

    python3 tests/federation/dc_type_test.py        (on Linux: the audit log uses syslog)
"""
import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import types

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.samba.writable_server as ws  # noqa: E402
import fabriclib.federation.request_dc_type as rdt  # noqa: E402
import fabriclib.federation.accept_dc_type as adt  # noqa: E402
import fabriclib.federation.accept_join as aj  # noqa: E402
import fabriclib.federation.change_dc_type as cdt  # noqa: E402
import fabriclib.federation.confirm_plan as cp  # noqa: E402
import fabriclib.federation.read_change_token as rct  # noqa: E402
import fabriclib.federation.run_federation_command as rfc  # noqa: E402
from fabriclib.federation.plan_dc_type_change import plan_dc_type_change  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp(prefix="fabric-dc-type-")
AUDIT = []


def audit(actor, event, detail, source="cli", **kw):
    AUDIT.append((actor, event, detail))


def write(path, text, mode, uid=0, gid=0):
    """write_file_if_changed without the chown (the tests do not run as root)."""
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)
    return True


for mod in (rdt, adt, aj, cdt):
    mod.write_audit = audit
for mod in (rdt, adt, aj):
    mod.federation_lock = contextlib.nullcontext
cdt.write_file_if_changed = write
cdt.vars_lock = contextlib.nullcontext
rdt.describe_cert = cdt.describe_cert = lambda pem: {"sha256": "AA:BB:CC"}
ROOT = os.path.join(W, "root_ca.crt")
with open(ROOT, "w") as f:
    f.write("-----BEGIN CERTIFICATE-----\nnot parsed here\n-----END CERTIFICATE-----\n")
cdt.ca_files = lambda v: (ROOT, "")


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def refused(fn, *args, match="", **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"      (refused, but with: {exc})")
        return False
    return False


NOW = 1_800_000_000
GOOD = {"error": "", "neighbours": [{"partition": "DC=ad", "from": "CN=NTDS Settings,CN=DC-SITE2", "failures": 0,
                                     "last_success": "2027-01-15 08:00:00 UTC", "message": ""}]}
BAD = {"error": "", "neighbours": [{"partition": "DC=ad", "from": "CN=NTDS Settings,CN=DC-SITE2", "failures": 4,
                                    "last_success": "2027-01-15 07:00:00 UTC", "message": "WERR_DS_DRA_ACCESS_DENIED"}]}
SITES = [{"site": "org", "dn": "OU=org,OU=sites,DC=ad"},
         {"site": "site2", "dn": "OU=site2,OU=org,OU=sites,DC=ad"},
         {"site": "site3", "dn": "OU=site3,OU=org,OU=sites,DC=ad"},
         {"site": "branch", "dn": "OU=branch,OU=site2,OU=org,OU=sites,DC=ad"}]
TYPES = {"org": "writable", "site2": "writable", "site3": "rodc", "branch": "rodc"}


class Directory:
    """Stands in for run_op: the requests in AD and every site's DC type (read_site_dcs)."""

    def __init__(self):
        self.requests, self.calls = {}, []

    def op(self, me):
        def run(name, args):
            self.calls.append((me, name, args))
            if name == "read_site_dcs":
                return {"sites": {s: {"type": TYPES.get(s, "none")} for s in args["sites"]}}
            if name == "set_dc_type_request":
                self.requests[args["target"]] = args["request"]
                return {"site": args["target"]}
            if name == "read_dc_type_request":
                target = args.get("target") or me
                return {"site": target, "request": self.requests.get(target)}
            raise AssertionError(name)
        return run


class Secrets:
    def __init__(self):
        self.data = {}

    def load(self, v=None):
        return json.loads(json.dumps(self.data))

    def save(self, changes, v=None):
        self.data.update(changes)


def top(**kw):
    return {"site_name": "org", "ad_dc_type": "writable", "federation_endpoint": True,
            "hostname_federation": "federation.org.example", "host_ip": "10.0.0.1", "hostname_dc": "dc-org.ad",
            "ad_domain": "ad.example", "deploy_base_dir": W, **kw}


def ask(v, target, to, d, s, replication=GOOD):
    return rdt.request_dc_type(v, "alice", target, to, now=NOW, op=d.op(v["site_name"]), sites=SITES,
                               replication=replication, load=s.load, save=s.save, root_pem="PEM")


_real_healthy = rdt.replication_healthy
rdt.replication_healthy = lambda status, now=None: _real_healthy(
    status, now=__import__("datetime").datetime(2027, 1, 15, 8, 30, tzinfo=__import__("datetime").timezone.utc))

# ---------------------------------------------------------------- asked from above
print("--- the request, from a site above")
# covers: cli:federation.dc-type +
d, s = Directory(), Secrets()
req = ask(top(), "site2", "rodc", d, s)
body = json.loads(base64.urlsafe_b64decode(req["token"][len("fabric-dctype-1."):] + "=="))
entry = s.data["federation_invitations"][req["id"]]
check("a site above asks a site below to change: the request in the site's OU, a one-hour token",
      d.requests["site2"]["to"] == "rodc" and d.requests["site2"]["by"] == "org" and req["was"] == "writable"
      and entry["kind"] == "dc-type" and entry["expires"] == NOW + 3600 and body["site"] == "site2"
      and body["root_sha256"] == "AA:BB:CC" and body["host"] == "federation.org.example", (req, d.requests))
check("...only the token secret's hash is kept, never the secret", body["secret"] not in json.dumps(s.data)
      and entry["sha256"] and ("alice", "FED_DC_TYPE_REQUEST") in [(a, e) for a, e, _ in AUDIT])
check("...a nested site two levels down may be asked from the top", ask(top(), "branch", "writable", Directory(),
                                                                         Secrets())["was"] == "rodc")
# covers: cli:federation.dc-type -
check("refused from the site itself", refused(ask, top(), "org", "rodc", Directory(), Secrets(), match="this site"))
check("refused from a sibling (site2 asking site3)",
      refused(ask, top(site_name="site2"), "site3", "writable", Directory(), Secrets(), match="not below this site"))
check("refused from below (site2 asking the top)",
      refused(ask, top(site_name="site2"), "org", "rodc", Directory(), Secrets(), match="not below this site"))
check("refused for a site not in the domain", refused(ask, top(), "nowhere", "rodc", Directory(), Secrets(),
                                                      match="no site nowhere"))
check("refused for 'none' (open: 1.9.8.12)", refused(ask, top(), "site2", "none", Directory(), Secrets(),
                                                     match="not built"))
check("refused for an unknown type", refused(ask, top(), "site2", "big", Directory(), Secrets(),
                                             match="writable or rodc"))
check("refused at a site whose own DC is read-only", refused(ask, top(ad_dc_type="rodc"), "site2", "rodc",
                                                             Directory(), Secrets(), match="read-only"))
check("refused with the federation endpoint off", refused(ask, top(federation_endpoint=False), "site2", "rodc",
                                                          Directory(), Secrets(), match="endpoint is off"))
check("refused when the site is already of that type", refused(ask, top(), "site3", "rodc", Directory(), Secrets(),
                                                               match="already read-only"))
d2, s2 = Directory(), Secrets()
check("refused when replication is unhealthy, naming the partner and its failure, nothing written",
      refused(ask, top(), "site2", "rodc", d2, s2, replication=BAD, match="WERR_DS_DRA_ACCESS_DENIED")
      and not d2.requests and not s2.data)

# ---------------------------------------------------------------- the token redeemed above
print("--- the change token redeemed at the site above")
converged = []


def redeem(secret=None, site="site2", to="rodc", now=NOW + 60, rid=None):
    return adt.accept_dc_type(top(), {"id": rid or req["id"], "secret": secret or body["secret"], "site": site,
                                      "to": to}, client_ip="10.0.2.1", now=now, op=d.op("org"),
                              converge=lambda state: converged.append(state) or [], load=s.load, save=s.save)


check("a sibling's token, the wrong site named: refused", refused(redeem, site="site3", match="was made for"))
check("a wrong secret: refused (one message)", refused(redeem, secret="guess", match="not valid"))
check("an expired token: refused", refused(redeem, now=NOW + 7200, match="not valid"))
ans = redeem()
check("redeemed: a join account for the site's DC alone (the converge's join_only), the answer names the DC",
      converged and converged[-1]["join_only"] and converged[-1]["join_account"]["name"] == "fabric-join-site2"
      and ans["join_user"] == "fabric-join-site2" and ans["dc_host"] == "dc-org.ad" and ans["to"] == "rodc", ans)
check("...used once: the second redeem is refused", refused(redeem, match="not valid"))
check("...the join account's password is in no audit line", all(ans["join_password"] not in x for _, _, x in AUDIT))
# a join invitation is never a DC type token, and a DC type token is never a join invitation
s.data["federation_invitations"] = {"inv1": {"sha256": __import__("hashlib").sha256(b"sekrit").hexdigest(),
                                             "site": "site2", "expires": NOW + 3600},
                                    "dct1": {"sha256": __import__("hashlib").sha256(b"sekrit").hexdigest(),
                                             "site": "site9", "expires": NOW + 3600, "kind": "dc-type",
                                             "to": "rodc"}}
check("a join invitation's id and secret are refused as a change token", refused(redeem, secret="sekrit", rid="inv1",
                                                                                   match="not valid"))
aj.load_secrets = s.load
check("a change token is refused as a join invitation",
      refused(aj.accept_join, {"domain": "org.example"}, {"id": "dct1", "secret": "sekrit", "site": "site9",
                                                          "csr": "x", "domain": "site9.example",
                                                          "address": "10.0.9.1"}, now=NOW, match="not valid"))
d.requests["site2"] = None
s.data["federation_invitations"]["dct2"] = {"sha256": __import__("hashlib").sha256(b"x2").hexdigest(),
                                            "site": "site2", "expires": NOW + 3600, "kind": "dc-type", "to": "rodc"}
check("a token whose request was withdrawn in AD: refused", refused(redeem, secret="x2", rid="dct2",
                                                                    match="no change of site site2"))

# ---------------------------------------------------------------- the plan at the site
print("--- the plan at the site")
SITE = {"site_name": "site2", "dc_name": "dc-site2", "ad_dc_type": "writable"}
PENDING = {"to": "rodc", "by": "org", "actor": "alice", "at": "2027-01-15T08:00:00Z", "id": "abc123"}
TOKEN = {"id": "abc123", "site": "site2", "to": "rodc", "by": "org", "root_ok": True}
ok = plan_dc_type_change(SITE, PENDING, TOKEN, ("dc-org.ad", ""), (True, ""), [])
check("every step, in order", ok["steps"] == ["token", "demote", "leftover", "set_aside", "join", "done"]
      and "read-only domain controller" in ok["lines"][4] and not ok["refused"], ok)
check("no request: refused", "no change of this site's DC type is requested"
      in plan_dc_type_change(SITE, None, None, ("x", ""), (True, ""), [])["refused"])
check("a token for another change: refused", "ask for a new one" in plan_dc_type_change(
    SITE, PENDING, {**TOKEN, "to": "writable"}, ("x", ""), (True, ""), [])["refused"])
check("a token of another organisation's root: refused", "another organisation" in plan_dc_type_change(
    SITE, PENDING, {**TOKEN, "root_ok": False}, ("x", ""), (True, ""), [])["refused"])
check("replication unhealthy: refused", "not healthy" in plan_dc_type_change(
    SITE, PENDING, TOKEN, ("x", ""), (False, "CN=DC-ORG failed 3 times"), [])["refused"])
check("an FSMO role here, to read-only: refused, saying how to move it", "fsmo transfer" in plan_dc_type_change(
    SITE, PENDING, TOKEN, ("x", ""), (True, ""), ["SchemaMasterRole"])["refused"])
check("already of the type: only the request is removed", plan_dc_type_change(
    {**SITE, "ad_dc_type": "rodc"}, PENDING, TOKEN, ("x", ""), (True, ""), [])["steps"] == ["done"])
check("after the demote, the checks before it no longer stop the rest", plan_dc_type_change(
    SITE, PENDING, TOKEN, (None, "nobody answers"), (False, "down"), [], done=["token", "demote"])["steps"]
    == ["leftover", "set_aside", "join", "done"])

# ---------------------------------------------------------------- the change, carried out
print("--- the change at the site")
CFG = os.path.join(W, "config")
os.makedirs(os.path.join(W, "samba", "data"), exist_ok=True)
os.makedirs(os.path.join(W, "samba", "secrets"), exist_ok=True)
os.makedirs(CFG, exist_ok=True)
SV = {**SITE, "ad_base_dn": "DC=ad", "ad_netbios": "AD", "ad_domain": "ad.example", "deploy_base_dir": W,
      "ad_writable_servers": ["10.0.0.1", "10.0.0.9"], "hostname_dc": "dc-site2.ad", "host_ip": "10.0.2.1"}
token = rdt.DC_TYPE_PREFIX + base64.urlsafe_b64encode(json.dumps(
    {"id": "abc123", "secret": "s3cret", "site": "site2", "to": "rodc", "by": "org", "host": "federation.org.example",
     "address": "10.0.0.1", "root_sha256": "aa:bb:cc"}).encode()).decode().rstrip("=")
site_dir = Directory()
site_dir.requests["site2"] = dict(PENDING)
docker_calls, setups, posted, saved_vars = [], [], [], {}
fail_setup = [True]


def docker(args, stdin=None):
    docker_calls.append(args)
    out = "SchemaMasterRole owner: CN=NTDS Settings,CN=DC-ORG,CN=Servers\n" if args[-2:] == ["fsmo", "show"] else ""
    return types.SimpleNamespace(returncode=0, stdout=out or "dc-site2\n", stderr="")


def setup():
    setups.append(1)
    if fail_setup[0]:
        fail_setup[0] = False
        return False, "the join timed out"
    return True, "ok"


def post(address, host, root_pem, path, body):
    posted.append((address, host, path, body))
    return {"join_user": "fabric-join-site2", "join_password": "Pw-1!", "dc_host": "dc-org.ad",
            "dc_address": "10.0.0.1"}


ws._answers = lambda server: server == "10.0.0.9"        # the first writable DC listed is down: the second answers
ws._seen.clear()
site_secrets = Secrets()


def change(text=token, consent=lambda lines: True, **kw):
    return cdt.change_dc_type(SV, CFG, "root", token_text=text, consent=consent, show=lambda m: None,
                              op=site_dir.op("site2"), post=post, docker=docker, setup=setup, replication=GOOD,
                              load=site_secrets.load, save=site_secrets.save,
                              vars_io=(lambda: dict(saved_vars), lambda data: saved_vars.update(data)),
                              now=__import__("datetime").datetime(2027, 1, 15, 8, 30,
                                                                  tzinfo=__import__("datetime").timezone.utc), **kw)


shown = cdt.change_dc_type(SV, CFG, "root", op=site_dir.op("site2"), docker=docker, replication=GOOD,
                           load=site_secrets.load, now=__import__("datetime").datetime(
                               2027, 1, 15, 8, 30, tzinfo=__import__("datetime").timezone.utc))
check("show: the plan, nothing changed (the second writable DC listed answers)",
      shown["plan"]["steps"][0] == "token" and "10.0.0.9" in shown["plan"]["lines"][1] and not posted
      and not docker_calls[2:], shown)
check("refused without consent, nothing changed", refused(change, consent=lambda lines: False,
                                                          match="not confirmed") and not posted)
check("refused for a token that is not one", refused(change, text="fabric-inv-1.abc", match="not a DC type change"))
check("a failed step names itself; the steps before it are recorded",
      refused(change, match="setup did not finish the join")
      and json.load(open(os.path.join(CFG, "dc-type-change.json")))["done"] == ["token", "demote", "leftover",
                                                                               "set_aside"])
check("...the demote went to the writable DC that answered, with the join account's file (no password on a "
      "command line)", any(a[:4] == ["exec", "samba", "samba-tool", "domain"] and "--server=10.0.0.9" in a
                           for a in docker_calls) and all("Pw-1!" not in " ".join(a) for a in docker_calls))
check("...the data set aside, never deleted", any(n.startswith("data.before-dc-type-")
                                                  for n in os.listdir(os.path.join(W, "samba"))))
check("...the settings say read-only, the join server kept", saved_vars.get("ad_dc_type") == "rodc", saved_vars)
before = len(posted)
res = change()
check("run again: it carries on from the join, the token not redeemed twice",
      res["done"] == ["join", "done"] and len(posted) == before and site_dir.requests["site2"] is None, res)
check("...audited per step and at the end", [e for _, e, _ in AUDIT].count("FED_DC_TYPE_STEP") >= 6
      and "FED_DC_TYPE_CHANGED" in [e for _, e, _ in AUDIT])
ws._answers = lambda server: False
ws._seen.clear()
site_dir.requests["site2"] = dict(PENDING, id="new1")
SV["ad_dc_type"] = "writable"
check("no writable DC answers: refused, naming each one tried, nothing changed",
      refused(change, text=None, match="10.0.0.1: did not answer; 10.0.0.9: did not answer"))
ws._answers = lambda server: True
ws._seen.clear()
check("unhealthy replication at the site: refused", refused(lambda: cdt.change_dc_type(SV, CFG, "root", op=site_dir.op("site2"), docker=docker,
                                             replication=BAD, load=site_secrets.load), match="not healthy"))
SV["ad_dc_type"] = "rodc"
site_dir.requests["site2"] = dict(PENDING, id="new2")
res = change(text=None)
check("already read-only: shown as only removing the request", res["plan"]["noop"]
      and res["plan"]["steps"] == ["done"])

# ---------------------------------------------------------------- the command line and its questions
print("--- the command line")
check("the token on the command line: refused", refused(rct.read_change_token, token, match="command line"))
tok_file = os.path.join(W, "token.txt")
with open(tok_file, "w") as f:
    f.write(token + "\n")
# covers: ask:federation.dc_type_token +
check("the token from @FILE", rct.read_change_token("@" + tok_file) == token)
rct.ask_secret = lambda qid, prompt: token if qid == "federation.dc_type_token" else ""
check("...or at the hidden prompt", rct.read_change_token("", tty=True) == token)
# covers: ask:federation.dc_type_token -
rct.ask_secret = lambda qid, prompt: "  "
check("an empty answer at the prompt: refused", refused(rct.read_change_token, "", tty=True, match="no change token"))
check("a missing file: refused, naming it", refused(rct.read_change_token, "@/nonexistent/t", match="/nonexistent/t"))
check("stdin when it is not a terminal", rct.read_change_token("-", stdin=io.StringIO(token)) == token)
# covers: ask:federation.confirm +
cp.ask = lambda qid, prompt: "yes" if qid == "federation.confirm" else ""
check("consent: typed yes", cp.confirm_plan(["a"], "yes", show=lambda m: None, tty=True))
# covers: ask:federation.confirm -
cp.ask = lambda qid, prompt: "y"
check("consent: anything else stops", not cp.confirm_plan(["a"], "yes",
                                                          show=lambda m: None, tty=True))
check("consent: no terminal and no --yes stops", not cp.confirm_plan(["a"], "yes",
                                                                     show=lambda m: None, tty=False))
ctx = types.SimpleNamespace(vars=top())
rfc.request_dc_type = lambda v, actor, target, to: {"token": "fabric-dctype-1.x", "site": target, "to": to,
                                                    "was": "writable", "id": "i1", "expires": NOW}
out = io.StringIO()
with contextlib.redirect_stdout(out):
    code = rfc.run_federation_command(ctx, ["dc-type", "site2", "rodc"])
check("fabricctl federation dc-type site2 rodc prints the token once and how to withdraw it",
      code == 0 and "fabric-dctype-1.x" in out.getvalue() and "revoke i1" in out.getvalue(), out.getvalue())
err = io.StringIO()
with contextlib.redirect_stderr(err):
    code = rfc.run_federation_command(ctx, ["dc-type", "accept", "fabric-dctype-1.secret"])
check("dc-type accept with the token as an argument: usage, nothing read", code == 2 and "usage" in err.getvalue())
with contextlib.redirect_stderr(err):
    code = rfc.run_federation_command(ctx, ["dc-type"])
check("dc-type alone: usage", code == 2)

print(f"\n{'FAILED: ' + str(FAILED) if FAILED else 'all passed'}")
sys.exit(1 if FAILED else 0)
