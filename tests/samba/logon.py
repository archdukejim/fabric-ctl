"""The `samba` suite, who may sign in per OU (manual 1.6.11.4, 2.1.6.42, 2.1.6.44): a real DC converged by fabric's
code, edited with `fabricctl domain logon` and the agent's routes. Proves: with `logon_policies` null the site's one
log-on GPO as before; the first edit keeps today's rights as the site OU's policy and adds the OU edited; one GPO per OU,
linked to it, granting its console and remote groups (each with fabric-break-glass and the machines' local
Administrators); the legacy GPO unlinked and deleted with its SYSVOL folder; an OU that does not exist reported and
skipped; clearing an OU removes its GPO; the refusals (an unknown group, a bad OU path, a policy granting nobody on
OU=machines, a clear that would leave the site's machines without a policy, a right that is not a list); the routes'
permissions.
    sudo python3 tests/samba/logon.py
"""
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import start_dc  # noqa: E402
import agent.get_route as m_get  # noqa: E402
import agent.post_domain as m_post  # noqa: E402
import fabriclib.samba.clear_logon_policy as m_clear  # noqa: E402
import fabriclib.samba.logon_overview as m_overview  # noqa: E402
import fabriclib.samba.run_domain_command as m_cmd  # noqa: E402
import fabriclib.samba.set_logon_policy as m_set  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-logon")
NET, SUBNET, IP, DC = "logon_net", "10.254.36.0/24", "10.254.36.10", "logondc"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def cleanup():
    subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
    subprocess.run(["docker", "network", "rm", NET], capture_output=True)


cleanup()
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
FED = os.path.join(W, "dc", "federation.yaml")

# the settings file as the editor keeps it, and the apply as its converge part runs it (the rest of an apply is
# outside this suite: nothing else reads logon_policies)
STORE = {"vars": {"site_name": "lan"}}
AUDIT, APPLIED = [], []


def settings():
    return {**V, **copy.deepcopy(STORE["vars"])}


def apply(actor, source="cli"):
    done = converge_domain(settings(), FED, SECRETS, container=DC)
    APPLIED.append(done)
    return True, "\n".join(done)


for mod in (m_set, m_clear):
    mod.load_vars = lambda: copy.deepcopy(STORE["vars"])
    mod.save_vars = lambda data: STORE.update(vars=copy.deepcopy(data))
    mod.vars_lock = contextlib.nullcontext
    mod.write_audit = lambda actor, event, detail, source="cli": AUDIT.append((event, detail, source))
for mod in (m_set, m_overview):         # the directory of this test's DC, and its secrets
    mod.run_op = lambda v, s, op, args=None, container="samba": run_op(v, s, op, args, DC)
    mod.load_secrets = lambda: SECRETS
m_cmd.apply_changes = m_post.apply_changes = apply
m_post.load_vars = m_get.load_vars = settings


def domain(*args):
    """fabricctl domain as an admin runs it: (exit status, what it printed)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_cmd.run_domain_command(settings(), list(args))
    return code, out.getvalue()


PROBE = r"""
import json, os, sys
sys.path.insert(0, "/fabric")
import ldb
from acl_entries import sid_of
from open_samdb import open_samdb
samdb, lp = open_samdb("/data/etc/smb.conf")
base, realm = str(samdb.domain_dn()), lp.get("realm").lower()
policies = os.path.join(lp.get("path", "sysvol"), realm, "Policies")
links = [(str(o.dn), str(o["gPLink"][0])) for o in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                                                                  expression="(gPLink=*)", attrs=["gPLink"])]
out = {"gpos": {}, "folders": sorted(os.listdir(policies)), "sids": {n: sid_of(samdb, n) for n in sys.argv[1:]}}
for g in samdb.search(base=f"CN=Policies,CN=System,{base}", scope=ldb.SCOPE_ONELEVEL,
                      expression="(objectClass=groupPolicyContainer)", attrs=["displayName", "cn"]):
    guid = str(g["cn"][0])
    inf = os.path.join(policies, guid, "Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf")
    out["gpos"][str(g["displayName"][0])] = {
        "guid": guid, "links": [dn.split(",DC=")[0] for dn, link in links if guid.lower() in link.lower()],
        "inf": open(inf, "rb").read().decode("utf-16") if os.path.exists(inf) else None}
print(json.dumps(out))
"""
GROUPS = ["lan-users", "lan-admins", "lan-machine-admins", "fabric-break-glass", "admins"]


def probe():
    res = subprocess.run(["docker", "exec", "-i", DC, "python3", "-", *GROUPS], input=PROBE, capture_output=True,
                         text=True)
    return json.loads(res.stdout) if res.returncode == 0 else {"error": res.stderr[-500:]}


def rights(inf):
    """The SIDs of each log-on right in a GptTmpl.inf: {"console": [...], "remote": [...]}."""
    out = {}
    for line in (inf or "").splitlines():
        for key, right in (("SeInteractiveLogonRight", "console"), ("SeRemoteInteractiveLogonRight", "remote")):
            if line.startswith(key + " = "):
                out[right] = [s.lstrip("*") for s in line.split(" = ", 1)[1].split(",")]
    return out


SITE_OU = "OU=lan,OU=sites"
p = probe()
SID = p.get("sids", {})
legacy = p.get("gpos", {}).get("fabric: lan log-on rights") or {}
check("logon_policies null: the site's one log-on GPO as before 0.9, linked to the site's OU, granting its users and "
      "admins both rights (2.1.6.44)",
      legacy.get("links") == [SITE_OU] and SID["lan-users"] in rights(legacy.get("inf"))["console"]
      and rights(legacy.get("inf"))["console"] == rights(legacy.get("inf"))["remote"]
      and not [n for n in p["gpos"] if n.startswith("fabric: lan log-on ") and n != "fabric: lan log-on rights"], p)

# an OU below machines for a policy of its own (an admin's sub-OU)
add = (f"dn: OU=lab,OU=machines,{SITE_OU},{V['ad_base_dn']}\nobjectClass: organizationalUnit\n")
made = subprocess.run(["docker", "exec", "-i", DC, "ldbadd", "-H", "/data/private/sam.ldb"], input=add,
                      capture_output=True, text=True)
check("an admin's sub-OU, OU=lab under OU=machines", made.returncode == 0, made.stderr)

code, out = domain("logon", "show")
# covers: cli:domain.logon +
check("logon show, before any edit: the site's OU with today's rights, read in the domain, and what is always kept",
      code == 0 and "before 0.9" in out and "site: console lan-users, lan-admins" in out
      and "fabric-break-glass, BUILTIN\\Administrators" in out, out)
code, out = domain("logon", "set", "machines", "--console", "lan-admins", "--remote", "lan-admins,lan-machine-admins")
check("logon set machines: saved, applied", code == 0 and "machines: console lan-admins; remote lan-admins, "
      "lan-machine-admins" in out and "applied" in out, out)
pol = STORE["vars"].get("logon_policies") or {}
check("the first edit keeps today's rights as the site OU's policy, beside the OU edited (2.1.6.44)",
      set(pol) == {"", "machines"} and pol[""]["console"][:2] == ["lan-users", "lan-admins"]
      and pol[""]["console"] == pol[""]["remote"], pol)
check("audited as LOGON_POLICY_SET with the OU and its groups",
      AUDIT and AUDIT[-1][0] == "LOGON_POLICY_SET" and "ou=machines" in AUDIT[-1][1], AUDIT)
p = probe()
gp = p.get("gpos", {})
mach, site = gp.get("fabric: lan log-on machines") or {}, gp.get("fabric: lan log-on site") or {}
always = [SID["fabric-break-glass"], "S-1-5-32-544"]
check("one GPO per OU, each linked to its OU: fabric: lan log-on machines and fabric: lan log-on site",
      mach.get("links") == [f"OU=machines,{SITE_OU}"] and site.get("links") == [SITE_OU], {k: x.get("links")
                                                                                         for k, x in gp.items()})
r = rights(mach.get("inf"))
check("OU=machines' GPO: its console and remote groups, each with fabric-break-glass and local Administrators "
      "(never locked out)", r.get("console") == [SID["lan-admins"]] + always
      and r.get("remote") == [SID["lan-admins"], SID["lan-machine-admins"]] + always, (r, SID))
check("...and the windows-admins role made local Administrators, as before (2.1.9.13)",
      "__Memberof = *S-1-5-32-544" in (mach.get("inf") or ""), mach.get("inf"))
check("the legacy GPO is gone: unlinked from the site's OU, its container deleted, its SYSVOL folder removed",
      "fabric: lan log-on rights" not in gp and legacy.get("guid") not in p.get("folders", [])
      and not any(legacy.get("guid", "?").lower() in json.dumps(x.get("links")).lower() for x in gp.values()),
      sorted(gp))
check("...and the rights in force did not change for the site's OU (its new GPO grants what the legacy one did)",
      rights(site.get("inf")) == rights(legacy.get("inf")), (rights(site.get("inf")), rights(legacy.get("inf"))))
again = converge_domain(settings(), FED, SECRETS, container=DC)
check("converge again changes nothing (idempotent)", again == [], again)

code, out = domain("logon", "set", "machines/lab", "--console", "lan-users", "--remote", "")
check("logon set machines/lab: the people at the keyboard, nobody remotely but those always kept",
      code == 0 and "machines/lab: console lan-users; remote (nobody)" in out, out)
r = rights((probe()["gpos"].get("fabric: lan log-on machines/lab") or {}).get("inf"))
check("OU=lab's GPO: lan-users at the keyboard; remotely only break-glass and local Administrators",
      r.get("console") == [SID["lan-users"]] + always and r.get("remote") == always, r)
code, out = domain("logon", "set", "machines/lab", "--remote", "lan-machine-admins")
check("a right left out is kept: --remote alone leaves the console as it was",
      code == 0 and STORE["vars"]["logon_policies"]["machines/lab"] == {"console": ["lan-users"],
                                                                         "remote": ["lan-machine-admins"]}, out)
code, out = domain("logon", "set", "machines/nowhere", "--console", "lan-admins")
check("an OU that does not exist: saved, and converge reports it and skips it (not fatal)",
      code == 0 and any("no OU OU=nowhere,OU=machines" in c and "skipped" in c for c in APPLIED[-1]), APPLIED[-1:])
code, out = domain("logon", "show", "machines/lab")
check("logon show <ou>: that OU only", code == 0 and "machines/lab: console lan-users; remote lan-machine-admins"
      in out and "machines: " not in out, out)
code, out = domain("logon", "clear", "machines/nowhere")
check("logon clear: the OU's policy removed", code == 0 and "machines/nowhere" not in STORE["vars"]["logon_policies"],
      out)
code, out = domain("logon", "clear", "site")
check("logon clear site: the site's OU loses its own policy (OU=machines still covers the machines); its GPO removed",
      code == 0 and "" not in STORE["vars"]["logon_policies"]
      and "fabric: lan log-on site" not in probe()["gpos"], out)

before = copy.deepcopy(STORE["vars"])
n_audit = len(AUDIT)
for args, why, words in (
        (("set", "machines", "--console", "no-such-group"), "a group not in the domain", "no group no-such-group"),
        (("set", "OU=x,DC=y", "--console", "lan-admins"), "an OU given as a DN", "a path below"),
        (("set", "machines", "--console", "a,b[c]"), "a group name AD could not hold", "not a group name"),
        (("set", "machines", "--console", "", "--remote", ""), "OU=machines granting nobody", "grants nobody"),
        (("clear", "machines"), "a clear leaving the site's machines without a policy", "no policy on the site's OU"),
        (("clear", "machines/linux"), "a clear of an OU without its own policy", "no log-on policy of its own")):
    code, out = domain("logon", *args)
    # covers: cli:domain.logon -
    check(f"refused: {why}, saying why, nothing saved or audited",
          code == 1 and words in out and STORE["vars"] == before and len(AUDIT) == n_audit, out)
code, out = domain("logon", "set", "machines")
check("usage: set without a right, or an unknown option, prints the usage (exit 2)",
      code == 2 and "logon set <ou>" in out and domain("logon", "set", "machines", "--ssh", "x")[0] == 2, out)
code, out = domain("status")
check("domain status shows who may sign in, per OU", "who may sign in to the machines of lan" in out
      and "machines: console lan-admins" in out, out)

print("--- the agent's routes (the web console's Machines section)")
got = m_get.get_route(["domain", "logon"])
# covers: agent:get.domain.logon +
check("GET /v1/domain/logon: each OU's policy and what is always kept",
      [x["ou"] for x in got["policies"]] == ["machines", "machines/lab"] and not got["legacy"]
      and "fabric-break-glass" in got["always"], got)
done = m_post.post_domain(["domain", "logon", "set"], "alice",
                          {"ou": "machines/lab", "console": ["lan-admins"], "remote": ["lan-admins"]})
# covers: agent:post.domain.logon.set +
check("POST /v1/domain/logon/set: saved and applied, audited from the web",
      done["applied"] and done["console"] == ["lan-admins"] and AUDIT[-1][2] == "web"
      and rights(probe()["gpos"]["fabric: lan log-on machines/lab"]["inf"]).get("remote") == [SID["lan-admins"]]
      + always, done)
done = m_post.post_domain(["domain", "logon", "clear"], "alice", {"ou": "machines/lab"})
# covers: agent:post.domain.logon.clear +
check("POST /v1/domain/logon/clear: the OU's policy and GPO gone",
      done["applied"] and "machines/lab" not in done["policies"]
      and "fabric: lan log-on machines/lab" not in probe()["gpos"], done)
before = copy.deepcopy(STORE["vars"])
for route, body, words in ((["set"], {"ou": "machines", "console": "lan-admins"}, "must be a list"),
                           (["set"], {"ou": "machines", "console": ["nobody-here"]}, "no group nobody-here"),
                           (["clear"], {"ou": "machines"}, "no policy on the site's OU")):
    try:
        m_post.post_domain(["domain", "logon", *route], "alice", body)
        err = ""
    except ValidationError as e:
        err = str(e)
    # covers: agent:post.domain.logon.set agent:post.domain.logon.clear -
    check(f"POST /v1/domain/logon/{route[0]} refused ({words}), nothing saved", words in err
          and STORE["vars"] == before, err)
STORE["vars"]["logon_policies"] = {"machines": {"console": ["lan-admins"]}, "machines/a b": {"console": []}}
try:
    m_get.get_route(["domain", "logon"])
    err = ""
except ValidationError as e:
    err = str(e)
# covers: agent:get.domain.logon -
check("GET /v1/domain/logon with a setting edited by hand into one fabric refuses: says why", "a path below" in err,
      err)
STORE["vars"] = before
check("the routes' permissions: reading needs domain:read, changing gpo:admin; the auditor reads, never changes",
      required_permission("GET", ["domain", "logon"]) == "domain:read"
      and required_permission("POST", ["domain", "logon", "set"]) == "gpo:admin"
      and required_permission("POST", ["domain", "logon", "clear"]) == "gpo:admin"
      and "domain:read" in BUNDLES["fabric-auditor"] and "gpo:admin" not in BUNDLES["fabric-auditor"])

print("--- the web console's form (its route code; the socket and the token are tests/webui's)")
import webui.agentclient as actions  # noqa: E402
from webui.routes.directory_post import directory_post  # noqa: E402


def through_agent(op, ou, console=None, remote=None):
    """agentclient.logon_change as the agent answers it: its route code, a refusal as the client's 400."""
    body = {"ou": ou, **({"console": console, "remote": remote} if op == "set" else {})}
    try:
        return m_post.post_domain(["domain", "logon", op], "alice", body)
    except ValidationError as e:
        raise actions.ValidationError(str(e))


class Handler:
    def redirect(self, location):
        self.sent = (303, location)

    def deny(self, code, message):
        self.sent = (code, message)


actions.logon_change = through_agent
h = Handler()
directory_post(h, {"user": "alice"}, ["logon", "set"],
               {"ou": "machines/lab", "console": "lan-users, lan-admins", "remote": ""})
loc = urllib.parse.unquote_plus(h.sent[1])
# covers: web:post.directory.logon.set +
check("the Who may sign in form: groups separated by commas, an empty field for nobody; saved, applied, back to the "
      "Machines section", h.sent[0] == 303 and "view=machines" in loc and "machines/lab: set; applied" in loc
      and STORE["vars"]["logon_policies"]["machines/lab"] == {"console": ["lan-users", "lan-admins"], "remote": []}
      and "fabric: lan log-on machines/lab" in probe()["gpos"], (h.sent, STORE["vars"].get("logon_policies")))
directory_post(h, {"user": "alice"}, ["logon", "set"], {"ou": "machines", "console": "ghosts", "remote": "ghosts"})
check("...and its refusal shown there (a group not in the domain)",
      h.sent[0] == 303 and "no group ghosts" in urllib.parse.unquote_plus(h.sent[1]), h.sent)

print("--- back to null: the legacy GPO again (what an upgrade that never edits keeps)")
STORE["vars"].pop("logon_policies", None)
back = converge_domain(settings(), FED, SECRETS, container=DC)
gp = probe()["gpos"]
check("logon_policies null again: the site's legacy log-on GPO, linked to its OU, and no per-OU one left to override "
      "it", (gp.get("fabric: lan log-on rights") or {}).get("links") == [SITE_OU]
      and [n for n in gp if n.startswith("fabric: lan log-on ")] == ["fabric: lan log-on rights"], back)

if not os.environ.get("FABRIC_TEST_KEEP"):
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
