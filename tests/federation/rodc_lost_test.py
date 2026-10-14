#!/usr/bin/env python3
"""A branch's read-only DC is lost or stolen (decision 2.1.6.58; manual 1.9.8.21, 4.9.1.3), container-free: the
accounts listed are exactly those the DC was told the password of (its revealed list); on confirmation only those are
reset — people to change at their next sign-in, machine and service accounts rotated — and the DC is removed (its own
account and krbtgt never reset, removed with it); refused without confirmation, from the site itself, a sibling or a
site below, at a read-only DC and when no writable DC answers; every step recorded and audited, so a second run
carries on and a finished one changes nothing; the agent's and the console's routes; the command line. The DC's side
(msDS-RevealedUsers, the resets, Samba's removal of a dead DC): tests/samba/dc.py (written, not run).

    python3 tests/federation/rodc_lost_test.py      (on Linux: the audit log uses syslog)
"""
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
import fabriclib.federation.rodc_lost as rl  # noqa: E402
import fabriclib.federation.confirm_plan as cp  # noqa: E402
import fabriclib.federation.run_federation_command as rfc  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp(prefix="fabric-rodc-lost-")
AUDIT = []
rl.write_audit = lambda actor, event, detail, source="cli", **kw: AUDIT.append((actor, event, detail, source))


def write(path, text, mode, uid=0, gid=0):
    """write_file_if_changed without the chown (the tests do not run as root)."""
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)
    return True


rl.write_file_if_changed = write


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


SITES = [{"site": "org", "dn": "OU=org,OU=sites,DC=ad"},
         {"site": "site2", "dn": "OU=site2,OU=org,OU=sites,DC=ad"},
         {"site": "branch", "dn": "OU=branch,OU=site2,OU=org,OU=sites,DC=ad"},
         {"site": "site3", "dn": "OU=site3,OU=org,OU=sites,DC=ad"}]
BOB = "CN=bob,OU=people,OU=branch,OU=site2,OU=org,OU=sites,DC=ad"
PC = "CN=PC-1,OU=machines,OU=branch,OU=site2,OU=org,OU=sites,DC=ad"
SVC = "CN=fabric-radius-branch,OU=service-accounts,OU=branch,OU=site2,OU=org,OU=sites,DC=ad"
OWN = "CN=DC-BRANCH,OU=Domain Controllers,DC=ad"
KRB = "CN=krbtgt_4242,CN=Users,DC=ad"
CAROL = "CN=carol,OU=people,OU=site2,OU=org,OU=sites,DC=ad"        # never revealed to the branch's DC


class DC:
    """Stands in for the writable DC (src/containers/samba/rodc_lost.py): one read-only DC and what it was told."""

    def __init__(self):
        self.rodc = {"name": "DC-BRANCH", "dn": OWN, "krbtgt": KRB, "accounts": [
            {"dn": BOB, "name": "bob", "kind": "person"}, {"dn": PC, "name": "PC-1$", "kind": "machine"},
            {"dn": SVC, "name": "fabric-radius-branch", "kind": "service"},
            {"dn": OWN, "name": "DC-BRANCH$", "kind": "dc"}, {"dn": KRB, "name": "", "kind": "krbtgt"}]}
        self.reset, self.removed, self.calls, self.down, self.fail_remove = [], [], [], False, False

    def run(self, request):
        self.calls.append(request["action"])
        if self.down:
            raise ValidationError("this site's writable domain controller does not answer (the DC is not running): "
                                  "nothing was changed")
        if request["action"] == "list":
            return {"rodcs": [self.rodc] if self.rodc else []}
        if request["action"] == "reset":
            held = {a["dn"] for a in self.rodc["accounts"]} if self.rodc else None
            for a in request["accounts"]:
                assert held is None or a["dn"] in held, a        # the DC's own check: never outside the list
                assert a["kind"] in ("person", "machine", "service"), a
            self.reset += [dict(a) for a in request["accounts"]]
            return {"reset": request["accounts"]}
        if request["action"] == "remove":
            if self.fail_remove:
                raise ValidationError("the domain controller refused it: DemoteException")
            self.removed.append(request["name"])
            self.rodc = None
            return {"removed": True}
        raise AssertionError(request)


def top(**kw):
    return {"site_name": "org", "ad_dc_type": "writable", **kw}


CFG = os.path.join(W, "config")
os.makedirs(CFG)


def lost(dc, v=None, target="branch", confirmed=None, source="cli"):
    return rl.rodc_lost(v or top(), CFG, "alice", target, confirmed=confirmed, source=source, sites=SITES,
                        runner=dc.run)


# ---------------------------------------------------------------- refusals before anything
print("--- refused, nothing changed")
# covers: cli:federation.rodc-lost -
for name, v, target, match in [("from the site itself", top(site_name="branch"), "branch", "this site"),
                               ("from a sibling (site3 for the branch)", top(site_name="site3"), "branch",
                                "not below this site"),
                               ("from below (the branch for site2)", top(site_name="branch"), "site2",
                                "not below this site"),
                               ("at a read-only DC", top(ad_dc_type="rodc"), "branch", "read-only"),
                               ("for a site not in the domain", top(), "nowhere", "no site nowhere")]:
    dc = DC()
    check(f"refused {name}", refused(lost, dc, v=v, target=target, match=match) and dc.calls == [], dc.calls)
dc = DC()
dc.down = True
check("refused when no writable DC answers, nothing changed", refused(lost, dc, match="does not answer")
      and not dc.reset and not dc.removed)
check("...every refusal audited", sum(1 for a in AUDIT if a[1] == "FED_RODC_LOST_REFUSED") == 6)

# ---------------------------------------------------------------- the list
print("--- the list: exactly the revealed accounts")
dc = DC()
plan = lost(dc)["plan"]
check("listed: exactly the accounts the DC was told the password of, each once",
      sorted(a["dn"] for a in plan["accounts"]) == sorted([BOB, PC, SVC, OWN, KRB]) and CAROL not in json.dumps(plan),
      plan["accounts"])
check("...to reset: the person, the machine and the service account only",
      sorted((a["dn"], a["kind"]) for a in plan["reset_left"]) == sorted([(BOB, "person"), (PC, "machine"),
                                                                          (SVC, "service")]), plan["reset_left"])
check("...the DC's own account and krbtgt: removed with it, never reset",
      sorted(s["kind"] for s in plan["skipped"]) == ["dc", "krbtgt"] and plan["remove_left"] == ["DC-BRANCH"])
check("...what happens, said: change at next sign-in, re-join, the site DC-less",
      "next sign-in" in " ".join(plan["lines"]) and "joined again" in " ".join(plan["lines"])
      and "has no DC until a new one joins" in " ".join(plan["lines"]), plan["lines"])
check("...listing changes nothing and is audited", not dc.reset and not dc.removed
      and any(a[1] == "FED_RODC_LOST_LISTED" for a in AUDIT))
check("refused without confirmation, nothing changed", refused(lost, dc, confirmed=lambda p: False,
                                                               match="not confirmed") and not dc.reset)

# ---------------------------------------------------------------- confirmed
print("--- confirmed: reset only them, remove the DC")
# covers: cli:federation.rodc-lost +
res = lost(dc, confirmed=lambda p: True)
check("only the revealed people, machines and service accounts reset, each once",
      sorted(a["dn"] for a in dc.reset) == sorted([BOB, PC, SVC]) and CAROL not in json.dumps(dc.reset), dc.reset)
check("...people must change at next sign-in, machines and services rotated (kind passed to the DC)",
      {a["dn"]: a["kind"] for a in dc.reset} == {BOB: "person", PC: "machine", SVC: "service"})
check("...then the DC removed (its account and allowance, its krbtgt, its objects)", dc.removed == ["DC-BRANCH"]
      and res["changed"] and res["removed"] == ["DC-BRANCH"])
check("...each account's reset audited with its kind, and the end",
      sorted(a[2] for a in AUDIT if a[1] == "FED_RODC_LOST_RESET") == sorted(
          [f"site=branch kind=person dn={BOB}", f"site=branch kind=machine dn={PC}",
           f"site=branch kind=service dn={SVC}"]) and any(a[1] == "FED_RODC_LOST_DONE" for a in AUDIT))
record = json.load(open(os.path.join(CFG, "rodc-lost-branch.json")))
check("...the record: what was listed, reset, removed and when (no password)", record["done_at"]
      and sorted(record["reset"]) == sorted([BOB, PC, SVC]) and record["removed"] == ["DC-BRANCH"]
      and "password" not in json.dumps(record).lower(), record)
dc.reset.clear()
again = lost(dc, confirmed=lambda p: True)
check("run again once finished: nothing to do, nothing reset", again["plan"]["noop"] and not dc.reset
      and not again["changed"] and "handled on" in again["plan"]["lines"][0], again["plan"])

print("--- carried on after a failure")
os.remove(os.path.join(CFG, "rodc-lost-branch.json"))
dc = DC()
dc.fail_remove = True
check("the removal fails: refused, the resets kept in the record", refused(lost, dc, confirmed=lambda p: True,
                                                                           match="DemoteException")
      and len(dc.reset) == 3)
dc.fail_remove = False
dc.reset.clear()
res = lost(dc, confirmed=lambda p: True)
check("run again: no account reset twice, the DC removed", not dc.reset and dc.removed == ["DC-BRANCH"]
      and res["removed"] == ["DC-BRANCH"], res)
os.remove(os.path.join(CFG, "rodc-lost-branch.json"))
dc = DC()
dc.rodc["accounts"].append({"dn": "CN=gone,OU=people,DC=ad", "name": "", "kind": "gone"})
dc.rodc["accounts"].append({"dn": "CN=krbtgt,CN=Users,DC=ad", "name": "krbtgt", "kind": "protected"})
lost(dc, confirmed=lambda p: True)
check("an account no longer in the domain and the domain's krbtgt: never reset", sorted(a["dn"] for a in dc.reset)
      == sorted([BOB, PC, SVC]))

# ---------------------------------------------------------------- the console and the command line
print("--- the console and the command line")
# covers: agent:get.federation.rodc-lost.* agent:post.federation.rodc-lost.* +
check("the agent's routes need federation:admin (central IT's, 2.1.6.58 revised 2026-10-14)",
      required_permission("GET", ["federation", "rodc-lost", "branch"]) == "federation:admin"
      and required_permission("POST", ["federation", "rodc-lost", "branch"]) == "federation:admin")
# covers: agent:get.federation.rodc-lost.* agent:post.federation.rodc-lost.* -
check("...a fabric user without it has no route (federation:read only reads the tab)",
      required_permission("POST", ["federation", "rodc-lost"]) is None
      and required_permission("GET", ["federation"]) == "federation:read")
try:
    import agent.post_federation as pf          # needs the agent's own imports
    seen = []
    pf.load_vars = lambda: top()
    pf.rodc_lost = lambda v, cfg, actor, site, confirmed, source: seen.append(
        (site, confirmed(None), source)) or {"plan": {}, "changed": True}
    # covers: web:post.federation.rodc-lost.* +
    pf.post_federation(["federation", "rodc-lost", "branch"], "alice", {"confirm": "Branch "})
    # covers: web:post.federation.rodc-lost.* -
    pf.post_federation(["federation", "rodc-lost", "branch"], "alice", {"confirm": "site2"})
    check("the console's confirmation: the site's name typed (case and spaces aside); anything else is no",
          seen == [("branch", True, "web"), ("branch", False, "web")], seen)
except ImportError as e:
    check("agent/post_federation imports", False, e)
# covers: ask:federation.confirm +
cp.ask = lambda qid, prompt: "branch" if qid == "federation.confirm" else ""
rfc.rodc_lost = lambda v, cfg, actor, site, confirmed: {
    "plan": {"lines": ["x"]}, "reset": [1, 2], "removed": ["DC-BRANCH"],
    "changed": confirmed({"rodcs": ["DC-BRANCH"], "accounts": [], "reset_left": [], "skipped": [], "lines": ["x"]})}
ctx = types.SimpleNamespace(vars=top())
out = io.StringIO()
with contextlib.redirect_stdout(out):
    cp.sys = types.SimpleNamespace(stdin=types.SimpleNamespace(isatty=lambda: True))
    code = rfc.run_federation_command(ctx, ["rodc-lost", "branch"])
check("fabricctl federation rodc-lost branch: the list shown, the site's name typed, done",
      code == 0 and "read-only DC(s): DC-BRANCH" in out.getvalue() and "done: 2 account(s) reset" in out.getvalue(),
      out.getvalue())
# covers: ask:federation.confirm -
cp.ask = lambda qid, prompt: "yes"
check("...typing yes is not the site's name: no", not cp.confirm_plan(["x"], "branch",
                                                                      show=lambda m: None, tty=True))
err = io.StringIO()
with contextlib.redirect_stderr(err):
    code = rfc.run_federation_command(ctx, ["rodc-lost"])
check("rodc-lost without a site: usage", code == 2 and "rodc-lost <site>" in err.getvalue())
try:                                            # the console page, rendered from the dev preview's samples
    from webui import views
    from webui.devpreview.sample_data import SAMPLE_FEDERATION, SAMPLE_RODC_LOST
    page_ctx = {"csrf": "t", "user": "alice", "perms": ["federation:admin", "federation:read"],
                "version": {"version": "1", "build": ""}}
    page = views.federation(page_ctx, SAMPLE_FEDERATION, "", "", SAMPLE_RODC_LOST)
    check("the console lists the lost DC's accounts with what happens to each, and the typed-name form",
          "PC-EDGE-1$" in page and "removed with it" in page and 'action="/federation/rodc-lost/edge"' in page
          and 'name="confirm"' in page and "DC type change requested" in page, page[:600])
    page = views.federation({**page_ctx, "perms": ["federation:read", "system:admin"]}, SAMPLE_FEDERATION)
    check("...without federation:admin (system:admin alone is not it), no way to start it",
          'name="rodc_lost"' not in page)
except ImportError as e:
    print(f"SKIP the console page (no {e.name})")

print(f"\n{'FAILED: ' + str(FAILED) if FAILED else 'all passed'}")
sys.exit(1 if FAILED else 0)
