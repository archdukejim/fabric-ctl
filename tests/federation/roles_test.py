"""Layered roles and sibling isolation in fabriclib, the CLI and the console, without containers (decisions 2.1.9.21,
2.1.9.22; manual 1.6.8.2, 1.9.8.20): the site's own groups and the bundle each gives at that site only (and the DC's
list of console roles agrees); granting and revoking from the CLI and the agent route (names checked before the DC is
asked, the DC's refusal passed on, audited); the address plan a site shows (itself and the sites below it; the top
every site; an overlap with a site not shown counted, never named) for the Federation tab, `federation networks` and
`ipam find`; and the Federation tab's Roles card and the People page's site-helpdesk note. The directory is a
stand-in here; tests/samba/roles.py and the keycloak and webui suites run the real ones.
    python3 tests/federation/roles_test.py"""
import importlib.util
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from urllib.parse import unquote_plus as urllib_unquote

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.federation.change_site_role as change_mod  # noqa: E402
import fabriclib.federation.common.sites_shown as shown_mod  # noqa: E402
from fabriclib.federation.common.visible_plan import visible_plan  # noqa: E402
import fabriclib.federation.run_federation_command as fed_cli  # noqa: E402
import fabriclib.federation.run_roles_command as roles_cli  # noqa: E402
import fabriclib.federation.show_networks as nets_mod  # noqa: E402
import fabriclib.ipam.run_ipam_command as ipam_cli  # noqa: E402
import fabriclib.ipam.visible_sites as vis_mod  # noqa: E402
from fabriclib.keycloak.site_bundle_grants import site_bundle_grants  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES, SITE_ROLE_BUNDLES  # noqa: E402
import agent.post_federation as post_fed  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def refused(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except (ValidationError, RouteNotFound) as e:
        return str(e) or type(e).__name__
    return ""


def run(fn, *args):
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        code = fn(*args)
    return code, out.getvalue()


print("--- the site's groups and their bundles (Keycloak, 1.6.8.2)")
spec = importlib.util.spec_from_file_location("dc_site_roles", os.path.join(REPO, "src", "containers", "samba",
                                                                           "site_roles.py"))
dc_roles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dc_roles)
check("the console roles the DC makes are the ones Keycloak maps, with the same bundles",
      {r: b for r, (b, _) in dc_roles.CONSOLE_ROLES.items()} == {r: b for r, b in SITE_ROLE_BUNDLES.items()
                                                                  if r != "admins"})
grants = dict(site_bundle_grants("house1"))
check("a site's Keycloak maps its own groups only: house1-admins the site helpdesk, house1-network-operators its "
      "bundle; every group is house1's",
      grants["house1-admins"] == "fabric-site-helpdesk" and grants["house1-network-operators"] ==
      "fabric-network-operator" and all(g.startswith("house1-") for g in grants), grants)
check("...so a role granted at house1 gives nothing at house2 (house2 maps none of house1's groups)",
      not set(dict(site_bundle_grants("house2"))) & set(grants))
check("every mapped bundle is one fabric makes", all(b in BUNDLES for b in grants.values()))

print("--- a role granted at a site works at every site below it (2.1.9.21, revised 2026-10-13)")
from fabriclib.keycloak.site_lineage import site_lineage  # noqa: E402
import fabriclib.keycloak.ensure_site_group_mapper as mapper_mod  # noqa: E402
OU = {"lan": "OU=lan,OU=sites", "house1": "OU=house1,OU=lan,OU=sites", "house2": "OU=house2,OU=lan,OU=sites",
      "house1a": "OU=house1a,OU=house1,OU=lan,OU=sites", "house2a": "OU=house2a,OU=house2,OU=lan,OU=sites"}


def mapped(site):
    lineage, _ = site_lineage({"site_name": site, "ad_site_ou": OU[site]})
    return dict(site_bundle_grants(site, lineage[1:]))


check("site_lineage: the site, then each site above it, nearest first; and the top site's OU",
      site_lineage({"site_name": "house1a", "ad_site_ou": OU["house1a"]}) == (["house1a", "house1", "lan"],
                                                                               "OU=lan,OU=sites"))
def lineage_refused(v):
    try:
        site_lineage(v)
    except ValueError as e:
        return str(e)
    return ""


check("refused: an ad_site_ou that is not the site's, or not under OU=sites",
      "is not site house2's OU" in lineage_refused({"site_name": "house2", "ad_site_ou": OU["house1"]})
      and "not a site's OU" in lineage_refused({"site_name": "x", "ad_site_ou": "OU=x,DC=ad"}))
check("the region's role (house1-network-operators) works at its branch house1a",
      mapped("house1a").get("house1-network-operators") == "fabric-network-operator")
check("...and at the region itself", mapped("house1").get("house1-network-operators") == "fabric-network-operator")
check("refused: not at a branch of another region (house2a), nor at that region (house2)",
      "house1-network-operators" not in mapped("house2a") and "house1-network-operators" not in mapped("house2"))
check("refused: not at the top (lan maps no region's groups)", not any(g.startswith("house1") for g in mapped("lan")))
check("the top's own granted roles reach every site (lan-helpdesk at house2a)",
      mapped("house2a").get("lan-helpdesk") == "fabric-helpdesk")
check("refused: a site's own helpdesk (<site>-admins) never reaches below it",
      "house1-admins" not in mapped("house1a") and mapped("house1a").get("house1a-admins") == "fabric-site-helpdesk")


class FakeKc:
    """Purpose: Keycloak's admin API, as ensure_site_group_mapper calls it, recorded. Inputs: none. Returns: per call.
    Fails: never. Feeds: the mapper checks below."""
    def __init__(self):
        self.made = []

    def call(self, method, path, body=None):
        if method == "POST" and path.endswith("/components"):
            self.made.append(body)
        return 200, [dict(m, id="m1") for m in self.made]


mapper_mod.step = lambda text: None
fake = FakeKc()
mapper_mod.ensure_site_group_mapper(fake, "r", "ldap1", {"site_name": "house1a", "ad_site_ou": OU["house1a"],
                                                          "ad_base_dn": "DC=ad,DC=test"})
cfg = fake.made[0]["config"]
check("house1a's Keycloak searches from the top site's OU and names its own groups and its ancestors' role groups",
      cfg["groups.dn"] == ["OU=lan,OU=sites,DC=ad,DC=test"] and "(cn=house1a-admins)" in cfg["groups.ldap.filter"][0]
      and "(cn=house1-pki-operators)" in cfg["groups.ldap.filter"][0]
      and "(cn=lan-auditors)" in cfg["groups.ldap.filter"][0], cfg)
check("...never a sibling's, a site below's, or an ancestor's helpdesk",
      "house2" not in cfg["groups.ldap.filter"][0] and "(cn=house1-admins)" not in cfg["groups.ldap.filter"][0]
      and "(cn=lan-admins)" not in cfg["groups.ldap.filter"][0], cfg)

print("--- change_site_role (fabriclib)")
CALLS, AUDIT = [], []
change_mod.write_audit = lambda *a: AUDIT.append(a)


def dc(v, secrets, op, args=None, container="samba", server=None):
    CALLS.append((op, args))
    if args["target"] == v["site_name"]:
        raise ValidationError(f"only a site above {args['target']} may grant its roles: {v['site_name']} is not above "
                              "it (a site cannot grant itself)")
    return {"site": args["target"], "role": args["role"], "group": f"{args['target']}-{args['role']}",
            "member": args["member"] or f"{args['target']}-admins", "granted": args["grant"], "changed": True}


change_mod.run_op = dc
V = {"site_name": "lan"}
done = change_mod.change_site_role(V, "owner", "house1", "network-operators", secrets={})
check("a grant asks the DC's grant_site_role and is audited as SITE_ROLE_GRANT",
      CALLS[-1] == ("grant_site_role", {"target": "house1", "role": "network-operators", "member": "",
                                        "grant": True}) and AUDIT[-1][1] == "SITE_ROLE_GRANT" and done["changed"])
change_mod.change_site_role(V, "owner", "house1", "network-operators", grant=False, secrets={})
check("a revoke is audited as SITE_ROLE_REVOKE", AUDIT[-1][1] == "SITE_ROLE_REVOKE")
n = len(CALLS)
check("refused before the DC is asked: a malformed site, role or member",
      "letters, digits" in refused(change_mod.change_site_role, V, "o", "house 1", "helpdesk", secrets={})
      and "letters, digits" in refused(change_mod.change_site_role, V, "o", "house1", "help;desk", secrets={})
      and "letters, digits" in refused(change_mod.change_site_role, V, "o", "house1", "helpdesk", "a,b", secrets={})
      and len(CALLS) == n)
check("the DC's refusal of a site granting itself is passed on, nothing audited",
      "cannot grant itself" in refused(change_mod.change_site_role, {"site_name": "house1"}, "o", "house1",
                                       "helpdesk", secrets={}) and AUDIT[-1][1] == "SITE_ROLE_REVOKE")

print("--- POST /v1/federation/roles (agent/post_federation)")
post_fed.load_vars = lambda: V
# covers: agent:post.federation.roles +
res = post_fed.post_federation(["federation", "roles"], "owner", {"site": "house1", "role": "helpdesk",
                                                                  "member": "", "action": "grant"})
check("grant through the agent route", res["granted"] and res["group"] == "house1-helpdesk", res)
# covers: agent:post.federation.roles -
check("refused: no action, or one that is not grant or revoke",
      "grant or revoke" in refused(post_fed.post_federation, ["federation", "roles"], "o", {"site": "house1",
                                                                                         "role": "helpdesk"})
      and "grant or revoke" in refused(post_fed.post_federation, ["federation", "roles"], "o",
                                       {"site": "house1", "role": "helpdesk", "action": "give"}))
check("refused: a site granting itself through the route (the DC's refusal)",
      "cannot grant itself" in refused(post_fed.post_federation, ["federation", "roles"], "o",
                                       {"site": "lan", "role": "helpdesk", "action": "grant"}))
check("refused: another federation route", refused(post_fed.post_federation, ["federation", "x"], "o", {})
      == "RouteNotFound")

print("--- fabricctl federation roles")
roles_cli.change_site_role = lambda v, actor, site, role, member, grant, source="web": {
    "site": site, "role": role, "group": f"{site}-{role}", "member": member or f"{site}-admins", "granted": grant,
    "changed": True}
roles_cli.site_roles = lambda v: {"sites": [
    {"site": "house1", "own": True, "roles": [{"role": "ou-admins", "kind": "ad", "bundle": "", "group": "house1-ou-admins", "exists": True, "members":
                                                ["house1-admins"], "pending": True},
                                               {"role": "helpdesk", "kind": "console", "bundle": "fabric-helpdesk",
                                                "group": "house1-helpdesk", "exists": False, "members": [],
                                                "pending": False}]},
    {"site": "house1a", "own": False, "roles": [{"role": "network-operators", "kind": "console",
                                                 "bundle": "fabric-network-operator", "exists": True,
                                                 "group": "house1a-network-operators", "members": ["house1a-admins"],
                                                 "pending": False}]}]}
# covers: cli:federation.roles +
code, out = run(roles_cli.run_roles_command, V, ["grant", "house1a", "network-operators"])
check("roles grant <site> <role>: to the site's admins", code == 0 and
      "network-operators at house1a granted to house1a-admins" in out, out)
code, out = run(roles_cli.run_roles_command, V, ["revoke", "house1a", "pki-operators", "--from", "jdoe"])
check("roles revoke <site> <role> --from <member>", code == 0 and "revoked from jdoe" in out, out)
grant_cli = roles_cli.change_site_role
roles_cli.change_site_role = lambda *a, **kw: {**grant_cli(*a, **kw), "remade": True}
code, out = run(roles_cli.run_roles_command, V, ["grant", "house1a", "gpo-admins"])
check("a grant that replaced a group the site had made itself says so", code == 0 and "remade:" in out, out)
roles_cli.change_site_role = grant_cli
code, out = run(roles_cli.run_roles_command, V, [])
check("roles: each site's held roles, its own marked, an old default marked pending, the empty ones left out",
      code == 0 and "site house1 (this site" in out and "an older default" in out and "house1a-admins" in out
      and "helpdesk" not in out.split("site house1a")[0].split("\n", 1)[1], out)
# covers: cli:federation.roles -
code, out = run(roles_cli.run_roles_command, V, ["grant", "house1a"])
code2, _ = run(roles_cli.run_roles_command, V, ["grant", "house1a", "helpdesk", "--from", "jdoe"])
check("usage (exit 2): a grant without a role; --from on a grant", code == 2 and code2 == 2)
check("refused: a site this one does not show", "no site house2 here" in refused(roles_cli.run_roles_command, V,
                                                                                 ["house2"]))


class Ctx:
    vars = V


fed_cli.run_roles_command = lambda v, args: 2
buf = io.StringIO()
with redirect_stderr(buf):
    code = fed_cli.run_federation_command(Ctx(), ["roles", "bogus", "x"])
check("fabricctl federation roles with bad words prints the usage (exit 2)",
      code == 2 and "federation roles grant" in buf.getvalue())

print("--- sibling isolation: the address plan (visible_plan, sites_shown)")
PLAN = [{"site": "lan", "name": "lan", "cidr": "10.0.0.0/24", "allow_overlap": ""},
        {"site": "house1", "name": "lan", "cidr": "10.1.0.0/24", "allow_overlap": ""},
        {"site": "house1a", "name": "lan", "cidr": "10.1.1.0/24", "allow_overlap": ""},
        {"site": "house2", "name": "lan", "cidr": "10.1.0.0/25", "allow_overlap": ""},
        {"site": "house3", "name": "iot", "cidr": "10.1.0.128/25", "allow_overlap": "never routed together"}]
seen = visible_plan(PLAN, ["house1", "house1a"])
check("house1 shows itself and house1a, never its siblings' or the top's networks",
      {p["site"] for p in seen["plan"]} == {"house1", "house1a"}, seen["plan"])
check("...its overlap with house2 counted, never named; an allowed one with house3 not even counted",
      seen["overlaps"] == [] and seen["hidden_overlaps"] == 1, seen)
top = visible_plan(PLAN, None)
check("the top (names None) shows every site and names every overlap",
      len(top["plan"]) == 5 and {c["other_site"] for c in top["overlaps"]} >= {"house1", "house2"}
      and top["hidden_overlaps"] == 0, top["overlaps"])
vis_mod.load_registry = lambda: {"upstream": {"site_name": "lan"}, "sites": {"house1a": {}}}
check("sites_shown: a site with an upstream shows itself and its registry's sites below",
      shown_mod.sites_shown({"site_name": "house1"}, {"upstream": {"site_name": "lan"}}) == ["house1", "house1a"])
check("sites_shown: the top (no upstream) shows every site", shown_mod.sites_shown({"site_name": "lan"}, {}) is None)

nets_mod.read_address_plan = lambda v: PLAN
nets_mod.sites_shown = lambda v: ["house1", "house1a"]
nets_mod.site_networks = lambda v: []
code, out = run(nets_mod.show_networks, {"site_name": "house1"})
check("fabricctl federation networks at house1: no sibling's or parent's network, the hidden overlap counted",
      "house2" not in out and "10.0.0.0/24" not in out and "OVERLAP 1 with a site this one does not show" in out
      and code == 1, out)

print("--- sibling isolation: fabricctl ipam find")
ROWS = [{"site": s, "vlan": "", "vlan_name": "", "subnet": "10.1.0.0/24", "ip": "10.1.0.5", "kind": "address",
         "range": "", "name": "nas", "mac": "", "owner": "", "dns": "", "lease": "", "notes": ""}
        for s in ("lan", "house1", "house1a", "house2")]
ipam_cli.read_plan = lambda *a, **kw: {"plans": {}}
ipam_cli._leases = lambda v, site: None
ipam_cli.find_in_plan = lambda read, text, leases, site: list(ROWS)
ipam_cli.sites_shown = lambda v: ["house1", "house1a"]
# covers: cli:ipam.find +
code, out = run(ipam_cli.run_ipam_command, {"site_name": "house1"}, ["find", "nas"], {}, "samba")
check("ipam find at house1: its own and house1a's rows only", code == 0 and "house1a" in out and "house2" not in out
      and "lan " not in out.replace("vlan", ""), out)
ipam_cli.sites_shown = lambda v: None
code, out = run(ipam_cli.run_ipam_command, {"site_name": "lan"}, ["find", "nas"], {}, "samba")
check("ipam find at the top: every site's", code == 0 and "house2" in out, out)
ipam_cli.sites_shown = lambda v: ["house2"]
ipam_cli.find_in_plan = lambda read, text, leases, site: [r for r in ROWS if r["site"] == "house1"]
# covers: cli:ipam.find -
code, out = run(ipam_cli.run_ipam_command, {"site_name": "house2"}, ["find", "nas"], {}, "samba")
check("ipam find at house2 for a name only its sibling has: not found (exit 1), the sibling not named",
      code == 1 and "not in any site's plan" in out and "house1" not in out, out)

print("--- sibling isolation: fabricctl ipam show <site> and ipam export [<site>]")
READS = []
ipam_cli.read_plan = lambda v, secrets=None, of="", container="samba": READS.append(of) or {
    "plans": {n: {} for n in ("lan", "house1", "house1a", "house2")}}
ipam_cli.show_plan = lambda read, which, leases: f"plan of {which}\n"
ipam_cli.export_plan = lambda read, site, leases, own: "sites:" + ",".join(sorted(read["plans"])) + "\n"
ipam_cli.sites_shown = lambda v: ["house1", "house1a"]
H1 = {"site_name": "house1"}
# covers: cli:ipam.show +
code, out = run(ipam_cli.run_ipam_command, H1, ["show", "house1a"], {}, "samba")
check("ipam show at house1 of house1a (a site below): shown", code == 0 and "plan of house1a" in out, out)
for name in ("house2", "lan", "nowhere"):
    n = len(READS)
    # covers: cli:ipam.show -
    code, out = run(ipam_cli.run_ipam_command, H1, ["show", name], {}, "samba")
    check(f"refused: ipam show at house1 of {name} (a sibling, the parent, unknown), before AD is read",
          code == 1 and "shows only itself and the sites below it" in out and len(READS) == n, out)
# covers: cli:ipam.export +
code, out = run(ipam_cli.run_ipam_command, H1, ["export"], {}, "samba")
check("ipam export at house1 without a site: only house1 and house1a", code == 0
      and "sites:house1,house1a" in out, out)
n = len(READS)
# covers: cli:ipam.export -
code, out = run(ipam_cli.run_ipam_command, H1, ["export", "house2"], {}, "samba")
check("refused: ipam export at house1 of its sibling house2, before AD is read",
      code == 1 and "shows only itself" in out and len(READS) == n, out)
ipam_cli.sites_shown = lambda v: None
code, out = run(ipam_cli.run_ipam_command, {"site_name": "lan"}, ["export"], {}, "samba")
check("ipam export at the top: every site", code == 0 and "sites:house1,house1a,house2,lan" in out, out)
code, out = run(ipam_cli.run_ipam_command, {"site_name": "lan"}, ["show", "house2"], {}, "samba")
check("ipam show at the top of any site", code == 0 and "plan of house2" in out, out)

print("--- the console: the Roles card and the People note")
try:
    from webui.views.federation import federation
    from webui.views.render_page import render_page
except ImportError as e:                    # jinja2 missing on this machine: the webui suite renders them
    print(f"SKIP the console's pages: {e}")
    federation = None
if federation:
    overview = {"site": "house1", "upstream": {"site_name": "lan", "domain": "lan.test"}, "sites": [],
                "replication": {"neighbours": []}, "conflicts": [], "limits": [], "plan": [], "overlaps": [],
                "hidden_overlaps": 2, "plan_error": "", "roles_error": "",
                "roles": roles_cli.site_roles(V)["sites"]}
    ctx = {"user": "owner", "csrf": "t", "perms": ["federation:read", "federation:admin"], "version": {}}
    page = federation(ctx, overview, "done.", "")
    check("the Roles card lists each site's roles, this site marked, a pending default said",
          "house1-ou-admins" in page and "house1a-network-operators" in page and "only a site above grants" in page
          and "taken away at the next convergence" in page, page[-2000:])
    form = page.split('action="/federation/roles"')[1].split("</form>")[0] if 'action="/federation/roles"' in page \
        else ""
    check("...the grant form for federation:admin, its sites only those below",
          "<option>house1a</option>" in form and "<option>house1</option>" not in form, form[:300])
    check("...the hidden overlaps counted; the plan titled for this site and those below",
          "2 overlap(s) with a site this one does not show" in page and "the sites&#39; below it" in page)
    reader = federation({**ctx, "perms": ["federation:read"]}, overview)
    check("without federation:admin no grant form", 'action="/federation/roles"' not in reader)
    people = render_page("directory", ctx={**ctx, "perms": ["site:people:read", "site:people:unlock",
                                                            "site:people:reset"]}, tab="directory", view="people",
                         people={"users": [{"uid": "ann", "name": "Ann", "mail": "", "locked": True,
                                            "groups": [], "site": "house1"}], "groups": [], "keycloak_url": "#"},
                         data={"devices": [], "roles": [], "types": [], "permissions": {}}, msg="", err="",
                         unavailable="", domain=None, device=None, role=None)
    check("People for the site helpdesk: the own-site note, Unlock and Reset shown (the site forms count), no "
          "Remove or groups form", "this site's own people only" in people and "/people/ann/unlock" in people
          and "/people/ann/reset" in people and "people/_form/delete" not in people, people[-1500:])

print("--- the console's posts: POST /federation/roles and /directory/people/<uid>/unlock (webui routes)")
try:
    from webui import agentclient as web_actions
    from webui.routes.directory_post import directory_post
    from webui.routes.federation_post import federation_post
except ImportError as e:                    # a webui dependency missing on this machine: the webui suite posts them
    print(f"  (skipped: {e})")
    federation_post = None
if federation_post:
    class FakeHandler:
        """Purpose: the request handler's redirect and deny, recorded. Inputs: none. Returns: the call's tuple.
        Fails: never. Feeds: the console post checks below."""
        def redirect(self, url):
            return ("redirect", url)

        def deny(self, code, text):
            return ("deny", code, text)

    def role_change(site, role, member, action):
        if site != "house1a":
            raise web_actions.ValidationError(f"only a site above {site} may grant its roles")
        return {"site": site, "role": role, "member": member or f"{site}-admins", "granted": action == "grant",
                "changed": True}

    web_actions.site_role_change = role_change
    # covers: web:post.federation.roles +
    res = federation_post(FakeHandler(), {"site": "house1a", "role": "helpdesk", "member": "", "action": "grant"})
    check("Federation tab: a grant at a site below goes back to the tab saying what was granted",
          res[0] == "redirect" and "msg=" in res[1] and "house1a-admins" in urllib_unquote(res[1]), res)
    # covers: web:post.federation.roles -
    res = federation_post(FakeHandler(), {"site": "house2", "role": "helpdesk", "member": "", "action": "grant"})
    check("refused: a grant at a site not below goes back with why", res[0] == "redirect" and "err=" in res[1]
          and "only a site above" in urllib_unquote(res[1]), res)

    def person_action(uid, op, extra=None):
        if uid != "ann":
            raise web_actions.ValidationError(f"{uid} is not one of this site's own people")
        return {"uid": uid, "unlocked": True}

    web_actions.person_action = person_action
    sess = {"user": "deskh1", "perms": ["site:people:unlock"]}
    # covers: web:post.directory.people.*.unlock +
    res = directory_post(FakeHandler(), sess, ["people", "ann", "unlock"], {})
    check("People: Unlock goes back to the list saying the person was unlocked",
          res[0] == "redirect" and "ann unlocked" in urllib_unquote(res[1]), res)
    # covers: web:post.directory.people.*.unlock -
    res = directory_post(FakeHandler(), sess, ["people", "bob", "unlock"], {})
    check("refused: unlocking someone not this site's own goes back with why",
          res[0] == "redirect" and "err=" in res[1] and "not one of this site" in urllib_unquote(res[1]), res)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
