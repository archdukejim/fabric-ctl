"""The site helpdesk in fabric-agent, without containers (decision 2.1.9.21, manual 1.6.8.2): a site's admins hold the
site forms of the people permissions; the agent accepts them for the people routes only and narrows each change to
this site's own people who hold no role — a reset, an unlock, a disable or enable refused for another site's person
(a sub-site's, a sibling's, a parent's) or for anyone in a fabric group or a site's admin or role group; the People
list narrowed to this site's people; the full permission never narrowed. `people:unlock` is new: its route, the CLI
and the bundles that carry it. The directory and Keycloak are stand-ins here (2.1.1.27); tests/samba/roles.py and the
keycloak and webui suites run them for real.
    python3 tests/samba/site_helpdesk_test.py"""
import io
import os
import sys
from contextlib import redirect_stdout

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.directory.common.person_guard as guard_mod  # noqa: E402
from fabriclib.directory.common.site_helpdesk_refusal import site_helpdesk_refusal  # noqa: E402
import fabriclib.directory.list_people as list_mod  # noqa: E402
import fabriclib.directory.run_people_command as cli_mod  # noqa: E402
import fabriclib.directory.unlock_person as unlock_mod  # noqa: E402
from fabriclib.rbac.holds_permission import holds_permission  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES, PERMISSIONS, SITE_SCOPED  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
import agent.get_route as get_mod  # noqa: E402
import agent.post_people as post_mod  # noqa: E402
from agent.route_not_found import RouteNotFound  # noqa: E402

PASS = FAIL = 0
V = {"site_name": "house1", "webui_admin_group": "admins",
     "ldap_groups": [{"name": "helpdesk", "bundle": "fabric-helpdesk"}, {"name": "network-staff"}]}
SITE = "OU=house1,OU=lan,OU=sites,DC=ad,DC=test"
PEOPLE = {
    "ann": {"uid": "ann", "dn": f"CN=ann,OU=people,{SITE}", "groups": ["house1-users"]},
    "kid": {"uid": "kid", "dn": f"CN=kid,OU=people,OU=house1a,{SITE}", "groups": ["house1a-users"]},
    "sib": {"uid": "sib", "dn": "CN=sib,OU=people,OU=house2,OU=lan,OU=sites,DC=ad,DC=test", "groups": ["house2-users"]},
    "top": {"uid": "top", "dn": "CN=top,OU=people,OU=lan,OU=sites,DC=ad,DC=test", "groups": ["lan-users"]},
    "boss": {"uid": "boss", "dn": f"CN=boss,OU=people,{SITE}", "groups": ["house1-users", "house1-admins"]},
    "it": {"uid": "it", "dn": f"CN=it,OU=people,{SITE}", "groups": ["house1-users", "admins"]},
    "desk": {"uid": "desk", "dn": f"CN=desk,OU=people,{SITE}", "groups": ["helpdesk"]},
    "netop": {"uid": "netop", "dn": f"CN=netop,OU=people,{SITE}", "groups": ["house1-network-operators"]},
    "host": {"uid": "host", "dn": f"CN=host,OU=people,{SITE}", "groups": ["house1-fabric-admins"]},
    "wifi": {"uid": "wifi", "dn": f"CN=wifi,OU=people,{SITE}", "groups": ["network-staff", "house1-users"]},
}
SITE_HELPDESK = set(BUNDLES["fabric-site-helpdesk"])
HELPDESK = set(BUNDLES["fabric-helpdesk"])


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


CALLS = []


def fake_run_op(v, secrets, op, args=None, container="samba", server=None):
    CALLS.append((op, args))
    if op == "get_person":
        if args["uid"] not in PEOPLE:
            raise ValidationError("no such entry")
        return PEOPLE[args["uid"]]
    if op == "unlock_person":
        return {"uid": args["uid"], "unlocked": True}
    if op == "list_people":
        return {"users": [{"uid": u, "site": p["dn"].split(",")[2][3:], "groups": p["groups"], "locked": False}
                          for u, p in PEOPLE.items()], "groups": []}
    return {}


guard_mod.run_op = fake_run_op
unlock_mod.run_op = fake_run_op
list_mod.run_op = fake_run_op
unlock_mod.clear_lockout = lambda v, s, uid: CALLS.append(("clear_lockout", uid)) or 1
AUDIT = []
unlock_mod.write_audit = lambda *a: AUDIT.append(a)

print("--- the bundle and the permission check (rbac)")
check("the site helpdesk bundle holds the site forms of the people permissions and status only",
      SITE_HELPDESK == {"status:read", "site:people:read", "site:people:create", "site:people:reset",
                        "site:people:unlock", "site:people:disable"}, SITE_HELPDESK)
check("...never people:remove, people:groups, a device, DHCP, DNS, machines or GPO permission",
      not SITE_HELPDESK & {"people:remove", "people:groups", "devices:enroll", "dhcp:write", "dns:write",
                           "machines:admin", "gpo:admin", "sudo:admin", "federation:admin"})
check("every site form is a permission, and names the plain one it narrows",
      all(f in PERMISSIONS and p in PERMISSIONS and f == "site:" + p for p, f in SITE_SCOPED.items()))
check("people:unlock is the helpdesk's and the admin's; federation:admin the admin's only",
      "people:unlock" in HELPDESK and "people:unlock" in BUNDLES["admin"] and "federation:admin" in BUNDLES["admin"]
      and not any("federation:admin" in p for b, p in BUNDLES.items() if b != "admin"))
check("holds_permission: the plain permission is full, a site form is site, neither is nothing, session is full",
      holds_permission(HELPDESK, "people:reset") == "full" and holds_permission(SITE_HELPDESK, "people:reset") == "site"
      and holds_permission(SITE_HELPDESK, "dhcp:write") == "" and holds_permission(set(), "session") == "full")
check("a site form never stands in for a permission it does not narrow (machines, GPO, DHCP, devices, removing)",
      all(holds_permission(SITE_HELPDESK, required_permission("POST", r)) == "" for r in
          (["machines"], ["machines", "pc1", "disable"], ["gpo", "set"], ["dhcp", "reservations"], ["devices"],
           ["people", "ann", "delete"], ["people", "ann", "groups"], ["networks", "house1", "vlans"],
           ["federation", "roles"])))
check("the routes: POST people/<uid>/unlock needs people:unlock, POST federation/roles federation:admin",
      required_permission("POST", ["people", "x", "unlock"]) == "people:unlock"
      and required_permission("POST", ["federation", "roles"]) == "federation:admin")

print("--- site_helpdesk_refusal: own site's people who hold no role")
check("allowed: a person of this site's own OU=people", site_helpdesk_refusal(V, PEOPLE["ann"], "x") == "")
for who, words, what in (("kid", "not a person of site house1", "a sub-site's person"),
                         ("sib", "not a person of site house1", "a sibling's person"),
                         ("top", "not a person of site house1", "the parent's person"),
                         ("boss", "holds a role (house1-admins)", "another local admin"),
                         ("it", "holds a role (admins)", "Central IT (the organisation's admins)"),
                         ("desk", "holds a role (helpdesk)", "a member of a fabric bundle group"),
                         ("netop", "holds a role (house1-network-operators)", "a granted operator"),
                         ("host", "holds a role (house1-fabric-admins)", "a host admin")):
    why = site_helpdesk_refusal(V, PEOPLE[who], "reset their sign-in")
    check(f"refused: {what}", words in why, why)
check("an 802.1X group (no bundle) is not a role", site_helpdesk_refusal(V, PEOPLE["wifi"], "x") == "")

print("--- person_guard with own_site")
check("own_site refuses another site's person before anything changes",
      "not a person of site house1" in refused(guard_mod.person_guard, V, {}, "sib", False, "reset", own_site=True))
check("without own_site (the full permission) that person passes the guard",
      refused(guard_mod.person_guard, V, {}, "sib", False, "reset") == "")

print("--- the agent's people routes (agent/post_people)")
SEEN = []
post_mod.load_vars = lambda: V
post_mod.reset_sign_in = lambda v, a, uid, priv, own_site=False: SEEN.append(("reset", uid, own_site)) or "pw"
post_mod.unlock_person = lambda v, a, uid, priv, own_site=False: SEEN.append(("unlock", uid, own_site)) or {"uid": uid}
post_mod.set_person_enabled = lambda v, a, uid, en, priv, own_site=False: SEEN.append(("enabled", uid, en, own_site))
post_mod.create_person = lambda v, a, uid, f, last, e: SEEN.append(("create", uid)) or "pw"
post_mod.remove_person = lambda *a: SEEN.append(("remove",))
post_mod.set_person_group = lambda *a: SEEN.append(("groups",))
# covers: agent:post.people.*.unlock +
post_mod.post_people(["people", "ann", "unlock"], "boss", {}, SITE_HELPDESK)
post_mod.post_people(["people", "ann", "reset"], "boss", {}, SITE_HELPDESK)
post_mod.post_people(["people", "ann", "disable"], "boss", {}, SITE_HELPDESK)
post_mod.post_people(["people"], "boss", {"uid": "neo", "first": "N", "last": "O", "email": "n@o.test"}, SITE_HELPDESK)
check("the site helpdesk's unlock, reset and disable are narrowed to this site (own_site); add adds to this site",
      SEEN == [("unlock", "ann", True), ("reset", "ann", True), ("enabled", "ann", False, True), ("create", "neo")],
      SEEN)
SEEN.clear()
post_mod.post_people(["people", "ann", "unlock"], "desk", {}, HELPDESK)
post_mod.post_people(["people", "ann", "reset"], "root", {}, None)
check("the full permission (Central IT's helpdesk) and root are never narrowed",
      SEEN == [("unlock", "ann", False), ("reset", "ann", False)], SEEN)
# covers: agent:post.people.*.unlock -
check("refused: an unknown people action, and a groups change without add or remove",
      refused(post_mod.post_people, ["people", "ann", "promote"], "x", {}, HELPDESK) == "RouteNotFound"
      and "add or remove" in refused(post_mod.post_people, ["people", "ann", "groups"], "x", {}, HELPDESK))

print("--- unlock_person (fabriclib) and the People list")
CALLS.clear()
done = unlock_mod.unlock_person(V, "boss", "ann", own_site=True, secrets={})
check("unlock: the DC's operation, Keycloak's lockout cleared, audited",
      done["unlocked"] and ("unlock_person", {"uid": "ann"}) in CALLS and ("clear_lockout", "ann") in CALLS
      and AUDIT[-1][1] == "PERSON_UNLOCK", (CALLS, AUDIT[-1:]))
CALLS.clear()
why = refused(unlock_mod.unlock_person, V, "boss", "it", own_site=True, secrets={})
check("refused: the site helpdesk unlocking Central IT; nothing asked of the DC",
      "holds a role" in why and not any(c[0] == "unlock_person" for c in CALLS), (why, CALLS))
why = refused(unlock_mod.unlock_person, V, "boss", "sib", own_site=True, secrets={})
check("refused: the site helpdesk unlocking a sibling's person", "not a person of site house1" in why, why)
listed = [u["uid"] for u in list_mod.list_people({**V, "hostname_keycloak": "kc", "domain": "d"}, {},
                                                 own_site=True)["users"]]
check("the People list for the site helpdesk: this site's people only",
      set(listed) == {"ann", "boss", "it", "desk", "netop", "host", "wifi"}, listed)
SHOWN = []
get_mod.load_vars = lambda: V
get_mod.list_people = lambda v, own_site=False: SHOWN.append(own_site) or {"users": []}
# covers: agent:get.people +
get_mod.get_route(["people"], "boss", SITE_HELPDESK)
get_mod.get_route(["people"], "desk", HELPDESK)
get_mod.get_route(["people"], None, None)
check("GET /v1/people: narrowed for the site helpdesk only (not the helpdesk, not root)",
      SHOWN == [True, False, False], SHOWN)

print("--- fabricctl people unlock")
cli_mod.unlock_person = lambda v, actor, uid, privileged=False, source="web": {"uid": uid, "unlocked": uid == "ann"}
out = io.StringIO()
with redirect_stdout(out):
    # covers: cli:people.unlock +
    ok = cli_mod.run_people_command(V, ["unlock", "ann"])
    # covers: cli:people.unlock -
    bad = cli_mod.run_people_command(V, ["unlock"])
check("people unlock <uid>: unlocked; without a user name: usage (exit 2)",
      ok == 0 and "ann: unlocked" in out.getvalue() and bad == 2 and "people unlock <uid>" in out.getvalue(),
      out.getvalue()[-300:])

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
