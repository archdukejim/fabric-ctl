"""Layered roles in the DC's own operations, without a DC (decision 2.1.9.21, manual 1.6.3.18, 1.9.8.20): granting a
role at a site below (the target must be below this site: never itself, a sibling or a parent; the grantee must exist;
only grantable roles; the site's own admins' grant marked so convergence keeps it; a console role's group made when
missing), the narrowing of a site's admins out of its role groups (a marked grant kept; at the root the
organisation's admins kept in the root's roles), and the list of roles at this site and the sites below it (never a
sibling's, 2.1.9.22). The directory is a stand-in (tests/samba/fake_samdb.py); tests/samba/roles.py runs the same
against a real DC.
    python3 tests/samba/site_roles_test.py"""
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..")
sys.path[0:0] = [HERE, os.path.join(REPO, "src", "containers", "samba")]
import fake_samdb  # noqa: E402

fake_samdb.install()                     # the DC's operations import ldb: the stand-in
import paths  # noqa: E402
import site_roles  # noqa: E402
grant_site_role = importlib.import_module("grant_site_role").grant_site_role
narrow_site_admins = importlib.import_module("narrow_site_admins").narrow_site_admins
list_site_roles = importlib.import_module("list_site_roles").list_site_roles

PASS = FAIL = 0
BASE = "DC=ad,DC=test"
SITES = f"OU=sites,{BASE}"


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def domain():
    """The top lan, with house1 and house2 below it (siblings) and house1a below house1; every site's groups as 0.8
    left them: <site>-admins in each AD role group."""
    paths.forget()
    db = fake_samdb.FakeSamDB(BASE)
    db.add_entry(SITES, objectClass=["organizationalUnit"], ou="sites")
    layout = {"lan": f"OU=lan,{SITES}", "house1": f"OU=house1,OU=lan,{SITES}", "house2": f"OU=house2,OU=lan,{SITES}",
              "house1a": f"OU=house1a,OU=house1,OU=lan,{SITES}"}
    for site, dn in layout.items():
        db.add_entry(dn, objectClass=["organizationalUnit", "fabricSiteInfo"], ou=site)
        groups = f"OU=groups,{dn}"
        db.add_entry(groups, objectClass=["organizationalUnit"], ou="groups")
        db.add_entry(f"OU=people,{dn}", objectClass=["organizationalUnit"], ou="people")
        db.add_entry(f"CN={site}-admins,{groups}", objectClass=["group"], sAMAccountName=f"{site}-admins")
        db.add_entry(f"CN={site}-users,{groups}", objectClass=["group"], sAMAccountName=f"{site}-users")
        for role in list(site_roles.ROLES) + ["fabric-admins"]:
            db.add_entry(f"CN={site}-{role},{groups}", objectClass=["group"], sAMAccountName=f"{site}-{role}",
                         member=[f"CN={site}-admins,{groups}"])
    org = f"OU=groups,OU=organisation,{layout['lan']}"
    db.add_entry(org, objectClass=["organizationalUnit"])
    db.add_entry(f"CN=admins,{org}", objectClass=["group"], sAMAccountName="admins")
    db.add_entry(f"CN=jdoe,OU=people,{layout['house1']}", objectClass=["user"], objectCategory="person",
                 sAMAccountName="jdoe")
    db.add_entry(f"CN=svc,OU=service-accounts,{layout['house1']}", objectClass=["user"], objectCategory="person",
                 sAMAccountName="fabric-agent-house1")
    return db


def refused(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except (ValueError, KeyError, LookupError) as e:
        return str(e)
    return ""


def members(db, group):
    return [m.split(",")[0][3:] for m in db.search(SITES, expression=f"(sAMAccountName={group})")[0].get("member", [])]


def mark(db, group):
    return (db.search(SITES, expression=f"(sAMAccountName={group})")[0].get("adminDescription") or [""])[0]


print("--- the roles a site above may grant (site_roles)")
check("grantable: the four AD roles, the host admins and the five console roles",
      site_roles.grantable() == ["ou-admins", "machine-admins", "gpo-admins", "windows-admins", "fabric-admins",
                                 "network-operators", "equipment-operators", "pki-operators", "helpdesk", "auditors"])
check("a role's group: <site>-<role>", site_roles.grant_group("house1", "helpdesk") == "house1-helpdesk")
check("refused: the site's own admins group, or a made-up role, is not a grantable role",
      refused(site_roles.grant_group, "house1", "admins") and refused(site_roles.grant_group, "house1", "domain-admins"))

print("--- paths.below: the sites below a site")
db = domain()
check("the top sees every site below it; house1 sees only house1a; house2 none (never a sibling or parent)",
      paths.below(db, "lan") == ["house1", "house1a", "house2"] and paths.below(db, "house1") == ["house1a"]
      and paths.below(db, "house2") == [], (paths.below(db, "lan"), paths.below(db, "house1")))

print("--- grant_site_role (fabricctl federation roles grant|revoke, POST /v1/federation/roles)")
db = domain()
done = grant_site_role(db, None, "lan", "house1", "network-operators")
# covers: agent:post.federation.roles +
check("the top grants house1 network-operators: its console group made, house1-admins in it",
      done["changed"] and done["member"] == "house1-admins" and done["group"] == "house1-network-operators"
      and members(db, "house1-network-operators") == ["house1-admins"] and ("newgroup", "house1-network-operators")
      in db.log, (done, db.log[-3:]))
check("...and the group marked as granted to the site's admins (convergence keeps it)",
      mark(db, "house1-network-operators") == site_roles.GRANT_MARK)
again = grant_site_role(db, None, "lan", "house1", "network-operators")
check("granting it again changes nothing", not again["changed"])
person = grant_site_role(db, None, "lan", "house1", "machine-admins", "jdoe")
check("a role granted to a person (jdoe), the group not marked for a person",
      person["changed"] and "jdoe" in members(db, "house1-machine-admins") and mark(db, "house1-machine-admins") == "")
nested = grant_site_role(db, None, "house1", "house1a", "helpdesk")
check("a site grants the site below it (house1 -> house1a)", nested["changed"], nested)
# covers: agent:post.federation.roles -
why = refused(grant_site_role, db, None, "house1", "house1", "network-operators")
check("refused: a site granting itself (the branch cannot grant itself)",
      "only a site above house1" in why and "cannot grant itself" in why, why)
why = refused(grant_site_role, db, None, "house1", "house2", "network-operators")
check("refused: a site granting its sibling", "house1 is not above it" in why, why)
why = refused(grant_site_role, db, None, "house1a", "house1", "helpdesk")
check("refused: a site granting its parent", "house1a is not above it" in why, why)
check("refused: a role that cannot be granted", "not a role a site can be granted" in
      refused(grant_site_role, db, None, "lan", "house1", "domain-admins"))
check("refused: a grantee that is not a group or person", "no group or person" in
      refused(grant_site_role, db, None, "lan", "house1", "helpdesk", "nobody"))
check("refused: a service account as grantee", "no group or person" in
      refused(grant_site_role, db, None, "lan", "house1", "helpdesk", "fabric-agent-house1"))
check("refused: an unknown site", refused(grant_site_role, db, None, "lan", "nowhere", "helpdesk"))
before = list(db.log)
gone = grant_site_role(db, None, "lan", "house1", "network-operators", grant=False)
check("revoking takes house1-admins out and clears the mark",
      gone["changed"] and not gone["granted"] and members(db, "house1-network-operators") == []
      and mark(db, "house1-network-operators") == "", (gone, db.log[len(before):]))

print("--- narrow_site_admins (each convergence; 0.9's upgrade)")
db = domain()
grant_site_role(db, None, "lan", "house1", "gpo-admins")           # granted before the narrowing: kept
changed = narrow_site_admins(db, "house1", False, "admins")
check("house1-admins taken out of the AD roles and the host admins it held by default, each said why",
      all("house1-admins" not in members(db, f"house1-{r}") for r in ("ou-admins", "machine-admins", "windows-admins",
                                                                       "fabric-admins"))
      and len([c for c in changed if "house1-admins removed (2.1.9.21" in c]) == 4, changed)
check("...but kept where a site above granted it (gpo-admins, marked)", "house1-admins" in members(db, "house1-gpo-admins"))
check("house1-admins nested in house1-users (Keycloak admits the site's users), said why",
      members(db, "house1-users") == ["house1-admins"]
      and any(c.startswith("group house1-users: house1-admins a member") for c in changed), changed)
check("a second run changes nothing", narrow_site_admins(db, "house1", False, "admins") == [])
root = narrow_site_admins(db, "lan", True, "admins")
check("at the root: lan-admins out, the organisation's admins in the root's four AD roles (Central IT everywhere)",
      all("admins" in members(db, f"lan-{r}") and "lan-admins" not in members(db, f"lan-{r}") for r in site_roles.ROLES)
      and "admins" not in members(db, "lan-fabric-admins") and any("Central IT" in c for c in root), root)
check("...and at the root too: lan-admins nested in lan-users", members(db, "lan-users") == ["lan-admins"])
db.add_remove_group_members("house1-users", ["house1-admins"], add_members_operation=False)
again = narrow_site_admins(db, "house1", False, "admins")
check("taken out of house1-users by hand: put back at the next convergence, nothing else changed",
      members(db, "house1-users") == ["house1-admins"] and len(again) == 1, again)
check("a site without its groups yet: nothing to do, no error", narrow_site_admins(db, "nowhere", False, "admins") == [])

print("--- a branch cannot grant through its agent's credentials (ensure_site_acl; 2.1.9.21 revised 2026-10-13)")
ensure_site_acl_mod = importlib.import_module("ensure_site_acl")
db = domain()
db.add_entry(f"CN=house1-helpdesk,OU=groups,OU=house1,OU=lan,{SITES}", objectClass=["group"],
             sAMAccountName="house1-helpdesk")
acl = ensure_site_acl_mod.ensure_site_acl(db, "house1", False)
G1 = f"OU=groups,OU=house1,OU=lan,{SITES}"
for group in ("house1-ou-admins", "house1-fabric-admins", "house1-helpdesk", "house1-admins"):
    check(f"{group}: house1's agent and OU admins denied every write (members, name, delete, permissions)",
          f"CN={group},{G1}: (D;;WPSDDTWDWO;;;SID-fabric-agent-house1)" in acl
          and f"CN={group},{G1}: (D;;WPSDDTWDWO;;;SID-house1-ou-admins)" in acl
          and f"CN={group},{G1}: (OD;;WP;GUID-member;;SID-fabric-agent-house1)" in acl, [a for a in acl if group in a])
check("...a console role group not made yet is skipped (house1-auditors)", not any("house1-auditors" in a for a in acl))
check("...house1-users stays the agent's (a new person joins it): no deny there",
      not any(a.startswith(f"CN=house1-users,{G1}: (D") or a.startswith(f"CN=house1-users,{G1}: (OD") for a in acl))
check("...the agent keeps its full control of the site's OU (its per-site rights unchanged)",
      f"OU=house1,OU=lan,{SITES}: (A;CI;{ensure_site_acl_mod.FULL};;;SID-fabric-agent-house1)" in acl)
db.add_entry(f"OU=organisation,OU=lan,{SITES}", objectClass=["organizationalUnit"], ou="organisation")
root = ensure_site_acl_mod.ensure_site_acl(db, "lan", True)
check("at the top no such deny (Central IT grants there)", not any("WPSDDTWDWO" in a for a in root))
db.objects[f"CN=house1-gpo-admins,{G1}"]["_owner"] = ["SID-fabric-agent-house1"]   # deleted and made again
why = ""
try:
    ensure_site_acl_mod.ensure_site_acl(db, "house1", False)
except PermissionError as e:
    why = str(e)
check("refused: a role group house1's agent made itself is given no rights, said why",
      "house1-gpo-admins was made by fabric-agent-house1" in why and "4.9.1.2" in why, why)
remade = grant_site_role(db, None, "lan", "house1", "gpo-admins")
check("the top's grant replaces it: deleted, made again empty with a gid, then granted (owned by the system here)",
      remade["remade"] and remade["changed"] and members(db, "house1-gpo-admins") == ["house1-admins"]
      and ("delete", f"CN=house1-gpo-admins,{G1}") in db.log
      and db.objects[f"CN=house1-gpo-admins,{G1}"].get("gidnumber"), (remade, db.log[-5:]))
check("...and convergence takes it again", ensure_site_acl_mod.ensure_site_acl(db, "house1", False) != [])
db.delete(f"CN=house1-fabric-admins,{G1}")
db.add_entry(f"CN=fabric-admins,OU=groups,OU=organisation,OU=lan,{SITES}", objectClass=["group"],
             sAMAccountName="fabric-admins")
made = grant_site_role(db, None, "lan", "house1", "fabric-admins", "jdoe")
check("a missing host admins group is made by the grant, the organisation's fabric-admins in it",
      not made["remade"] and sorted(members(db, "house1-fabric-admins")) == ["fabric-admins", "jdoe"], made)

print("--- an AD role granted at a site works at every site below it (ensure_site_acl; 2.1.9.21 revised 2026-10-13)")
db = domain()
A1A = f"OU=house1a,OU=house1,OU=lan,{SITES}"
sub = ensure_site_acl_mod.ensure_site_acl(db, "house1a", False)
FULL = ensure_site_acl_mod.FULL
for owner in ("house1a", "house1", "lan"):
    check(f"house1a's machines and devices: {owner}-machine-admins full control there",
          all(f"OU={ou},{A1A}: (A;CI;{FULL};;;SID-{owner}-machine-admins)" in sub for ou in ("machines", "devices")),
          [a for a in sub if "machine-admins" in a])
    check(f"house1a's GPO links: {owner}-gpo-admins may write them",
          f"{A1A}: (OA;;RPWP;{ensure_site_acl_mod.GP_LINK};;SID-{owner}-gpo-admins)" in sub)
check("the OU admins reach it by inheritance only: house1's entry sits on house1's OU, with CI (none added here)",
      not any("house1-ou-admins)" in a and "(A;CI" in a for a in sub)
      and f"OU=house1,OU=lan,{SITES}: (A;CI;{FULL};;;SID-house1-ou-admins)"
      in ensure_site_acl_mod.ensure_site_acl(db, "house1", False))
sib = ensure_site_acl_mod.ensure_site_acl(db, "house2", False)
check("refused: a region's machine and GPO admins get nothing at a site of another region (house2)",
      not any("SID-house1-" in a or "SID-house1a-" in a for a in sib), [a for a in sib if "house1" in a])
check("refused: a site below gets nothing at the site above it (house1a's roles at house1)",
      not any("SID-house1a-" in a for a in ensure_site_acl_mod.ensure_site_acl(db, "house1", False)))

print("--- remake_site_group (fabricctl federation roles remake; 2.3.9.2.8 option (a))")
remake = importlib.import_module("remake_site_group").remake_site_group
db = domain()
G1 = f"OU=groups,OU=house1,OU=lan,{SITES}"
db.objects[f"CN=house1-admins,{G1}"]["_owner"] = ["SID-fabric-agent-house1"]      # the branch re-made it
db.objects[f"CN=house1-admins,{G1}"]["member"] = [f"CN=jdoe,OU=people,OU=house1,OU=lan,{SITES}"]
done = remake(db, None, "lan", "house1", "admins")
check("the top remakes house1-admins the branch had made: replaced, empty, a gid, nested in house1-users",
      done["remade"] and done["changed"] and members(db, "house1-admins") == []
      and db.objects[f"CN=house1-admins,{G1}"].get("gidnumber") and "house1-admins" in members(db, "house1-users")
      and db.objects[f"CN=house1-admins,{G1}"]["_owner"] == ["SID-system"], (done, db.log[-4:]))

done = remake(db, None, "lan", "house1", "helpdesk")
check("a missing console role group is made", done["made"] and not done["remade"]
      and f"CN=house1-helpdesk,{G1}" in db.objects, done)
done = remake(db, None, "lan", "house1", "ou-admins")
check("a group fabric made is left as it is (nothing changed)", not done["changed"]
      and members(db, "house1-ou-admins") == ["house1-admins"], done)
check("a site remakes the group of the site below it (house1 -> house1a)",
      not remake(db, None, "house1", "house1a", "gpo-admins")["remade"])
for args, why in ((("house1", "house1", "admins"), "a site cannot repair its own"),
                  (("house1", "house2", "admins"), "house1 is not above it"),
                  (("house1a", "house1", "admins"), "house1a is not above it"),
                  (("lan", "house1", "users"), "not a group a site above can make again")):
    check(f"refused: remake {args[1]}'s {args[2]} from {args[0]} ({why})", why in refused(remake, db, None, *args))

print("--- list_site_roles (the Roles card, fabricctl federation roles; 2.1.9.22)")
db = domain()
grant_site_role(db, None, "lan", "house1", "network-operators")
listed = list_site_roles(db, None, "house1")
names = [s["site"] for s in listed["sites"]]
check("house1 lists itself and house1a, never house2 or lan", names == ["house1", "house1a"], names)
h1 = {r["role"]: r for r in listed["sites"][0]["roles"]}
check("its own site is marked; a granted console role shows its bundle and members",
      listed["sites"][0]["own"] and h1["network-operators"]["bundle"] == "fabric-network-operator"
      and h1["network-operators"]["members"] == ["house1-admins"] and not h1["network-operators"]["pending"], h1)
check("an AD role still held through the 0.8 default is pending; a console role not made yet says so",
      h1["ou-admins"]["pending"] and h1["helpdesk"]["exists"] is False, (h1["ou-admins"], h1["helpdesk"]))
top = [s["site"] for s in list_site_roles(db, None, "lan")["sites"]]
check("the top lists every site", top == ["lan", "house1", "house1a", "house2"], top)

print("--- an account holds a role only at its own level or below (2.1.9.24)")
add_member = importlib.import_module("add_group_member").add_group_member
move = importlib.import_module("move_person").move_person
protect = importlib.import_module("protect_privileged_people").protect_privileged_people
levels = importlib.import_module("levels")
db = domain()
PEOPLE = {s: f"OU=people,{dn}" for s, dn in (("lan", f"OU=lan,{SITES}"), ("house1", f"OU=house1,OU=lan,{SITES}"),
                                              ("house1a", f"OU=house1a,OU=house1,OU=lan,{SITES}"),
                                              ("house2", f"OU=house2,OU=lan,{SITES}"))}
for uid, where in (("kid", "house1a"), ("sib", "house2"), ("topper", "lan"), ("itguy", "house1")):
    db.add_entry(f"CN={uid},{PEOPLE[where]}", objectClass=["user"], objectCategory="person", sAMAccountName=uid)
for site in ("house1", "house1a", "house2"):
    for kind in ("agent", "keycloak"):
        db.add_entry(f"CN=fabric-{kind}-{site},OU=service-accounts,OU={site},{SITES}", objectClass=["user"],
                     sAMAccountName=f"fabric-{kind}-{site}")
check("site_of: where an account lives (its nearest site OU)",
      levels.site_of(db, f"CN=kid,{PEOPLE['house1a']}") == "house1a"
      and levels.site_of(db, f"CN=x,CN=Users,{BASE}") == "")
done = grant_site_role(db, None, "lan", "house1a", "machine-admins", "jdoe")
check("a role at house1a granted to jdoe, who lives above it (house1): allowed", done["changed"], done)
why = refused(grant_site_role, db, None, "lan", "house1", "machine-admins", "kid")
check("refused: a role at house1 granted to kid, who lives below it (house1a), naming where and how to move",
      "kid lives at house1a" in why and "house1, lan" in why and "fabricctl people move kid --site house1" in why, why)
db.add_remove_group_members("house1a-users", ["kid"])
why = refused(grant_site_role, db, None, "lan", "house1", "network-operators", "house1a-users")
check("refused: a role at house1 granted to a group with a member living below it (kid in house1a-users)",
      "kid lives at house1a" in why, why)
check("refused: a role at house2 granted to jdoe of house1 (a sibling's role)",
      "jdoe lives at house1" in refused(grant_site_role, db, None, "lan", "house2", "gpo-admins", "jdoe"))
why = refused(add_member, db, None, "house1", "house1-machine-admins", "kid")
check("refused: kid (house1a) put in house1-machine-admins, before anything changes",
      "kid lives at house1a" in why and "kid" not in members(db, "house1-machine-admins"), why)
db.add_entry(f"CN=house1-ops,OU=groups,OU=house1,OU=lan,{SITES}", objectClass=["group"], sAMAccountName="house1-ops")
db.add_remove_group_members("house1-ou-admins", ["house1-ops"])
check("refused: kid put in a plain group nested in a role group (house1-ops in house1-ou-admins)",
      "kid lives at house1a" in refused(add_member, db, None, "house1", "house1-ops", "kid"))
check("refused: itguy (house1) put in the organisation's admins (a role at the top, lan)",
      "itguy lives at house1" in refused(add_member, db, None, "lan", "admins", "itguy", ["admins"]))
check("jdoe (house1) put in house1a-ou-admins (below its level): allowed",
      add_member(db, None, "house1", "house1a-ou-admins", "jdoe") == {"added": True})
check("kid put in a group that gives no role (house1-users): allowed",
      add_member(db, None, "house1a", "house1-users", "kid") == {"added": True})

print("--- misplaced people, and move_person (fabricctl people move)")
db.add_remove_group_members("admins", ["itguy"])            # Central IT living at a branch: placed before the rule
lost = levels.misplaced(db, "house1", ["admins"])
check("misplaced: itguy at house1 holds a role at the top (lan); reported, nobody moved",
      [(m["uid"], m["lives"], sorted(m["holds"])) for m in lost] == [("itguy", "house1", ["lan"])]
      and f"CN=itguy,{PEOPLE['house1']}" in db.objects, lost)
listed = list_site_roles(db, None, "lan", ["admins"])
check("the roles listing shows it for house1 (the Roles card, fabricctl federation roles)",
      [m["uid"] for s in listed["sites"] if s["site"] == "house1" for m in s["misplaced"]] == ["itguy"], listed)
acl = protect(db, "house1", ["admins"])
check("house1's own agent and Keycloak accounts denied every write on itguy, not on jdoe (house1's own roles)",
      f"CN=itguy,{PEOPLE['house1']}: (D;;WPCRSDDTWDWO;;;SID-fabric-agent-house1)" in acl
      and f"CN=itguy,{PEOPLE['house1']}: (D;;WPCRSDDTWDWO;;;SID-fabric-keycloak-house1)" in acl
      and not any(a.startswith("CN=jdoe,") and "WPCRSDDTWDWO" in a for a in acl), [a for a in acl if "D;;WPCR" in a])
why = refused(move, db, None, "house1", "itguy", "lan", ["admins"])
check("refused: house1 moving itguy up to lan (a branch cannot move anyone above itself)",
      "only a site above both" in why and "house1 is not above lan" in why, why)
check("refused: house2 moving kid (house1a is not below house2)",
      "only a site above both" in refused(move, db, None, "house2", "kid", "house2"))
check("refused: moving itguy below a site where it holds a role (admins at lan; house1a)",
      "holds a role at lan" in refused(move, db, None, "lan", "itguy", "house1a", ["admins"]))
check("refused: an unknown person, or a service account",
      "no person" in refused(move, db, None, "lan", "nobody", "lan")
      and "no person" in refused(move, db, None, "lan", "fabric-agent-house1", "lan"))
done = move(db, None, "lan", "itguy", "lan", ["admins"])
check("the top moves itguy to lan: its account now lives there, in lan-users, no longer misplaced",
      done == {"uid": "itguy", "from": "house1", "to": "lan", "moved": True}
      and f"CN=itguy,{PEOPLE['lan']}" in db.objects and "itguy" in members(db, "lan-users")
      and levels.misplaced(db, "house1", ["admins"]) == [], done)
check("moving again changes nothing", not move(db, None, "lan", "itguy", "lan", ["admins"])["moved"])
check("house1 moves kid up from house1a to house1 (both at or below it)",
      move(db, None, "house1", "kid", "house1")["moved"] and f"CN=kid,{PEOPLE['house1']}" in db.objects)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
