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
check("a second run changes nothing", narrow_site_admins(db, "house1", False, "admins") == [])
root = narrow_site_admins(db, "lan", True, "admins")
check("at the root: lan-admins out, the organisation's admins in the root's four AD roles (Central IT everywhere)",
      all("admins" in members(db, f"lan-{r}") and "lan-admins" not in members(db, f"lan-{r}") for r in site_roles.ROLES)
      and "admins" not in members(db, "lan-fabric-admins") and any("Central IT" in c for c in root), root)
check("a site without its groups yet: nothing to do, no error", narrow_site_admins(db, "nowhere", False, "admins") == [])

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

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
