"""The `samba` suite, domain management (manual 1.6.12, step D4 of 1.6.12.15): fabric-agent's checks and the D4 routes
and `fabricctl domain` commands, against a real DC from fabric's image and fabric-agent's own route code. Proves:
the tiers (nothing below a tier touches it: a Directory Administrator refused on another, the Enterprise Admin's
account refused to everyone, root acting for the Enterprise Admin), the grants' people and machines rights (a helpdesk
person acting only where a grant with that right reaches, a new person or machine only in a grant's groups), a group's
two levels (scope and managers by the tier above; a manager adding a member within their controls and refused
anything else), every refusal of 1.6.12.13 (the permission's tier, fabric's objects, no grant, wrong input, a name AD
refuses, an OU not empty, a group in use, a taken name), the OUs, computers moved, typed and sited, the keytab
command, the Kerberos facts, service principals with a duplicate flagged and the ticket policy (rendered, the KDC
issuing tickets of that age, and its limits). Keycloak is not started here (a person's sessions are the keycloak
suite's): its calls are stubbed.
    sudo python3 tests/samba/domain.py          (FABRIC_TEST_KEEP=1 leaves the container for a look)
"""
import contextlib
import io
import os
import subprocess
import sys
import time
import types

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]

# what every module below finds when it imports them: this suite's vars, secrets and audit, no Keycloak, no lock file
HOLD = {"v": {}, "secrets": {}}
AUDIT = []
import fabriclib.common.load_vars as _lv  # noqa: E402
import fabriclib.common.save_vars as _sv  # noqa: E402
import fabriclib.common.vars_lock as _vl  # noqa: E402
import fabriclib.common.write_audit as _wa  # noqa: E402
import fabriclib.secrets.load_secrets as _ls  # noqa: E402
import fabriclib.keycloak.sign_out_person as _so  # noqa: E402
import fabriclib.keycloak.enable_person as _ep  # noqa: E402

_lv.load_vars = lambda path=None: HOLD["v"]


def _save(data, path=None):
    """The vars saved in place, so the suite's V (what the CLI's next command reads) sees them."""
    copy = dict(data)
    HOLD["v"].clear()
    HOLD["v"].update(copy)


_sv.save_vars = _save
_vl.vars_lock = lambda path=None: contextlib.nullcontext()
_wa.write_audit = lambda actor, action, detail, source="cli": AUDIT.append((actor, action, detail, source))
_ls.load_secrets = lambda *a, **k: HOLD["secrets"]
_so.sign_out_person = lambda *a, **k: 0
_ep.enable_person = lambda *a, **k: None

from start_dc import start_dc  # noqa: E402
import agent.get_route as m_get  # noqa: E402
import agent.post_domain as m_domain  # noqa: E402
import agent.post_groups as m_groups  # noqa: E402
import agent.post_host_access as m_hosts  # noqa: E402
import agent.post_ous as m_ous  # noqa: E402
import agent.post_people as m_people  # noqa: E402
import fabriclib.directory.run_op as m_runop  # noqa: E402
import fabriclib.grants.grant_request as m_greq  # noqa: E402
import fabriclib.samba.domain_dc_names as m_dcnames  # noqa: E402
import fabriclib.samba.domain_sites as m_dsites  # noqa: E402
from fabriclib.breakglass.ensure_enterprise_admin import ensure_enterprise_admin  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.deploy.check_samba_settings import check_samba_settings  # noqa: E402
from fabriclib.directory.add_machine import add_machine  # noqa: E402
from fabriclib.directory.create_person import create_person  # noqa: E402
from fabriclib.directory.ensure_admin import ensure_admin  # noqa: E402
from fabriclib.directory.set_person_group import set_person_group  # noqa: E402
from fabriclib.grants.add_grant import add_grant  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.samba.run_domain_command import run_domain_command  # noqa: E402
from fabriclib.samba.set_domain_password_policy import set_domain_password_policy  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-domain")
# a second run beside this one (another worktree) names its own: SAMBA_TEST_ID, SAMBA_TEST_NET (a /24's three octets)
NET = "domain_net" + os.environ.get("SAMBA_TEST_ID", "")
SUBNET = os.environ.get("SAMBA_TEST_NET", "10.254.41") + ".0/24"
IP = SUBNET.rsplit(".", 1)[0] + ".10"
DC = "dmdc" + os.environ.get("SAMBA_TEST_ID", "")
TARGET = {"name": DC}                 # where every `docker exec … samba` of the code under test goes
FAILED = 0
KERBEROS = {"ticket_hours": 3, "renew_days": 2, "skew_minutes": 7}


def redirect(module):
    """The module's `docker exec … samba …` goes to this suite's DC (or wherever TARGET says)."""
    real = subprocess.run

    def run(cmd, *a, **kw):
        return real([TARGET["name"] if c == "samba" else c for c in cmd], *a, **kw)
    module.subprocess = types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired)


for mod in (m_runop, m_greq, m_dcnames, m_dsites):
    redirect(mod)


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-900:]}"), flush=True)


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd[:6]}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def ldb(expr, *attrs):
    return sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", expr, *attrs],
              ok=False).stdout.replace("\n ", "")


def refused(fn, *a, **kw):
    """(refused?, why): the call raised ValidationError, and nothing was audited."""
    n = len(AUDIT)
    try:
        fn(*a, **kw)
        return False, "allowed"
    except ValidationError as e:
        return len(AUDIT) == n, str(e)


def cli(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = run_domain_command(V, list(args))
    return code, out.getvalue()


def cleanup():
    sh(["docker", "rm", "-f", DC], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


cleanup()
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP, extra_vars={"ad_kerberos_policy": KERBEROS})
V, SECRETS = dc["v"], dc["secrets"]
HOLD.update(v=V, secrets=SECRETS)
BASE = V["ad_base_dn"]
PW = "Correct-Horse-9-" + random_password(8)


def person(uid, *groups):
    create_person(V, "test", uid, uid.capitalize(), "Test", f"{uid}@lan.test", secrets=SECRETS, container=DC)
    sh(["docker", "exec", DC, "samba-tool", "user", "setpassword", uid, f"--newpassword={PW}", "-s",
        "/data/etc/smb.conf"])
    for g in groups:
        set_person_group(V, "test", g, uid, True, secrets=SECRETS, container=DC)


print("--- the people, the groups and the grants")
ea = ensure_enterprise_admin(V, container=DC)
ensure_admin(V, SECRETS, "alice", "alice@lan.test", lambda: PW, container=DC)          # a Directory Administrator
sh(["docker", "exec", DC, "samba-tool", "group", "add", "helpdesk-lan", "-s", "/data/etc/smb.conf",
    "--groupou=OU=groups"])
sh(["docker", "exec", DC, "samba-tool", "group", "add", "lab-people", "-s", "/data/etc/smb.conf",
    "--groupou=OU=groups"])
person("dee", "directory-admins")        # another Directory Administrator
person("hd", "helpdesk-lan")             # the help desk: delegated, no tier
person("bob")                            # site lan's person (create_person: site-lan)
person("carol", "lab-people")
sh(["docker", "exec", DC, "samba-tool", "group", "removemembers", "site-lan", "carol", "-s", "/data/etc/smb.conf"])
person("aud", "auditors")                # a fabric group's member (a role bundle)
person("sup")                            # a supervisor, to be a group's manager
add_grant(V, "test", "lan-helpdesk", {"who": ["helpdesk-lan"], "where": ["site-lan"],
                                      "people": ["edit", "reset", "unlock", "add"]}, container=DC)
add_machine(V, "test", "srv1", type="server", secrets=SECRETS, container=DC)
add_machine(V, "test", "dsk1", type="desktop", secrets=SECRETS, container=DC)
add_grant(V, "test", "lan-servers", {"who": ["helpdesk-lan"], "where": ["site-lan", "machines-servers"],
                                     "machines": ["move", "disable", "groups", "add"]}, container=DC)
set_person_group(V, "test", "site-lan", "aud", True, secrets=SECRETS, container=DC)
check("set up: fabric-admin, two Directory Administrators, a help desk with grants on site lan's people and servers",
      ea["created"] and "lan-helpdesk" in ldb("(cn=lan-helpdesk)", "cn"), ea)
m_get.load_vars = lambda: V

print("--- the routes' permissions (1.6.12.11)")
perms = {(m, tuple(r)): required_permission(m, r) for m, r in (
    ("POST", ["people", "x", "edit"]), ("POST", ["people", "x", "unlock"]), ("POST", ["groups"]),
    ("POST", ["groups", "g", "delete"]), ("POST", ["groups", "g", "managers"]), ("POST", ["groups", "g", "members"]),
    ("POST", ["ous"]), ("POST", ["ous", "rename"]), ("POST", ["ous", "delete"]), ("POST", ["machines", "m", "move"]),
    ("POST", ["machines", "m", "type"]), ("POST", ["machines", "m", "sites"]), ("POST", ["machines", "m", "keytab"]),
    ("POST", ["domain", "kerberos", "policy"]), ("POST", ["account", "password"]), ("GET", ["groups"]),
    ("GET", ["groups", "g"]), ("GET", ["ous"]), ("GET", ["domain", "kerberos"]),
    ("GET", ["domain", "kerberos", "spns"]), ("GET", ["account", "groups"]), ("GET", ["machines"]),
    ("GET", ["machines", "m"]), ("GET", ["sites"]))}
check("people:edit; unlock is people:reset (widened); groups:admin creates, deletes and sets managers; members and a "
      "person's own account any signed-in person (fabric-agent decides); ous:admin; machines:admin; domain:admin",
      [perms[k] for k in sorted(perms)] == [perms[k] for k in sorted(perms)] and perms[("POST", ("people", "x", "edit"))]
      == "people:edit" and perms[("POST", ("people", "x", "unlock"))] == "people:reset"
      and {perms[("POST", ("groups",))], perms[("POST", ("groups", "g", "delete"))],
           perms[("POST", ("groups", "g", "managers"))]} == {"groups:admin"}
      and perms[("POST", ("groups", "g", "members"))] == "session" and perms[("POST", ("account", "password"))]
      == "session" and perms[("GET", ("account", "groups"))] == "session"
      and {perms[("POST", ("ous",))], perms[("POST", ("ous", "rename"))], perms[("POST", ("ous", "delete"))]}
      == {"ous:admin"} and perms[("POST", ("domain", "kerberos", "policy"))] == "domain:admin"
      and {perms[("GET", r)] for r in (("groups",), ("groups", "g"), ("ous",), ("domain", "kerberos"), ("machines",),
                                       ("machines", "m"), ("sites",),
                                       ("domain", "kerberos", "spns"))} == {"domain:read"}, perms)

print("--- people: edit and unlock (1.6.12.4), through the grants and the tiers")
done = m_people.post_people(["people", "bob", "edit"], "hd", {"name": "Bob Builder", "email": "bob.b@lan.test"}, "hd")
mail = ldb("(sAMAccountName=bob)", "displayName", "mail")
# covers: agent:post.people.*.edit +
check("POST /v1/people/bob/edit by hd: a grant's people edit reaches bob (site lan): seen in AD, audited",
      done["changed"] == ["displayName", "mail"] and "displayName: Bob Builder" in mail and "mail: bob.b@lan.test" in mail
      and AUDIT[-1][1] == "PERSON_EDIT", (done, mail))
for who, target, body, words in (
        ("hd", "carol", {"name": "C"}, "no grant gives you people edit on carol"),
        ("hd", "aud", {"name": "A"}, "in a fabric group (auditors)"),
        ("hd", "alice", {"name": "A"}, "a Directory Administrator"),
        ("alice", "dee", {"name": "D"}, "only the Enterprise Admin"),
        ("alice", "fabric-admin", {"name": "F"}, "AD's top tier"),
        (None, "fabric-admin", {"name": "F"}, "AD's top tier"),
        ("sup", "bob", {"name": "B"}, "no grant gives you people edit on bob"),
        ("alice", "bob", {"email": "not-an-address"}, "e-mail address looks wrong"),
        ("alice", "bob", {"name": "x" * 80}, "display name"),
        ("alice", "bob", {}, "give at least one of a person's fields"),
        ("alice", "bob", {"frob": "x"}, "unknown field: frob"),
        ("alice", "bob", {"first": " "}, "first name may not be cleared"),
        ("alice", "bob", {"last": "B<b"}, "last name: letters and simple punctuation"),
        ("alice", "bob", {"phone": "call me"}, "phone: digits"),
        ("alice", "bob", {"mobile": "+"}, "mobile: digits"),
        ("alice", "bob", {"title": 'the "boss"'}, "without quotes"),
        ("alice", "bob", {"city": "x" * 65}, "city: up to 64 characters"),
        ("alice", "bob", {"country": "GBR"}, "a two-letter code"),
        ("alice", "bob", {"employee_id": "E" * 17}, "employee ID"),
        ("alice", "bob", {"manager": "bob"}, "not the person themselves"),
        ("alice", "bob", {"manager": "no.such"}, "no such entry"),
        ("alice", "bob", {"department": 7}, "department must be text"),
        ("hd", "carol", {"title": "T"}, "no grant gives you people edit on carol"),
        ("alice", "bob", {"email": "alice@lan.test"}, "already taken"),
        ("alice", "nobody", {"name": "N"}, "no person nobody")):
    gone, why = refused(m_people.post_people, ["people", target, "edit"], who or "root", body, who)
    # covers: agent:post.people.*.edit -
    check(f"edit {target} as {who or 'root'} refused ({words}), nothing changed", gone and words in why, why)
# AD's standard attributes (2.1.6.93): every field set at once, then two cleared
FULL = {"first": "Robert", "last": "Builder", "phone": "+44 20 7946 0000", "mobile": "07700 900000",
        "title": "Site engineer", "department": "Operations", "company": "Acme Ltd", "office": "Room 4",
        "city": "Leeds", "state": "West Yorkshire", "country": "gb", "manager": "carol", "employee_id": "E-1001"}
done = m_people.post_people(["people", "bob", "edit"], "alice", FULL, "alice")
seen = ldb("(sAMAccountName=bob)", "givenName", "sn", "telephoneNumber", "mobile", "title", "department", "company",
           "physicalDeliveryOfficeName", "l", "st", "c", "manager", "employeeID")
want = ("givenName: Robert", "sn: Builder", "telephoneNumber: +44 20 7946 0000", "mobile: 07700 900000",
        "title: Site engineer", "department: Operations", "company: Acme Ltd", "physicalDeliveryOfficeName: Room 4",
        "l: Leeds", "st: West Yorkshire", "c: GB", "manager: CN=carol", "employeeID: E-1001")
# covers: agent:post.people.*.edit +
check("POST /v1/people/bob/edit by alice: first, last, phone, mobile, title, department, company, office, city, state, "
      "country (upper-cased), manager (a person, stored as their DN) and employee ID, all in AD, audited",
      all(w in seen for w in want) and done["person"]["manager"] == "carol" and done["person"]["country"] == "GB"
      and len(done["changed"]) == 13 and AUDIT[-1][1] == "PERSON_EDIT", (done, seen))
done = m_people.post_people(["people", "bob", "edit"], "alice", {"phone": "", "manager": " "}, "alice")
seen = ldb("(sAMAccountName=bob)", "telephoneNumber", "manager", "mobile")
check("...an empty value clears a field (phone, manager), the others kept",
      done["changed"] == ["telephoneNumber", "manager"] and "telephoneNumber:" not in seen and "manager:" not in seen
      and "mobile: 07700 900000" in seen and done["person"]["phone"] == "", (done, seen))
done = m_people.post_people(["people", "bob", "edit"], "alice", {"title": "Site engineer"}, "alice")
check("...a value it already has changes nothing, and nothing is audited", done["changed"] == [], done)
lock = int((time.time() + 11644473600) * 10_000_000)
dn_bob = f"CN=Bob Test,OU=people,{BASE}" if "CN=Bob Test" in ldb("(sAMAccountName=bob)", "dn") else \
    ldb("(sAMAccountName=bob)", "dn").split("dn: ", 1)[1].split("\n", 1)[0]
sh(["docker", "exec", "-i", DC, "ldbmodify", "-H", "/data/private/sam.ldb"],
   input=f"dn: {dn_bob}\nchangetype: modify\nreplace: lockoutTime\nlockoutTime: {lock}\n")
page = m_get.get_route(["people", "bob"], "alice")
# covers: agent:get.people.* +
check("GET /v1/people/bob (a person's page, 1.6.12.4): locked out, his details (the 15 fields), groups, sites, last "
      "sign-in (\"\" or a time), certificates and devices", page["state"] == "locked" and page["uid"] == "bob"
      and page["person"]["title"] == "Site engineer" and "site-lan" in page["groups"] and page["sites"] == ["lan"]
      and isinstance(page["certs"], list) and isinstance(page["devices"], list)
      and (page["last_logon"] == "" or page["last_logon"][:2] == "20"), page)
row = next(u for u in m_get.get_route(["people"], "alice")["users"] if u["uid"] == "bob")
check("...and the People list says so too (state, last sign-in)", row["state"] == "locked" and row["locked"]
      and "last_logon" in row, row)
done = m_people.post_people(["people", "bob", "unlock"], "hd", {}, "hd")
# covers: agent:post.people.*.unlock +
check("POST /v1/people/bob/unlock by hd (a grant's unlock): bob's lockoutTime is 0 again, audited",
      done["changed"] and "lockoutTime: 0" in ldb("(sAMAccountName=bob)", "lockoutTime")
      and AUDIT[-1][1] == "PERSON_UNLOCK", done)
check("...unlocked: active on his page", m_get.get_route(["people", "bob"], "alice")["state"] == "active")
again = m_people.post_people(["people", "bob", "unlock"], "hd", {}, "hd")
check("...again: not locked out, nothing changed or audited", again["changed"] is False and AUDIT[-1][1] == "PERSON_UNLOCK",
      again)
for who, target, words in (("hd", "carol", "no grant gives you people unlock on carol"),
                           ("hd", "dee", "a Directory Administrator"), ("alice", "fabric-admin", "AD's top tier")):
    gone, why = refused(m_people.post_people, ["people", target, "unlock"], who, {}, who)
    # covers: agent:post.people.*.unlock -
    check(f"unlock {target} as {who} refused ({words})", gone and words in why, why)

print("--- the existing people routes now checked the same way (2.1.6.66)")
pw = m_people.post_people(["people", "bob", "reset"], "hd", {}, "hd")["password"]
check("reset bob by hd: the grant's reset reaches him", len(pw) >= 20 and AUDIT[-1][1] == "PERSON_RESET")
gone, why = refused(m_people.post_people, ["people", "carol", "reset"], "hd", {}, "hd")
check("reset carol by hd refused: no grant reaches her", gone and "no grant gives you people reset on carol" in why, why)
gone, why = refused(m_people.post_people, ["people", "bob", "disable"], "hd", {}, "hd")
check("disable bob by hd refused: the grant gives no disable", gone and "people disable on bob" in why, why)
gone, why = refused(m_people.post_people, ["people", "dee", "reset"], "alice", {}, "alice")
check("a Directory Administrator resetting another refused: only the Enterprise Admin (2.1.6.68)",
      gone and "only the Enterprise Admin" in why, why)
done = m_people.post_people(["people", "dee", "disable"], "root", {}, None)
check("a disabled person's state is disabled (not locked) on their page",
      m_get.get_route(["people", "dee"], "alice")["state"] == "disabled")
m_people.post_people(["people", "dee", "enable"], "root", {}, None)
check("root (acting for the Enterprise Admin) disables and enables a Directory Administrator",
      done["changed"] and AUDIT[-1][1] == "PERSON_ENABLE", done)
gone, why = refused(m_people.post_people, ["people", "fabric-admin", "reset"], "root", {}, None)
check("fabric-admin's own account is nobody's through fabric-agent, root's neither (reset-break-glass)",
      gone and "AD's top tier" in why, why)
pw = m_people.post_people(["people"], "hd", {"uid": "newbie", "first": "New", "last": "Bie",
                                              "email": "newbie@lan.test"}, "hd")["password"]
check("hd adds a person: the grant's people add, its where (site-lan) the new person's group", len(pw) >= 20
      and "CN=site-lan," in ldb("(sAMAccountName=newbie)", "memberOf"), ldb("(sAMAccountName=newbie)", "memberOf"))
gone, why = refused(m_people.post_people, ["people"], "sup", {"uid": "newbie2", "first": "N", "last": "B",
                                                             "email": "newbie2@lan.test"}, "sup")
check("sup adds a person refused: no grant gives them people add there", gone and "no grant gives you people add" in why,
      why)

print("--- groups: create, managers, members, delete (1.6.12.5; 2.1.6.67)")
done = m_groups.post_groups(["groups"], "alice", {"name": "ops-team", "description": "the ops team"}, "alice")
# covers: agent:post.groups +
check("POST /v1/groups by a Directory Administrator: ops-team in OU=groups with a gid, audited",
      f"CN=ops-team,OU=groups,{BASE}" in ldb("(sAMAccountName=ops-team)", "dn") and done["gid"] > 0
      and AUDIT[-1][1] == "GROUP_CREATE", done)
for who, body, words in (("hd", {"name": "hd-team"}, "only a Directory Administrator"),
                         ("alice", {"name": "site-x"}, "one of fabric's names"),
                         ("alice", {"name": "grant-x"}, "one of fabric's names"),
                         ("alice", {"name": "Bad Name"}, "a group's name"),
                         ("alice", {"name": "domain users"}, "a group's name"),
                         ("alice", {"name": "bob"}, "already taken"),
                         ("alice", {"name": "ops-team"}, "already taken"),
                         ("alice", {"name": "fine", "description": "x" * 300}, "description")):
    gone, why = refused(m_groups.post_groups, ["groups"], who, body, who)
    # covers: agent:post.groups -
    check(f"create {body['name'][:20]} as {who} refused ({words})", gone and words in why, why)
done = m_groups.post_groups(["groups", "ops-team", "managers"], "alice",
                            {"managers": ["sup"], "add": True, "remove": False, "only_from": "site-lan"}, "alice")
managed = ldb("(sAMAccountName=ops-team)", "managedBy")
# covers: agent:post.groups.*.managers +
check("POST /v1/groups/ops-team/managers: sup may add (only people in site-lan), not remove; managedBy names sup",
      done["changed"] and done["managers"] == ["sup"] and "managedBy: CN=sup,OU=people" in managed
      and AUDIT[-1][1] == "GROUP_MANAGERS", (done, managed))
for who, name, body, words in (
        ("hd", "ops-team", {"managers": ["hd"]}, "only by a Directory Administrator"),
        ("alice", "directory-admins", {"managers": ["sup"], "add": True}, "only by the Enterprise Admin"),
        ("alice", "machines-servers", {"managers": ["sup"]}, "takes no managers"),
        ("alice", "Domain Users", {"managers": ["sup"]}, "takes no managers"),
        ("alice", "ops-team", {"managers": ["fabric-admin"]}, "AD's top tier"),
        ("alice", "ops-team", {"managers": ["nobody"]}, "no person or group nobody"),
        ("alice", "ops-team", {"managers": ["sup"], "only_from": "nogroup"}, "no group nogroup"),
        ("alice", "ops-team", {"managers": ["sup", "sup"]}, "a name given twice"),
        ("alice", "ops-team", {"managers": "sup"}, "must be a list"),
        ("alice", "ops-team", {"managers": ["sup"], "add": "yes"}, "true or false"),
        ("alice", "nogroup", {"managers": ["sup"]}, "no group nogroup")):
    gone, why = refused(m_groups.post_groups, ["groups", name, "managers"], who, body, who)
    # covers: agent:post.groups.*.managers -
    check(f"managers of {name} as {who} refused ({words})", gone and words in why, why)
done = m_groups.post_groups(["groups", "ops-team", "members"], "sup", {"action": "add", "member": "bob"}, "sup")
# covers: agent:post.groups.*.members +
check("POST /v1/groups/ops-team/members by sup, its manager: bob (in site-lan) added, seen in AD, audited by manager",
      done["changed"] and "CN=ops-team," in ldb("(sAMAccountName=bob)", "memberOf")
      and any(a[1] == "PERSON_GROUP_ADD" and "by=manager" in a[2] for a in AUDIT[-2:]), done)
for who, name, body, words in (
        ("sup", "ops-team", {"action": "remove", "member": "bob"}, "may not remove members"),
        ("sup", "ops-team", {"action": "add", "member": "carol"}, "may add only people already in site-lan"),
        ("sup", "ops-team", {"action": "add", "member": "alice"}, "a Directory Administrator"),
        ("sup", "lab-people", {"action": "add", "member": "bob"}, "not a manager of lab-people"),
        ("hd", "ops-team", {"action": "add", "member": "bob"}, "not a manager of ops-team"),
        ("alice", "directory-admins", {"action": "add", "member": "bob"}, "the Enterprise Admin"),
        ("alice", "grant-lan-helpdesk-who", {"action": "add", "member": "bob"}, "computed for the grants"),
        ("alice", "machines-servers", {"action": "add", "member": "bob"}, "filled by fabric"),
        ("alice", "Domain Admins", {"action": "add", "member": "bob"}, "AD's own groups"),
        ("alice", "ops-team", {"action": "add", "member": "fabric-admin"}, "AD's top tier"),
        ("alice", "ops-team", {"action": "add", "member": "directory-admins"}, "the tiers"),
        ("alice", "ops-team", {"action": "add", "member": "nobody"}, "no person or group nobody"),
        ("alice", "ops-team", {"action": "frob", "member": "bob"}, "add or remove")):
    gone, why = refused(m_groups.post_groups, ["groups", name, "members"], who, body, who)
    # covers: agent:post.groups.*.members -
    check(f"members of {name} as {who} refused ({words})", gone and words in why, why)
gone, why = refused(m_people.post_people, ["people", "bob", "reset"], "sup", {}, "sup")
check("the manager gets nothing else (2.1.6.67): sup resetting bob, whom he added, refused",
      gone and "no grant gives you people reset on bob" in why, why)
gone, why = refused(m_groups.post_groups, ["groups", "ops-team", "managers"], "sup", {"managers": ["sup"],
                                                                                       "remove": True}, "sup")
check("...nor widening his own controls: refused", gone and "only by a Directory Administrator" in why, why)
done = m_groups.post_groups(["groups", "ops-team", "members"], "alice", {"action": "add", "member": "lab-people"},
                            "alice")
check("a Directory Administrator nests a group (lab-people in ops-team)", done["changed"]
      and "CN=lab-people," in ldb("(sAMAccountName=ops-team)", "member"), done)
done = m_groups.post_groups(["groups", "directory-admins", "members"], "root", {"action": "add", "member": "sup"},
                            None)
m_groups.post_groups(["groups", "directory-admins", "members"], "root", {"action": "remove", "member": "sup"}, None)
check("root (the Enterprise Admin's tier) changes the Directory Administrators' members", done["changed"]
      and "CN=directory-admins," not in ldb("(sAMAccountName=sup)", "memberOf"), done)
got = m_get.get_route(["groups"])
# covers: agent:get.groups +
check("GET /v1/groups: kinds (fabric's, a bundle's, the computed ones, an admin's own)",
      {("ops-team", "own"), ("auditors", "bundle"), ("site-lan", "fabric"), ("directory-admins", "tier"),
       ("machines-servers", "filled"), ("grant-lan-helpdesk-who", "computed")}
      <= {(g["name"], g["kind"]) for g in got["groups"]}, got)
got = m_get.get_route(["groups", "ops-team"])
# covers: agent:get.groups.* +
check("GET /v1/groups/ops-team: both levels: its managers and controls, its members (bob, lab-people)",
      got["managers"] == {"managers": ["sup"], "add": True, "remove": False, "only_from": "site-lan"}
      and got["members"]["people"] == ["bob"] and got["members"]["groups"] == ["lab-people"], got)
got = m_get.get_route(["groups", "helpdesk-lan"])
check("...a group a grant names shows it in its scope", {"name": "lan-helpdesk", "as": "who"} in got["scope"]["grants"],
      got)
got = m_get.get_route(["account", "groups"], "sup")
# covers: agent:get.account.groups +
check("GET /v1/account/groups as sup: Groups I manage, ops-team with its members and controls",
      [g["name"] for g in got["groups"]] == ["ops-team"] and got["groups"][0]["add"] and "bob" in got["groups"][0]["members"],
      got)
for route, user, words in ((["account", "groups"], None, "sign in as them"),
                           (["account", "groups"], "nobody", "not a person of the domain")):
    gone, why = refused(m_get.get_route, route, user)
    # covers: agent:get.account.groups -
    check(f"GET /v1/account/groups as {user} refused ({words})", gone and words in why, why)
gone, why = refused(m_get.get_route, ["groups", "nogroup"])
# covers: agent:get.groups.* -
check("GET /v1/groups/nogroup refused: no such group", gone and "no group nogroup" in why, why)
for who, name, words in (("alice", "helpdesk-lan", "in use: grant lan-helpdesk"),
                         ("alice", "site-lan", "one of fabric's own groups"),
                         ("alice", "auditors", "one of fabric's own groups"),
                         ("alice", "users", "one of fabric's own groups"),
                         ("alice", "Domain Admins", "AD's own"),
                         ("alice", "grant-lan-helpdesk-who", "computed"),
                         ("alice", "site-lan", "fabric"),
                         ("alice", "directory-admins", "only by the Enterprise Admin"),
                         ("hd", "ops-team", "only by a Directory Administrator"),
                         ("alice", "nogroup", "no group nogroup")):
    gone, why = refused(m_groups.post_groups, ["groups", name, "delete"], who, {}, who)
    # covers: agent:post.groups.*.delete -
    check(f"delete {name} as {who} refused ({words})", gone and words in why, why)
m_groups.post_groups(["groups"], "alice", {"name": "only-from-me"}, "alice")
m_groups.post_groups(["groups", "ops-team", "managers"], "alice", {"managers": ["sup"], "add": True,
                                                                   "only_from": "only-from-me"}, "alice")
gone, why = refused(m_groups.post_groups, ["groups", "only-from-me", "delete"], "alice", {}, "alice")
check("delete refused while another group's managers name it (its only-from)", gone and "the managers of" in why, why)
m_groups.post_groups(["groups", "ops-team", "managers"], "alice", {"managers": ["sup"], "add": True,
                                                                   "only_from": "site-lan"}, "alice")
done = m_groups.post_groups(["groups", "only-from-me", "delete"], "alice", {}, "alice")
# covers: agent:post.groups.*.delete +
check("POST /v1/groups/only-from-me/delete once unused: gone from AD, audited",
      done["name"] == "only-from-me" and not ldb("(sAMAccountName=only-from-me)", "dn").count("dn: ")
      and AUDIT[-1][1] == "GROUP_REMOVE", done)

print("--- the CLI: fabricctl domain person and group (as root)")
code, out = cli("person", "edit", "carol", "--name", "Carol Lab")
# covers: cli:domain.person +
check("domain person edit (root)", code == 0 and "displayName changed" in out, out)
code, out = cli("person", "edit", "carol", "--title", "Lab lead", "--country", "us", "--employee-id", "C-7")
check("domain person edit --title --country --employee-id (2.1.6.93)",
      code == 0 and "title, c, employeeID changed" in out and "c: US" in ldb("(sAMAccountName=carol)", "c"), out)
code, out = cli("person", "unlock", "carol")
check("domain person unlock: not locked out", code == 0 and "not locked out" in out, out)
code, out = cli("person", "disable", "carol")
code2, out2 = cli("person", "enable", "carol")
check("domain person disable, enable", code == code2 == 0 and "disabled" in out and "enabled" in out2, out + out2)
for args, words, want in ((("person", "edit", "fabric-admin", "--name", "X"), "AD's top tier", 1),
                          (("person", "frob", "carol"), "usage", 2), (("person", "edit"), "usage", 2),
                          (("person", "edit", "carol", "--bad", "x"), "unknown option", 1),
                          (("person", "edit", "carol", "--country", "USA"), "a two-letter code", 1),
                          (("person", "edit", "carol"), "give at least one of a person's fields", 1),
                          (("person", "unlock", "carol", "extra"), "usage", 2)):
    code, out = cli(*args)
    # covers: cli:domain.person -
    check(f"domain {' '.join(args)} refused ({words})", code == want and words in out, out)
code, out = cli("group", "create", "cli-team", "--description", "made on the host")
code2, out2 = cli("group", "managers", "cli-team", "--set", "sup", "--add", "on", "--remove", "on")
code3, out3 = cli("group", "members", "cli-team", "add", "carol")
code4, out4 = cli("group", "scope", "cli-team")
code5, out5 = cli("group", "list")
code6, out6 = cli("group", "members", "cli-team", "remove", "carol")
code7, out7 = cli("group", "delete", "cli-team")
# covers: cli:domain.group +
check("domain group create, managers, members, scope, list, delete (root)",
      [code, code2, code3, code4, code5, code6, code7] == [0] * 7 and "managers: sup" in out4
      and "people: carol" in out4 and "cli-team" in out5 and "deleted" in out7,
      (out, out2, out3, out4, out6, out7))
for args, words, want in ((("group", "create", "site-y"), "fabric's names", 1),
                          (("group", "delete", "site-lan"), "fabric's own", 1),
                          (("group", "managers", "ops-team", "--add", "maybe"), "on or off", 1),
                          (("group", "members", "ops-team", "join", "bob"), "usage", 2),
                          (("group", "scope"), "usage", 2)):
    code, out = cli(*args)
    # covers: cli:domain.group -
    check(f"domain {' '.join(args)} refused ({words})", code == want and words in out, out)

print("--- OUs (1.6.12.7)")
done = m_ous.post_ous(["ous"], "alice", {"parent": "people", "name": "staff"})
done2 = m_ous.post_ous(["ous"], "alice", {"parent": "machines/servers", "name": "web"})
# covers: agent:post.ous +
check("POST /v1/ous: people/staff and machines/servers/web, audited",
      done["path"] == "people/staff" and done2["dn"] == f"OU=web,OU=servers,OU=machines,{BASE}"
      and AUDIT[-1][1] == "OU_CREATE", (done, done2))
for body, words in (({"parent": "groups/fabric", "name": "x"}, "takes no admin's folders"),
                    ({"parent": "machines", "name": "x"}, "takes no admin's folders"),
                    ({"parent": "devices", "name": "x"}, "takes no admin's folders"),
                    ({"parent": "people", "name": "people"}, "one of fabric's folders' names"),
                    ({"parent": "people", "name": "a,b"}, "an OU's name"),
                    ({"parent": "people", "name": "staff"}, "already taken"),
                    ({"parent": "people/nowhere", "name": "x"}, "no OU people/nowhere"),
                    ({"parent": "service-accounts", "name": "apps"}, "not permitted for fabric's agent")):
    gone, why = refused(m_ous.post_ous, ["ous"], "alice", body)
    # covers: agent:post.ous -
    check(f"create {body['parent']}/{body['name']} refused ({words})", gone and words in why, why)
got = m_get.get_route(["ous"])
rows = {o["path"]: o for o in got["ous"]}
# covers: agent:get.ous +
check("GET /v1/ous: the tree, fabric's marked (people, machines/servers), the admin's own (people/staff) changeable",
      rows["people"]["fabric"] and not rows["people"]["own"] and rows["people/staff"]["own"]
      and rows["machines/servers"]["fabric"] and rows["people"]["holds"]["people"] >= 5, rows.get("people"))
done = m_ous.post_ous(["ous", "rename"], "alice", {"ou": "people/staff", "name": "office"})
# covers: agent:post.ous.rename +
check("POST /v1/ous/rename: people/staff is people/office", done["path"] == "people/office"
      and "OU=office,OU=people" in ldb("(ou=office)", "dn"), done)
for body, words in (({"ou": "people", "name": "folk"}, "one of fabric's folders"),
                    ({"ou": "machines/servers", "name": "srv"}, "one of fabric's folders"),
                    ({"ou": "people/nowhere", "name": "x"}, "no OU people/nowhere"),
                    ({"ou": "people/office", "name": "groups"}, "one of fabric's folders' names")):
    gone, why = refused(m_ous.post_ous, ["ous", "rename"], "alice", body)
    # covers: agent:post.ous.rename -
    check(f"rename {body['ou']} refused ({words})", gone and words in why, why)

print("--- computers: move, type, sites, keytab (1.6.12.6, 1.6.12.9)")
done = m_domain.post_domain(["machines", "srv1", "move"], "hd", {"path": "machines/servers/web"}, "hd",
                            {"machines:admin", "ous:admin"})
# covers: agent:post.machines.*.move +
check("POST /v1/machines/srv1/move by hd (a grant's machines move on lan's servers): in machines/servers/web, its "
      "groups unchanged (nobody's access changes)", done["changed"]
      and f"CN=SRV1,OU=web,OU=servers,OU=machines,{BASE}" in ldb("(sAMAccountName=SRV1$)", "dn")
      and "CN=machines-servers," in ldb("(sAMAccountName=SRV1$)", "memberOf")
      and AUDIT[-1][1] == "MACHINE_MOVE", done)
for who, name, body, perms_, words in (
        ("hd", "dsk1", {"path": "machines"}, {"machines:admin", "ous:admin"}, "no grant gives you machines move on dsk1"),
        ("hd", "srv1", {"path": "machines"}, {"machines:admin"}, "needs ous:admin too"),
        ("alice", "srv1", {"path": "people/office"}, None, "only to a folder under OU=machines"),
        ("alice", "srv1", {"path": "machines/nowhere"}, None, "no OU machines/nowhere"),
        ("alice", "nomachine", {"path": "machines"}, None, "no machine nomachine")):
    gone, why = refused(m_domain.post_domain, ["machines", name, "move"], who, body, who, perms_)
    # covers: agent:post.machines.*.move -
    check(f"move {name} as {who} refused ({words})", gone and words in why, why)
gone, why = refused(m_ous.post_ous, ["ous", "delete"], "alice", {"ou": "machines/servers/web"})
# covers: agent:post.ous.delete -
check("delete machines/servers/web refused while it holds srv1, naming it", gone and "not empty" in why
      and "CN=SRV1" in why, why)
for body, words in (({"ou": "people"}, "one of fabric's folders"), ({"ou": "people/nowhere"}, "no OU")):
    gone, why = refused(m_ous.post_ous, ["ous", "delete"], "alice", body)
    # covers: agent:post.ous.delete -
    check(f"delete {body['ou']} refused ({words})", gone and words in why, why)
done = m_ous.post_ous(["ous", "delete"], "alice", {"ou": "people/office"})
# covers: agent:post.ous.delete +
check("POST /v1/ous/delete: the empty people/office gone", done["path"] == "people/office"
      and "OU=office" not in ldb("(ou=office)", "dn"), done)
done = m_domain.post_domain(["machines", "dsk1", "type"], "alice", {"type": "server", "move": True}, "alice",
                            {"machines:admin"})
groups = ldb("(sAMAccountName=DSK1$)", "memberOf")
# covers: agent:post.machines.*.type +
check("POST /v1/machines/dsk1/type server, moved: in machines-servers (out of machines-desktops) and OU=servers, "
      "compiled at once", "CN=machines-servers," in groups and "CN=machines-desktops," not in groups
      and f"CN=DSK1,OU=servers,OU=machines,{BASE}" in ldb("(sAMAccountName=DSK1$)", "dn")
      and AUDIT[-1][1] in ("MACHINE_TYPE", "GRANT_COMPILE"), (done, groups))
done = m_domain.post_domain(["machines", "srv1", "type"], "alice", {"type": "server", "move": True}, "alice",
                            {"machines:admin"})
check("...srv1 a server already, in an admin's folder: nothing changed, its folder kept",
      done["changed"] == [] and done["kept_folder"].startswith("ou=web"), done)
for who, name, body, words in (("alice", "dsk1", {"type": "laptop"}, "type: one of"),
                               ("sup", "dsk1", {"type": "desktop"}, "no grant gives you machines groups"),
                               ("alice", "nomachine", {"type": "server"}, "no machine nomachine")):
    gone, why = refused(m_domain.post_domain, ["machines", name, "type"], who, body, who, {"machines:admin"})
    # covers: agent:post.machines.*.type -
    check(f"type {name} as {who} refused ({words})", gone and words in why, why)
done = m_domain.post_domain(["machines", "srv1", "sites"], "hd", {"action": "remove", "site": "lan"}, "hd",
                            {"machines:admin"})
check("hd takes srv1 out of site lan (a grant's machines groups)", done["changed"]
      and "CN=site-lan," not in ldb("(sAMAccountName=SRV1$)", "memberOf"), done)
gone, why = refused(m_domain.post_domain, ["machines", "srv1", "sites"], "hd", {"action": "add", "site": "lan"}, "hd",
                    {"machines:admin"})
check("...and is then refused putting it back: no grant reaches it outside site lan (where: site-lan and servers)",
      gone and "no grant gives you machines groups on srv1" in why, why)
done = m_domain.post_domain(["machines", "srv1", "sites"], "alice", {"action": "add", "site": "lan"}, "alice",
                            {"machines:admin"})
# covers: agent:post.machines.*.sites +
check("POST /v1/machines/srv1/sites add lan by a Directory Administrator", done["changed"]
      and "CN=site-lan," in ldb("(sAMAccountName=SRV1$)", "memberOf") and AUDIT[-1][1] in ("MACHINE_SITE_ADD",
                                                                                           "GRANT_COMPILE"), done)
for body, words in (({"action": "add", "site": "nowhere"}, "no site nowhere"), ({"action": "frob", "site": "lan"},
                                                                                 "add or remove"),
                    ({"action": "add", "site": ""}, "must be text")):
    gone, why = refused(m_domain.post_domain, ["machines", "srv1", "sites"], "alice", body, "alice", {"machines:admin"})
    # covers: agent:post.machines.*.sites -
    check(f"sites {body} refused ({words})", gone and words in why, why)
done = m_domain.post_domain(["machines", "srv1", "disable"], "hd", {}, "hd", {"machines:admin"})
check("hd disables srv1 (a grant's machines disable): the existing route checked too", done["changed"])
m_domain.post_domain(["machines", "srv1", "enable"], "hd", {}, "hd", {"machines:admin"})
gone, why = refused(m_domain.post_domain, ["machines", "srv1", "delete"], "hd", {}, "hd", {"machines:admin"})
check("hd removing srv1 refused: the grant gives no remove", gone and "machines remove on srv1" in why, why)
gone, why = refused(m_domain.post_domain, ["machines"], "hd", {"name": "dsk9", "type": "desktop"}, "hd",
                    {"machines:admin"})
check("hd pre-creating a desktop refused: the grant's add reaches only lan's servers", gone
      and "no grant gives you machines add" in why, why)
done = m_domain.post_domain(["machines"], "hd", {"name": "srv9", "type": "server"}, "hd", {"machines:admin"})
check("...a server of site lan allowed: the new machine's groups hold the grant's where", len(done["password"]) >= 20)
gone, why = refused(m_hosts.post_host_access, ["host-groups", "web", "members"], "sup",
                    {"action": "add", "machine": "srv1"}, "sup")
check("a machine group's machines checked too: sup refused (no grant's machines groups)", gone
      and "machines groups on srv1" in why, why)
done = m_domain.post_domain(["machines", "srv1", "keytab"], "alice", {"service": "HTTP", "user": "www-data"}, "alice",
                            {"machines:admin"})
# covers: agent:post.machines.*.keytab +
check("POST /v1/machines/srv1/keytab: one command for its administrator, nothing secret in it, nothing changed",
      done["command"] == "sudo fabric-keytab --machine srv1 --service HTTP --user www-data"
      and done["spns"][1] == "HTTP/SRV1", done)
for body, words in (({"service": "host", "user": "www-data"}, "the machine's own"),
                    ({"service": "HTTP", "user": "Bad User"}, "user:"),
                    ({"service": "HTTP", "user": "www-data", "path": "/etc/krb5.keytab"}, "path:"),
                    ({"service": "HTTP", "user": "www-data", "path": "relative"}, "path:")):
    gone, why = refused(m_domain.post_domain, ["machines", "srv1", "keytab"], "alice", body, "alice", None)
    # covers: agent:post.machines.*.keytab -
    check(f"keytab {body} refused ({words})", gone and words in why, why)
gone, why = refused(m_domain.post_domain, ["machines", "nomachine", "keytab"], "alice",
                    {"service": "HTTP", "user": "www-data"}, "alice", None)
# covers: agent:post.machines.*.keytab -
check("keytab for a machine the domain does not know refused", gone and "no machine nomachine" in why, why)
print("--- Computers (1.6.12.6): the list and a computer's page")
listed = m_get.get_route(["machines"], "alice")
row = next((m for m in listed if m["name"] == "srv1"), {})
# covers: agent:get.machines +
check("GET /v1/machines: each computer with its type, sites, machine groups and folder (srv1: a server of lan, "
      "still in machines/servers/web: a type change to its own type moves nothing)", row.get("type") == "server"
      and "lan" in row.get("sites", []) and row.get("folder") == "machines/servers/web"
      and isinstance(row.get("groups"), list)
      and {"enabled", "last_logon", "os", "dns"} <= set(row), row)
page = m_get.get_route(["machines", "SRV1"], "alice")
reaching = {g["name"]: g for g in page["grants"]}
# covers: agent:get.machines.* +
check("GET /v1/machines/SRV1 (any case): its row; the grants that reach it, each with what it gives there (lan-servers: "
      "the help desk's machines rights; server-administrators: sign-in, sudo, local administrator); the choices of "
      "its actions (sites, folders under machines)", page["machine"]["name"] == "srv1"
      and reaching.get("lan-servers", {}).get("rights", {}).get("machines") == ["move", "disable", "groups", "add"]
      and reaching["lan-servers"]["who"] == ["helpdesk-lan"]
      and reaching.get("server-administrators", {}).get("rights", {}).get("local_admin") is True
      and reaching.get("lan-helpdesk", {}).get("rights", {}).get("machines") == []
      and "lan" in page["choices"]["sites"]
      and {"machines", "machines/servers", "machines/servers/web"} <= set(page["choices"]["folders"])
      and "people" not in page["choices"]["folders"] and page["devices"] == [], page)
for name in ("nomachine", "dmdc" + os.environ.get("SAMBA_TEST_ID", "")):
    gone, why = refused(m_get.get_route, ["machines", name], "alice")
    # covers: agent:get.machines.* -
    check(f"refused: GET /v1/machines/{name} (not a computer of the domain's folders: no machine)",
          gone and "no machine" in why, why)
code, out = cli("machine", "move", "dsk1", "machines")
code2, out2 = cli("machine", "type", "dsk1", "desktop", "--move")
code3, out3 = cli("machine", "sites", "dsk1", "add", "lan")
code4, out4 = cli("machine", "keytab", "dsk1", "--service", "postgres", "--user", "postgres")
# covers: cli:domain.machine +
check("domain machine move, type, sites, keytab (root)", [code, code2, code3, code4] == [0] * 4
      and "moved to machines" in out and "moved to OU=desktops" in out2 and "(already)" in out3
      and "sudo fabric-keytab --machine dsk1 --service postgres --user postgres" in out4, (out, out2, out3, out4))
for args, words, want in ((("machine", "move", "dsk1", "people"), "only to a folder under OU=machines", 1),
                          (("machine", "type", "dsk1", "toaster"), "type: one of", 1),
                          (("machine", "keytab", "dsk1", "--service", "cifs", "--user", "x"), "the machine's own", 1),
                          (("machine", "frob", "dsk1"), "usage", 2)):
    code, out = cli(*args)
    # covers: cli:domain.machine -
    check(f"domain {' '.join(args)} refused ({words})", code == want and words in out, out)
sites = m_get.get_route(["sites"], "alice")
lan = next((s for s in sites["sites"] if s["name"] == "lan"), {})
# covers: agent:get.sites +
check("GET /v1/sites (1.6.12.8): site lan with its people and machines, its DC, the grants whose where names site-lan, "
      "its AD site (this DC, the DC's subnet), the DC count; nothing failed", sites["error"] == ""
      and "bob" in lan.get("people", []) and "srv1" in lan.get("machines", []) and "lan-helpdesk" in lan.get("grants", [])
      and "carol" not in lan.get("people", []) and lan.get("dcs") and (lan.get("ad") or {}).get("dcs")
      and "1 DC used" in sites["dc_text"], sites)
page = m_get.get_route(["machines", "dsk1"], "alice")
check("GET /v1/machines/dsk1, a desktop again: the servers' grants no longer reach it",
      page["machine"]["type"] == "desktop" and "lan-servers" not in {g["name"] for g in page["grants"]}
      and "server-administrators" not in {g["name"] for g in page["grants"]}, page["grants"])
code, out = cli("ou", "create", "groups", "teams")
code2, out2 = cli("ou", "list")
code3, out3 = cli("ou", "rename", "groups/teams", "squads")
code4, out4 = cli("ou", "delete", "groups/squads")
# covers: cli:domain.ou +
check("domain ou create, list, rename, delete (root)", [code, code2, code3, code4] == [0] * 4
      and "groups/teams" in out2 and "fabric's" in out2 and "groups/squads" in out3, (out, out2, out3, out4))
for args, words, want in ((("ou", "delete", "people"), "one of fabric's folders", 1),
                          (("ou", "create", "groups/fabric", "x"), "takes no admin's folders", 1),
                          (("ou", "move", "x"), "usage", 2)):
    code, out = cli(*args)
    # covers: cli:domain.ou -
    check(f"domain {' '.join(args)} refused ({words})", code == want and words in out, out)

print("--- Kerberos (1.6.12.9)")
got = m_get.get_route(["domain", "kerberos"])
# covers: agent:get.domain.kerberos +
check("GET /v1/domain/kerberos: the realm, its KDC (this DC), the ticket policy as set",
      got["realm"] == V["ad_domain"].upper() and got["kdcs"] == [V["dc_name"]] and got["policy"] == KERBEROS, got)
sh(["docker", "exec", DC, "samba-tool", "spn", "add", "HTTP/web.lan.test", "bob", "-s", "/data/etc/smb.conf"])
dup = sh(["docker", "exec", "-i", DC, "ldbmodify", "-H", "/data/private/sam.ldb",
          "--configfile=/data/etc/smb.conf", "--controls=relax:0"], ok=False,
         input=f"dn: {ldb('(sAMAccountName=carol)', 'dn').split('dn: ', 1)[1].splitlines()[0]}\nchangetype: modify\n"
               "add: servicePrincipalName\nservicePrincipalName: HTTP/web.lan.test\n")
got = m_get.get_route(["domain", "kerberos", "spns"])
rows = [r for r in got["spns"] if r["spn"].lower() == "http/web.lan.test"]
# covers: agent:get.domain.kerberos.spns +
check("GET /v1/domain/kerberos/spns: every SPN with its account (the DC's own among them)",
      any(r["account"] == "DC-0001$" or r["account"].lower().startswith("dc-0001") for r in got["spns"])
      and any(r["account"] == "bob" for r in rows), got["spns"][:4])
check("...a duplicate SPN (on bob and carol) flagged on both" if dup.returncode == 0 else
      "...a duplicate SPN cannot be made here: the DC itself refuses it (Samba enforces SPN uniqueness)",
      (len(rows) == 2 and all(r["duplicate"] for r in rows) and "HTTP/web.lan.test" in got["duplicates"])
      if dup.returncode == 0 else ("unique" in (dup.stdout + dup.stderr).lower()
                                   or "constraint" in (dup.stdout + dup.stderr).lower()), (rows, dup.stderr[-300:]))
TARGET["name"] = "no-such-dc"
for route in (["domain", "kerberos", "spns"], ["groups"], ["ous"]):
    gone, why = refused(m_get.get_route, route)
    # covers: agent:get.domain.kerberos.spns agent:get.groups agent:get.ous -
    check(f"GET /v1/{'/'.join(route)} with the DC not running: refused, saying so", gone and "not reachable" in why, why)
got = m_get.get_route(["domain", "kerberos"])
# covers: agent:get.domain.kerberos -
check("GET /v1/domain/kerberos with the DC not running: the facts it has, the KDCs' error said",
      got["kdcs"] is None and got["kdcs_error"], got)
TARGET["name"] = DC
klist = sh(["docker", "exec", "-i", DC, "bash", "-c",
            f"printf '[libdefaults]\\n default_realm = {V['ad_domain'].upper()}\\n[realms]\\n {V['ad_domain'].upper()} = "
            "{\\n  kdc = 127.0.0.1\\n }\\n' > /tmp/d4-krb5.conf && export KRB5_CONFIG=/tmp/d4-krb5.conf "
            "KRB5CCNAME=FILE:/tmp/cc-d4 && kinit -r 10d carol >/dev/null && klist && kdestroy"],
           ok=False, input=PW + "\n")
spans = [ln.split() for ln in klist.stdout.splitlines() if "krbtgt/" in ln]
renew = [ln for ln in klist.stdout.splitlines() if "renew until" in ln]
conf = sh(["docker", "exec", DC, "bash", "-c", "grep -iE 'ticket lifetime|renewal lifetime' /data/etc/smb.conf; "
           "grep -i clockskew /data/private/krb5.conf"], ok=False).stdout


def hours(a, b):
    import datetime
    fmt = ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S")
    for f in fmt:
        try:
            return (datetime.datetime.strptime(b, f) - datetime.datetime.strptime(a, f)).total_seconds() / 3600
        except ValueError:
            continue
    return -1


life = hours(f"{spans[0][0]} {spans[0][1]}", f"{spans[0][2]} {spans[0][3]}") if spans else -1
# covers: setting:ad_kerberos_policy +
check("ad_kerberos_policy rendered (3 hours, 2 days, 7 minutes): the KDC's lifetimes in smb.conf and its clock skew "
      "in krb5.conf, and the KDC issues a ticket of 3 hours, renewable at most 2 days",
      "kdc:user ticket lifetime = 3" in conf and "kdc:renewal lifetime = 48" in conf and "clockskew = 420" in conf
      and 2.9 < life <= 3.01 and renew, (conf, klist.stdout[-600:], klist.stderr[-400:], life))
for bad, words in (({**KERBEROS, "skew_minutes": 20}, "1 to 15 minutes"), ({**KERBEROS, "renew_days": 31}, "1 to 30 days"),
                   ({**KERBEROS, "ticket_hours": 0}, "at least 1 hour"), ({**KERBEROS, "ticket_hours": 49},
                                                                          "over the renewal age"),
                   ({"ticket_hours": 3}, "exactly")):
    gone, why = refused(check_samba_settings, {**V, "ad_kerberos_policy": bad})
    # covers: setting:ad_kerberos_policy -
    check(f"ad_kerberos_policy {bad} refused at the settings' check ({words})", gone and words in why, why)
done = m_domain.post_domain(["domain", "kerberos", "policy"], "alice", {"ticket_hours": 8, "renew_days": 5}, "alice",
                            {"domain:admin"})
# covers: agent:post.domain.kerberos.policy +
check("POST /v1/domain/kerberos/policy by a Directory Administrator: saved (applied with the next apply), audited",
      done["policy"] == {"ticket_hours": 8, "renew_days": 5, "skew_minutes": 7}
      and HOLD["v"]["ad_kerberos_policy"]["ticket_hours"] == 8 and AUDIT[-1][1] == "AD_KERBEROS_POLICY", done)
for who, body, words in (("hd", {"ticket_hours": 4}, "only a Directory Administrator"),
                         ("alice", {"ticket_hours": 0}, "at least 1 hour"),
                         ("alice", {"ticket_hours": 200}, "over the renewal age"),
                         ("alice", {"renew_days": 31}, "1 to 30 days"),
                         ("alice", {"skew_minutes": 0}, "1 to 15 minutes"),
                         ("alice", {"skew_minutes": 16}, "1 to 15 minutes"),
                         ("alice", {"ticket_hours": "4"}, "each a whole number"),
                         ("alice", {"lifetime": 4}, "each a whole number")):
    gone, why = refused(m_domain.post_domain, ["domain", "kerberos", "policy"], who, body, who, {"domain:admin"})
    # covers: agent:post.domain.kerberos.policy -
    check(f"ticket policy {body} as {who} refused ({words}), nothing saved",
          gone and words in why and HOLD["v"]["ad_kerberos_policy"]["ticket_hours"] == 8, why)
code, out = cli("kerberos", "show")
code2, out2 = cli("kerberos", "spns")
code3, out3 = cli("kerberos", "policy", "--skew-minutes", "6", "--no-apply")
code4, out4 = cli("kerberos", "policy")
# covers: cli:domain.kerberos +
check("domain kerberos show, spns, policy --no-apply and the policy shown (root)", [code, code2, code3, code4]
      == [0] * 4 and "tickets 8 hours" in out and "HTTP/web.lan.test" in out2 and "recorded" in out3
      and "skew_minutes: 6" in out4, (out, out3, out4))
for args, words, want in ((("kerberos", "policy", "--skew-minutes", "30"), "1 to 15 minutes", 1),
                          (("kerberos", "policy", "--ticket-hours", "x"), "whole number", 1),
                          (("kerberos", "frob"), "usage", 2)):
    code, out = cli(*args)
    # covers: cli:domain.kerberos -
    check(f"domain {' '.join(args)} refused ({words})", code == want and words in out, out)

print("--- the Directory Administrators' own: the password policy and the grants (2.1.6.71, 2.1.6.73)")
gone, why = refused(set_domain_password_policy, "hd", {"minimum_length": 16}, "web", "hd", DC)
check("the domain's password policy: refused to anyone not a Directory Administrator, even with domain:admin",
      gone and "only a Directory Administrator" in why, why)
done = set_domain_password_policy("alice", {"minimum_length": 15}, "web", "alice", DC)
check("...a Directory Administrator changes it", done["minimum_length"] == 15, done)
done = m_domain.post_domain(["domain", "password-policy"], "alice", {"minimum_length": 16}, "alice", {"domain:admin"})
# covers: agent:post.domain.password-policy +
check("POST /v1/domain/password-policy by a Directory Administrator: saved, audited",
      done["policy"]["minimum_length"] == 16 and V["ad_password_policy"]["minimum_length"] == 16
      and AUDIT[-1][1] == "AD_PASSWORD_POLICY", done)
for who, body, words in (("hd", {"minimum_length": 17}, "only a Directory Administrator"),
                         ("alice", {"minimum_length": 99}, "minimum")):
    gone, why = refused(m_domain.post_domain, ["domain", "password-policy"], who, body, who, {"domain:admin"})
    # covers: agent:post.domain.password-policy -
    check(f"POST /v1/domain/password-policy {body} as {who} refused ({words}), nothing saved",
          gone and words.lower() in why.lower() and V["ad_password_policy"]["minimum_length"] == 16, why)
gone, why = refused(add_grant, V, "hd", "hd-grant", {"who": ["helpdesk-lan"], "where": ["site-lan"],
                                                     "people": ["reset"]}, None, "web", DC, "hd")
check("a grant made by anyone not a Directory Administrator refused (groups:admin alone is not enough)",
      gone and "only a Directory Administrator" in why, why)

print("--- a relaxation shown while on (2.1.6.88)")
code, out = cli("status")
V["grants_fallback_open"] = True
code2, out2 = cli("status")
V.pop("grants_fallback_open")
check("fabricctl domain status says RELAXED while grants_fallback_open is on, and not otherwise",
      "RELAXED: grants_fallback_open is on" in out2 and "RELAXED" not in out, (out, out2))

print("--- Apply per page (manual 1.8.6.5): fabric-agent's own pending store, against this DC")
import agent.post_pending as m_pending  # noqa: E402
from agent.job_store import JOBS  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402

m_pending.load_vars = lambda: V
ADMIN = set(BUNDLES["admin"])


def pend(route, body=None, who="alice", perms=ADMIN):
    """A pending route as the agent answers it for a signed-in person (their token's user and permissions)."""
    return m_pending.post_pending(route, who, body or {}, perms, None)


def hold(change, body=None, who="alice", perms=ADMIN):
    return pend(["pending", "hold"], {"route": change, "body": body or {}}, who, perms)


def applied(page, who="alice", perms=ADMIN):
    """Apply a page and wait for its job; the job's result."""
    job = pend(["pending", page, "apply"], who=who, perms=perms)["id"]
    for _ in range(600):
        done = JOBS.read(job, who)
        if done["state"] != "running":
            return done["result"] or {"error": done["error"]}
        time.sleep(0.2)
    return {"error": "timed out"}


def review(page, who="alice", perms=ADMIN):
    return m_get.get_route(["pending", page], who, perms)


def title(uid):
    return ldb(f"(sAMAccountName={uid})", "title").split("title: ")[-1].split("\n")[0].strip()


before = title("bob")
out = hold("people/bob/edit", {"title": "Pending title"})
# covers: agent:post.pending.hold +
mine = review("people")["changes"]
# covers: agent:get.pending.* +
check("a change held on People: listed with its old and new values; the DC untouched until Apply",
      out["page"] == "people" and out["pending"] == 1 and mine[0]["what"] == "Edit bob"
      and mine[0]["new"] == {"title": "Pending title"} and title("bob") == before, (out, mine, title("bob")))
# covers: agent:get.pending +
check("...the counts: one pending on People, none elsewhere", m_get.get_route(["pending"], "alice", ADMIN)
      == {"people": {"pending": 1, "running": False}}, m_get.get_route(["pending"], "alice", ADMIN))
check("...another person sees none of alice's pending changes (held per person)",
      review("people", "hd", set(BUNDLES["fabric-helpdesk"]))["changes"] == [])
result = applied("people")
# covers: agent:post.pending.*.apply +
check("Apply: one job, the change done, written to the DC, nothing left pending",
      result.get("applied") == 1 and title("bob") == "Pending title" and review("people")["changes"] == []
      and review("people")["queue"][0]["items"][0]["state"] == "done", (result, title("bob")))
hold("people/bob/edit", {"title": "Discarded"})
out = pend(["pending", "people", "discard"])
# covers: agent:post.pending.*.discard +
check("Discard: dropped, the DC untouched", out == {"dropped": 1, "pending": 0} and title("bob") == "Pending title",
      out)
hold("people/bob/edit", {"title": "Mine"})
m_people.post_people(["people", "bob", "edit"], "dee", {"title": "Dee's"}, "dee")    # another person, first
result = applied("people")
mine = review("people")["changes"]
check("refused at Apply: bob changed since the change was made; held again against bob as he is now, the DC "
      "keeps the other person's change", result["items"][0]["state"] == "failed" and "changed since"
      in result["items"][0]["why"] and title("bob") == "Dee's" and mine[0]["changed_since"] is True
      and mine[0]["old"] == {"title": "Dee's"}, (result, mine))
result = applied("people")
check("...applied once reviewed again", result.get("applied") == 1 and title("bob") == "Mine", result)
hold("people/bob/edit", {"title": "First"})
hold("people/fabric-admin/reset")
hold("people/bob/edit", {"title": "Third"})
hold("domain/password-policy", {"minimum_length": 18})
result = applied("people")
mine = review("people")["changes"]
check("a failing change stops the Apply, says which and why; the one after not run; both still pending",
      [i["state"] for i in result["items"]] == ["done", "failed", "not run"] and len(result["items"][1]["why"]) > 10
      and title("bob") == "First" and [c["what"] for c in mine]
      == ["Reset the sign-in of fabric-admin", "Edit bob"], (result, mine))
check("...another page's changes untouched by People's Apply (the password policy still waits on Policies)",
      [c["what"] for c in review("policies")["changes"]] == ["Change the password policy"]
      and V["ad_password_policy"]["minimum_length"] != 18, review("policies"))
pend(["pending", "people", "discard"])
pend(["pending", "policies", "discard"])
hold("people/bob/edit", {"title": "No right"})
result = applied("people", perms=ADMIN - {"people:edit"})
# covers: agent:post.pending.*.apply -
check("refused at Apply without the change's permission, naming it; the DC untouched",
      result["items"][0]["state"] == "failed" and "people:edit" in result["items"][0]["why"]
      and title("bob") == "First", result)
pend(["pending", "people", "discard"])
gone, why = refused(hold, "people/bob/edit", {"title": "x"}, "aud", set(BUNDLES["fabric-auditor"]))
# covers: agent:post.pending.hold -
check("refused: holding a change without its permission (an auditor's edit), named", gone and "people:edit" in why,
      why)
gone, why = refused(hold, "account/password", {"current": "x", "new": "y"})
check("refused: holding a change that is done at once (a person's own password)", gone and "not held" in why, why)
gone, why = refused(pend, ["pending", "people", "apply"])
check("refused: Apply with nothing pending", gone and "nothing is pending" in why, why)
gone, why = refused(pend, ["pending", "people", "drop"], {"id": "no-such"})
# covers: agent:post.pending.*.drop -
check("refused: dropping a change that is not there", gone and "no such change" in why, why)
try:
    pend(["pending", "nowhere", "apply"])
    why = "allowed"
except m_pending.RouteNotFound:
    why = "not found"
check("refused: a page that holds nothing (404)", why == "not found", why)
print("--- a read of one thing that is not there: NotFound, the handler's 404 (2.1.8.21)")
from fabriclib.common.errors import NotFound  # noqa: E402
for route in (["people", "nobody-here"], ["groups", "nobody-here"], ["machines", "nobody-here"],
              ["domain", "grants", "nobody-here"]):
    try:
        m_get.get_route(route, "alice")
        why = "answered"
    except NotFound as exc:
        why = f"not found: {exc}"
    except Exception as exc:  # noqa: BLE001
        why = f"{type(exc).__name__}: {exc}"
    check(f"GET /v1/{'/'.join(route)}: NotFound (404), saying what is not there", why.startswith("not found: no "),
          why)
print("--- 802.1X's Devices and Device roles on their own Apply (2.1.8.10, 1.8.6.5)")
from fabriclib.directory.device_overview import device_overview as m_devov  # noqa: E402
from fabriclib.directory.update_device import update_device as m_upd_device  # noqa: E402


def device(name):
    return next((d for d in m_devov(V)["devices"] if d["name"] == name), None)


FIELDS = {"type": "printer", "owner": "bob", "description": "", "macs": ["aa:bb:cc:5e:00:01"], "enabled": True,
          "roles": []}
out = hold("roles", {"name": "pend-role", "fields": {"description": "", "vlan": "", "priority": "70",
                                                     "permissions": []}})
check("a device role held on Device roles, the DC untouched", out["page"] == "roles"
      and review("roles")["changes"][0]["what"] == "Add device role pend-role"
      and all(r["name"] != "pend-role" for r in m_devov(V)["roles"]), out)
result = applied("roles")
check("...applied: the role in the DC", result.get("applied") == 1
      and any(r["name"] == "pend-role" for r in m_devov(V)["roles"]), result)
out = hold("devices", {"name": "pend-dev", "fields": {**FIELDS, "roles": ["pend-role"]}})
check("a device held on Devices, its own page's Apply (not Device roles'), the DC untouched", out["page"] == "devices"
      and review("devices")["changes"][0]["what"] == "Add device pend-dev" and review("roles")["changes"] == []
      and device("pend-dev") is None, out)
result = applied("devices")
check("...applied: the device in the DC, owner and role set", result.get("applied") == 1
      and (device("pend-dev") or {}).get("owner") == "bob" and device("pend-dev")["roles"] == ["pend-role"], result)
hold("devices/pend-dev", {"fields": {**FIELDS, "description": "mine", "roles": ["pend-role"]}})
mine = review("devices")["changes"]
check("a device's change: its old and new fields on the Review", mine[0]["what"] == "Change device pend-dev"
      and mine[0]["old"]["fields"]["description"] == "" and mine[0]["new"]["fields"]["description"] == "mine", mine)
m_upd_device(V, "dee", "pend-dev", {**FIELDS, "description": "dee's", "roles": ["pend-role"]}, source="test")
result = applied("devices")
check("refused at Apply: the device changed since; the DC keeps the other person's change",
      result["items"][0]["state"] == "failed" and "changed since" in result["items"][0]["why"]
      and device("pend-dev")["description"] == "dee's", result)
pend(["pending", "devices", "discard"])
hold("roles/pend-role/delete")
result = applied("roles")
check("refused at Apply: removing a device role that still has a device, with why", result["items"][0]["state"]
      == "failed" and len(result["items"][0]["why"]) > 10 and any(r["name"] == "pend-role" for r in m_devov(V)["roles"]),
      result)
pend(["pending", "roles", "discard"])
gone, why = refused(hold, "devices/pend-dev/delete", None, "aud", set(BUNDLES["fabric-auditor"]))
check("refused: an auditor holding a device's removal (devices:admin named)", gone and "devices:admin" in why, why)
hold("devices/pend-dev/delete")
applied("devices")
hold("roles/pend-role/delete")
result = applied("roles")
check("...the device removed on Devices' Apply, then the empty role on Device roles'", device("pend-dev") is None
      and all(r["name"] != "pend-role" for r in m_devov(V)["roles"]) and result.get("applied") == 1, result)
out = pend(["pending", "people", "discard"])
# covers: agent:post.pending.*.discard -
check("Discard with nothing pending: nothing dropped", out == {"dropped": 0, "pending": 0}, out)
try:
    m_get.get_route(["pending", "people"], None, None)
    why = "allowed"
except ValidationError as e:
    why = str(e)
# covers: agent:get.pending agent:get.pending.* -
check("refused: the host (a root peer) holds nothing", "signed-in person" in why, why)
out = hold("people/bob/edit", {"title": "Dropped"})
# covers: agent:post.pending.*.drop +
check("drop one change by its id", pend(["pending", "people", "drop"], {"id": out["id"]}) == {"dropped": 1,
                                                                                         "pending": 0})

print("--- the Directory's Overview (1.6.12.3) and a person's page refused")
over = m_get.get_route(["directory"], "alice")
# covers: agent:get.directory +
# (the domain's status and replication ask the container `samba` by name, which this suite's DC is not: shown as not
# running and an error there, as on a host without a DC; the directory's own reads go through run_op to this DC)
check("GET /v1/directory: the domain, its functional level, this DC writable, the sites, the counts; nothing failed",
      over["error"] == "" and over["level"] and any(d["writable"] for d in over["dcs"]) and "lan" in over["sites"]
      and over["counts"]["people"] >= 3 and over["counts"]["groups"] > 0 and over["counts"]["ous"] > 0
      and isinstance(over["replication"], dict) and over["status"]["domain"], over)
gone, why = refused(m_get.get_route, ["people", "nobody"], "alice")
# covers: agent:get.people.* -
check("refused: GET /v1/people/nobody (no person nobody: NotFound, 2.1.8.21)", gone and "no person nobody" in why, why)

print("--- My account (manual 1.8.6.6): the person's own read; a managed group's members on My account's Apply")
got = m_get.get_route(["account"], "bob")
# covers: agent:get.account +
check("GET /v1/account as bob: his details as the DC has them (his title among the 15 fields), his groups, his "
      "certificates (none issued here) and devices", got["uid"] == "bob" and got["person"]["title"] == title("bob")
      and set(got["person"]) >= {"first", "last", "email", "manager", "employee_id"} and "site-lan" in got["groups"]
      and got["certs"] == [] and isinstance(got["devices"], list), got)
for user, words in ((None, "sign in as them"), ("nobody", "no such")):
    gone, why = refused(m_get.get_route, ["account"], user)
    # covers: agent:get.account -
    check(f"GET /v1/account as {user} refused ({words})", gone and words in why, why)
out = hold("account/groups/ops-team/members", {"action": "add", "member": "newbie"}, who="sup", perms=set())
# covers: agent:post.account.groups.*.members +
check("sup (no fabric role) holds a member change from My account: on the account page, in a sentence, the DC "
      "untouched", out["page"] == "account" and out["what"] == "Add newbie to group ops-team"
      and "CN=ops-team," not in ldb("(sAMAccountName=newbie)", "memberOf"), out)
check("...nobody else sees it, and an admin's account page holds none of it",
      review("account")["changes"] == [] and review("account", "sup", set())["changes"][0]["what"]
      == "Add newbie to group ops-team")
done = applied("account", "sup", set())
check("...applied: newbie in ops-team, seen in AD; the queue on My account sup's alone",
      "CN=ops-team," in ldb("(sAMAccountName=newbie)", "memberOf") and done["items"][0]["state"] == "done"
      and review("account", "sup", set())["queue"] and not review("account")["queue"], done)
hold("account/groups/ops-team/members", {"action": "remove", "member": "newbie"}, who="sup", perms=set())
done = applied("account", "sup", set())
# covers: agent:post.account.groups.*.members -
check("...a removal the group's controls do not allow: refused at Apply by the DC's check, newbie still a member",
      done["items"][0]["state"] == "failed" and "may not remove members" in done["items"][0]["why"]
      and "CN=ops-team," in ldb("(sAMAccountName=newbie)", "memberOf"), done)
pend(["pending", "account", "discard"], who="sup", perms=set())
gone, why = refused(hold, "account/groups/nogroup/members", {"action": "add", "member": "newbie"}, "sup", set())
check("refused when held: a group that is not there", gone and "no group nogroup" in why, why)

if not os.environ.get("FABRIC_TEST_KEEP"):
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
