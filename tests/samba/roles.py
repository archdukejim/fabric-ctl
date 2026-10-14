"""The `samba` suite, layered roles on a real DC (decisions 2.1.9.21, 2.1.9.22; manual 1.6.3.18, 1.9.8.20): the top
`lan` with `house1` (and `house1a` below it) and `house2` beside it, each prepared in the top's DC the way a join does
(prepare_site). Proves, signed in over LDAP as the people themselves: a site's admin (`house1-admins`) adds a person
to its own site, unlocks, disables and enables them and resets their password; and is refused for another site's
people (a sibling's, the sub-site's, the parent's), for a person who holds a role (Central IT, another local admin), for
machines, GPO links, the address plan (DHCP), and for its own site's role groups (no self-grant). The pre-0.9 default
(`house1-admins` in the role groups) is taken away at convergence and said; a grant from the top is kept. Granting runs
as the sites' agent accounts: the top grants house1 a role, house1 cannot grant itself or its sibling, and a granted
AD role works at that site only.
    sudo python3 tests/samba/roles.py
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[0:0] = [os.path.join(REPO, "src"), HERE]
from start_dc import IMAGE, start_dc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.samba.prepare_site import prepare_site  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-roles")
NET, SUBNET, IP, DC = "rolestest_net", "10.254.38.0/24", "10.254.38.10", "rolestest-dc"
CONF = "/data/etc/smb.conf"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def dc(*args, input=None):
    return sh(["docker", "exec", "-i", DC, *args], input=input)


def cleanup():
    sh(["docker", "rm", "-f", DC])
    sh(["docker", "network", "rm", NET])


def as_user(user, password, tool, ldif=None, *extra):
    """An ldb tool (or samba-tool) run against the DC over LDAP as a person, from a throwaway container of the DC's
    image; the credentials in a 0600 file, never on a command line."""
    auth = os.path.join(W, f"{user}.auth")
    with open(auth, "w") as f:
        f.write(f"username={user}\npassword={password}\ndomain=AD\n")
    os.chmod(auth, 0o600)
    with open(os.path.join(W, "op.ldif"), "w") as f:
        f.write(ldif or "")
    where = ["-H", f"ldap://{IP}", "-A", "/auth"]
    if tool == "samba-tool":                # its subcommand first, then where and as whom
        args = [*extra, *where]
    else:
        args = [*where, *(["/op.ldif"] if ldif is not None else list(extra))]
    return sh(["docker", "run", "--rm", "--network", NET, "-v", f"{auth}:/auth:ro", "-v", f"{W}/op.ldif:/op.ldif:ro",
               "--entrypoint", tool, IMAGE, *args])


def ok(res):
    """An ldbadd or ldbmodify that did what it was asked ("Added 1 records successfully")."""
    return "successfully" in (res.stdout + res.stderr) and "ERR" not in res.stderr


def person(name, ou, *groups):
    pw = "Rl-" + random_password(20)
    dc("samba-tool", "user", "create", name, pw, f"--userou={ou}", "-s", CONF)
    for g in groups:
        dc("samba-tool", "group", "addmembers", g, name, "-s", CONF)
    return pw


def modify(dn, attr, value):
    return f"dn: {dn},{BASE}\nchangetype: modify\nreplace: {attr}\n{attr}: {value}\n"


def members(group):
    out = dc("ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={group})", "member").stdout
    return {line.split(":", 1)[1].strip().split(",")[0][3:].lower() for line in out.splitlines()
            if line.startswith("member:")}


cleanup()
os.makedirs(W, exist_ok=True)
top = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP, site="lan")
RV, RS = top["v"], top["secrets"]
BASE = dc("ldbsearch", "-H", "/data/private/sam.ldb", "-s", "base", "-b", "", "defaultNamingContext"
          ).stdout.split("defaultNamingContext: ")[1].split()[0]
LAN, H1, H2 = "OU=lan,OU=sites", "OU=house1,OU=lan,OU=sites", "OU=house2,OU=lan,OU=sites"
H1A = f"OU=house1a,{H1}"
AGENTS = {}
for site, parent, block, cidr in (("house1", "lan", "2000000-2999999", "10.61.0.0/24"),
                                  ("house2", "lan", "3000000-3999999", "10.62.0.0/24"),
                                  ("house1a", "house1", "4000000-4999999", "10.63.0.0/24")):
    accounts = {k: random_password() for k in ("agent", "keycloak", "radius")}
    pv = RV if parent == "lan" else {**RV, "site_name": parent}
    done = prepare_site(pv, site, [{"name": "lan", "cidr": cidr}], block, accounts, random_password(), container=DC)
    AGENTS[site] = accounts["agent"]
    check(f"{site} prepared in the top's DC below {parent}, its console role groups made empty",
          f"group {site}-network-operators created" in " ".join(done) and not members(f"{site}-network-operators"),
          done)

print("--- the pre-0.9 default taken away, a grant kept (narrow_site_admins)")
for role in ("ou-admins", "machine-admins", "gpo-admins", "windows-admins"):
    dc("samba-tool", "group", "addmembers", f"house1-{role}", "house1-admins", "-s", CONF)    # as 0.8 left it
check("as 0.8 left it: house1-admins in its four AD role groups", "house1-admins" in members("house1-ou-admins"))
changed = converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
check("the top's convergence narrows house1 (a site below it) and says so per group",
      all("house1-admins" not in members(f"house1-{r}") for r in ("ou-admins", "machine-admins", "gpo-admins",
                                                                  "windows-admins"))
      and len([c for c in changed if "house1-admins removed (2.1.9.21" in c]) == 4, changed)
check("at the top the organisation's admins (Central IT) are in lan's four AD role groups, lan-admins in none",
      all("admins" in members(f"lan-{r}") and "lan-admins" not in members(f"lan-{r}")
          for r in ("ou-admins", "machine-admins", "gpo-admins", "windows-admins")))
check("and the next convergence changes nothing",
      converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC) == [])

print("--- the site helpdesk in AD (house1-admins)")
desk_pw = person("deskh1", f"OU=people,{H1}", "house1-admins")
person("ann", f"OU=people,{H1}", "house1-users")
person("kid", f"OU=people,{H1A}", "house1a-users")
person("sib", f"OU=people,{H2}", "house2-users")
person("topper", f"OU=people,{LAN}", "lan-users")
person("itguy", f"OU=people,{H1}", "admins")                   # Central IT living at house1
person("peer", f"OU=people,{H1}", "house1-admins")             # another local admin
converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)    # the denies on people with roles
add = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=newbie,OU=people,{H1},{BASE}\nobjectClass: user\n"
              "sAMAccountName: newbie\n")
check("house1's admin adds a person to house1", ok(add), add.stderr[-300:])
check("...disables and enables them", ok(as_user("deskh1", desk_pw, "ldbmodify",
                                                 modify(f"CN=ann,OU=people,{H1}", "userAccountControl", "514")))
      and ok(as_user("deskh1", desk_pw, "ldbmodify", modify(f"CN=ann,OU=people,{H1}", "userAccountControl", "512"))))
check("...unlocks them (lockoutTime 0)", ok(as_user("deskh1", desk_pw, "ldbmodify",
                                                    modify(f"CN=ann,OU=people,{H1}", "lockoutTime", "0"))))
reset = as_user("deskh1", desk_pw, "samba-tool", None, "user", "setpassword", "ann", "--random-password")
check("...resets their password", reset.returncode == 0, (reset.stdout + reset.stderr)[-300:])
for who, ou, what in (("sib", H2, "a sibling site's person"), ("kid", H1A, "the sub-site's person"),
                      ("topper", LAN, "the parent's person"), ("itguy", H1, "Central IT living at house1"),
                      ("peer", H1, "another local admin")):
    res = as_user("deskh1", desk_pw, "ldbmodify", modify(f"CN={who},OU=people,{ou}", "userAccountControl", "514"))
    pw = as_user("deskh1", desk_pw, "samba-tool", None, "user", "setpassword", who, "--random-password")
    check(f"refused: disabling or resetting {what}", not ok(res) and pw.returncode != 0,
          (res.stdout + res.stderr + pw.stderr)[-300:])
pc = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=PC9,OU=machines,{H1},{BASE}\nobjectClass: computer\n"
             "sAMAccountName: PC9$\nuserAccountControl: 4096\n")
check("refused: adding a machine (that is machine-admins')", not ok(pc))
gp = as_user("deskh1", desk_pw, "ldbmodify", modify(H1, "gPOptions", "1"))
check("refused: blocking GPO inheritance on the site's OU (that is gpo-admins')", not ok(gp))
net = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=evil,OU=networks,{H1},{BASE}\nobjectClass: fabricNetwork\n"
              "fabricCidr: 10.61.9.0/24\n")
check("refused: writing the site's address plan (DHCP)", not ok(net))
grp = as_user("deskh1", desk_pw, "ldbmodify", f"dn: CN=house1-network-operators,OU=groups,{H1},{BASE}\n"
              "changetype: modify\nadd: member\nmember: CN=deskh1,OU=people," + H1 + "," + BASE + "\n")
check("refused: the site's admin granting itself a role (its own role group's members)", not ok(grp))
dl = as_user("deskh1", desk_pw, "ldbdel", None, f"CN=ann,OU=people,{H1},{BASE}")
check("refused: removing a person (Central IT's)", dl.returncode != 0)

print("--- granting from above (grant_site_role as the sites' agents)")
H1V, H1S = {**RV, "site_name": "house1"}, {**RS, "ad_agent_password": AGENTS["house1"]}


def refused(fn, *a):
    try:
        fn(*a)
    except ValidationError as e:
        return str(e)
    return ""


# covers: agent:post.federation.roles +
g = run_op(RV, RS, "grant_site_role", {"target": "house1", "role": "machine-admins", "member": "", "grant": True}, DC)
check("the top grants house1 machine-admins (to house1-admins)", g["changed"] and "house1-admins"
      in members("house1-machine-admins"), g)
pc2 = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=PC8,OU=machines,{H1},{BASE}\nobjectClass: computer\n"
              "sAMAccountName: PC8$\nuserAccountControl: 4096\n")
check("...house1's admin now adds a machine at house1", ok(pc2), pc2.stderr[-300:])
pc3 = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=PC7,OU=machines,{H2},{BASE}\nobjectClass: computer\n"
              "sAMAccountName: PC7$\nuserAccountControl: 4096\n")
check("refused: ...but not at house2 (a granted role works at that site only)", not ok(pc3))
converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
check("the grant survives convergence (marked)", "house1-admins" in members("house1-machine-admins"))
# a role granted at a site works at every site below it (2.1.9.21, revised 2026-10-13): the top's convergence gave
# house1-machine-admins house1a's machines (ensure_site_acl for each site below)
pc4 = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=PC6,OU=machines,{H1A},{BASE}\nobjectClass: computer\n"
              "sAMAccountName: PC6$\nuserAccountControl: 4096\n")
check("...house1's admin adds a machine at house1a, the site below house1", ok(pc4), pc4.stderr[-300:])
pc5 = as_user("deskh1", desk_pw, "ldbadd", f"dn: CN=PC5,OU=machines,{LAN},{BASE}\nobjectClass: computer\n"
              "sAMAccountName: PC5$\nuserAccountControl: 4096\n")
check("refused: ...but not at the top (lan), the site above", not ok(pc5))
# covers: agent:post.federation.roles -
why = refused(run_op, H1V, H1S, "grant_site_role", {"target": "house1", "role": "ou-admins", "member": "",
                                                    "grant": True}, DC)
check("refused: house1 granting itself", "cannot grant itself" in why, why)
why = refused(run_op, H1V, H1S, "grant_site_role", {"target": "house2", "role": "helpdesk", "member": "",
                                                    "grant": True}, DC)
check("refused: house1 granting its sibling house2", "not above it" in why, why)
sub = run_op(H1V, H1S, "grant_site_role", {"target": "house1a", "role": "helpdesk", "member": "", "grant": True}, DC)
check("house1 grants the site below it (house1a helpdesk)", sub["changed"], sub)
listed = run_op(H1V, H1S, "list_site_roles", {}, DC)
check("house1 lists itself and house1a, never house2 or lan (2.1.9.22)",
      [s["site"] for s in listed["sites"]] == ["house1", "house1a"], listed)
back = run_op(RV, RS, "grant_site_role", {"target": "house1", "role": "machine-admins", "member": "", "grant": False},
              DC)
check("the top takes it back", back["changed"] and "house1-admins" not in members("house1-machine-admins"))

print("--- root on a branch host cannot grant through the agent's credentials (2.1.9.21, revised 2026-10-13)")
AG = "fabric-agent-house1"
deskdn = f"CN=deskh1,OU=people,{H1},{BASE}"
for group in ("house1-ou-admins", "house1-fabric-admins", "house1-network-operators", "house1-admins"):
    add = as_user(AG, AGENTS["house1"], "ldbmodify", f"dn: CN={group},OU=groups,{H1},{BASE}\nchangetype: modify\n"
                  f"add: member\nmember: {deskdn}\n")
    check(f"refused: house1's agent adding a member to {group}", not ok(add) and "deskh1" not in members(group),
          add.stderr[-300:])
why = refused(run_op, H1V, H1S, "add_group_member", {"group": "house1-machine-admins", "uid": "deskh1"}, DC)
check("refused: ...nor through fabric's own operation (add_group_member as house1's agent)", why != "", why)
ren = as_user(AG, AGENTS["house1"], "ldbmodify", f"dn: CN=house1-gpo-admins,OU=groups,{H1},{BASE}\n"
              "changetype: modify\nreplace: sAMAccountName\nsAMAccountName: house1-gpo-old\n")
check("refused: house1's agent renaming a role group (so it could make another of that name)", not ok(ren))
mine = as_user(AG, AGENTS["house1"], "ldbmodify", f"dn: CN=house1-users,OU=groups,{H1},{BASE}\nchangetype: modify\n"
               f"add: member\nmember: {deskdn}\n")
check("house1's agent still adds people to house1-users (a new person joins it)", ok(mine), mine.stderr[-300:])
g = run_op(H1V, H1S, "grant_site_role", {"target": "house1a", "role": "machine-admins", "member": "", "grant": True},
           DC)
check("house1's agent still grants the site below it (house1a machine-admins)", g["changed"], g)
run_op(H1V, H1S, "grant_site_role", {"target": "house1a", "role": "machine-admins", "member": "", "grant": False}, DC)
check("the top still converges house1's groups as the system: house1-admins nested in house1-users",
      "house1-admins" in members("house1-users"))
gone = as_user(AG, AGENTS["house1"], "ldbdel", None, f"CN=house1-windows-admins,OU=groups,{H1},{BASE}")
if gone.returncode == 0:        # its right to delete the OU's children reaches the group: re-made, then refused
    made = as_user(AG, AGENTS["house1"], "ldbadd", f"dn: CN=house1-windows-admins,OU=groups,{H1},{BASE}\n"
                   f"objectClass: group\nsAMAccountName: house1-windows-admins\nmember: {deskdn}\n")
    changed = converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
    check("a role group house1's agent deleted and re-made is refused by the top's convergence, said why",
          ok(made) and any("was made by fabric-agent-house1" in c for c in changed), changed)
    back = run_op(RV, RS, "grant_site_role", {"target": "house1", "role": "windows-admins", "member": "",
                                              "grant": True}, DC)
    changed = converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
    check("the top's grant replaces it (deskh1 gone, house1-admins in it) and convergence takes it again",
          back["remade"] and members("house1-windows-admins") == {"house1-admins"}
          and not any("was made by" in c for c in changed), (back, changed))
else:
    check("house1's agent cannot delete a role group either", gone.returncode != 0)

print("--- remake_site_group: house1-admins made again from above (2.3.9.2.8 option (a))")
# covers: agent:post.federation.roles -
why = refused(run_op, H1V, H1S, "remake_site_group", {"target": "house1", "role": "admins"}, DC)
check("refused: house1 remaking its own admins group", "cannot repair its own" in why, why)
gone = as_user(AG, AGENTS["house1"], "ldbdel", None, f"CN=house1-admins,OU=groups,{H1},{BASE}")
if gone.returncode == 0:
    as_user(AG, AGENTS["house1"], "ldbadd", f"dn: CN=house1-admins,OU=groups,{H1},{BASE}\nobjectClass: group\n"
            f"sAMAccountName: house1-admins\nmember: {deskdn}\n")
    # covers: agent:post.federation.roles +
    r = run_op(RV, RS, "remake_site_group", {"target": "house1", "role": "admins"}, DC)
    changed = converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
    check("the top remakes it: replaced empty, in house1-users, and the next convergence takes it again",
          r["remade"] and members("house1-admins") == set() and "house1-admins" in members("house1-users")
          and not any("was made by" in c for c in changed), (r, changed))
else:
    r = run_op(RV, RS, "remake_site_group", {"target": "house1", "role": "admins"}, DC)
    check("house1's agent cannot delete its admins group; the top's remake leaves fabric's group as it is",
          not r["changed"], r)

print("--- an account holds a role only at its own level (2.1.9.24)")
changed = converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
check("convergence reports itguy (Central IT living at house1), moving nobody",
      any(c.startswith("misplaced: itguy lives at house1") for c in changed)
      and "CN=itguy,OU=people," + H1 in dc("ldbsearch", "-H", "/data/private/sam.ldb", "(sAMAccountName=itguy)",
                                           "dn").stdout, changed)
pw = as_user(AG, AGENTS["house1"], "samba-tool", None, "user", "setpassword", "itguy", "--random-password")
check("refused: house1's own agent resetting itguy's password (every write denied)", pw.returncode != 0,
      (pw.stdout + pw.stderr)[-300:])
pw = as_user(AG, AGENTS["house1"], "samba-tool", None, "user", "setpassword", "ann", "--random-password")
check("...but it still resets ann's (house1's own person, no role beyond house1)", pw.returncode == 0,
      (pw.stdout + pw.stderr)[-300:])
why = refused(run_op, RV, RS, "grant_site_role", {"target": "house1", "role": "helpdesk", "member": "kid",
                                                  "grant": True}, DC)
check("refused: a role at house1 granted to kid, who lives at house1a, naming the move", "kid lives at house1a" in why
      and "fabricctl people move kid --site house1" in why, why)
why = refused(run_op, RV, RS, "add_group_member", {"group": "house1-gpo-admins", "uid": "kid"}, DC)
check("refused: kid put in house1-gpo-admins", "kid lives at house1a" in why, why)
why = refused(run_op, H1V, H1S, "move_person", {"uid": "itguy", "target": "lan"}, DC)
check("refused: house1 moving itguy up to lan (from below)", "only a site above both" in why, why)
mv = run_op(RV, RS, "move_person", {"uid": "itguy", "target": "lan", "privileged": ["admins"]}, DC)
changed = converge_domain(RV, os.path.join(W, "dc", "federation.yaml"), RS, container=DC)
check("the top moves itguy to lan; convergence reports nobody now",
      mv["moved"] and not any(c.startswith("misplaced: itguy") for c in changed), (mv, changed))

print("--- unlock_person (the agent's operation)")
dc("ldbmodify", "-H", "/data/private/sam.ldb", input=f"dn: CN=ann,OU=people,{H1},{BASE}\nchangetype: modify\n"
   "replace: lockoutTime\nlockoutTime: 132000000000000000\n")
u = run_op(H1V, H1S, "unlock_person", {"uid": "ann"}, DC)
check("house1's agent unlocks ann", u == {"uid": "ann", "unlocked": True}, u)
dc("ldbmodify", "-H", "/data/private/sam.ldb", input=f"dn: CN=sib,OU=people,{H2},{BASE}\nchangetype: modify\n"
   "replace: lockoutTime\nlockoutTime: 132000000000000000\n")
check("refused: house1's agent unlocking a sibling's locked-out person (AD's limit on the agent)",
      refused(run_op, H1V, H1S, "unlock_person", {"uid": "sib"}, DC) != "")

if not os.environ.get("SAMBA_TEST_KEEP"):
    cleanup()
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
