"""The `samba` suite, grants (manual 1.6.13.4 to 1.6.13.8): a real DC from fabric's image and real Ubuntu 24.04 members
joined with fabric's join-linux.sh (a server and a desktop of site lan, a desktop of site lab), sssd enforcing the GPOs
fabric compiles. Proves: the shipped grants (a server administrator signs in and has sudo on a server, not remotely
nor with sudo at a desktop; every person signs in at a desktop's keyboard and nowhere else); the owner's case (a
restricting grant keeps lan's desktops to lan's people, the other site's desktop open); two grants on one machine both
holding (one GPO per set); a membership change by fabric taking effect at the next sign-in, and one made with
samba-tool once compiled; the fallback (a machine no grant reaches admits nobody from the domain, its link first in
gPLink); the computed groups refused to every other writer, the Directory Administrators and fabric's agent account
too, and a person put in a set's group taken out; every refusal of 1.6.13.4 with its message (the tiers' groups, the DC
hosts, sudo of every command for everyone, empty who or where, ...); `fabricctl domain grant` and the agent's routes,
positive and negative; explain; a second convergence changing nothing.
    sudo python3 tests/samba/grants.py          (FABRIC_TEST_KEEP=1 leaves the containers for a look)
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import POLICY, start_dc  # noqa: E402
import agent.get_route as m_get  # noqa: E402
import agent.post_grants as m_post  # noqa: E402
import fabriclib.directory.set_person_group as m_group  # noqa: E402
import fabriclib.grants.add_grant as m_add  # noqa: E402
import fabriclib.grants.remove_grant as m_remove  # noqa: E402
import fabriclib.grants.run_grant_command as m_cmd  # noqa: E402
import fabriclib.grants.set_grant as m_set  # noqa: E402
import fabriclib.grants.sync_grants as m_sync  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.grants.grant_request import grant_request  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-grants")
NET, SUBNET, IP, WEB_IP = "grants_net", "10.254.39.0/24", "10.254.39.10", "10.254.39.20"
DC, WEB = "grdc", "gr-certs"
SRV, DSK, LAB = "grsrv", "grdsk", "grlab"           # a lan server, a lan desktop, a lab desktop
PW = "Correct-Horse-9-" + random_password(8)
FAILED = 0
AUDIT = []


def audit(actor, action, detail, source="cli"):
    AUDIT.append((action, detail, source))


for mod in (m_add, m_set, m_remove, m_sync, m_group):
    mod.write_audit = audit


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-900:]}"), flush=True)


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd[:6]}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def on(box, script, stdin=None):
    res = sh(["docker", "exec", "-i", box, "bash", "-c", script], ok=False, input=stdin)
    return res.returncode, res.stdout + res.stderr


def samba_tool(*args):
    return sh(["docker", "exec", DC, "samba-tool", *args, "-s", "/data/etc/smb.conf"], ok=False)


def ldb(expr, *attrs):
    return sh(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", expr, *attrs],
              ok=False).stdout.replace("\n ", "")


def grant(*args):
    """fabricctl domain grant as root runs it: (exit status, what it printed)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_cmd.run_grant_command(V, list(args), DC)
    return code, out.getvalue()


def allowed(box, user, service):
    """sssd's access check in PAM's account phase (where the GPO access control runs): login is SeInteractiveLogonRight
    (the keyboard), sshd SeRemoteInteractiveLogonRight; the password checked first, as a sign-in does."""
    code, _ = on(box, f"pamtester {service} {user} authenticate acct_mgmt", stdin=PW + "\n")
    return code == 0


def within(cond, seconds=40):
    """A sign-in is checked again until the condition holds (sssd reads groups online, GPO files at a new version)."""
    end = time.time() + seconds
    while True:
        if cond():
            return True
        if time.time() > end:
            return False
        time.sleep(4)


def sudo_list(box, user):
    on(box, "systemctl restart sssd")              # its sudo rules fetched anew (else its refresh, 15 minutes)
    time.sleep(8)
    return on(box, f"sudo -l -U {user} 2>&1")[1]


def cleanup():
    sh(["docker", "rm", "-f", DC, WEB, *[f"gr-{b}" for b in (SRV, DSK, LAB)]], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


cleanup()
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
BASE = V["ad_base_dn"]
MACHINES = f"OU=machines,{BASE}"

print("--- a fresh install's grants (1.6.13.5) and the fallback (2.1.6.87)")
code, out = grant("list")
# covers: cli:domain.grant +
check("grant list: the four shipped grants and the two templates",
      code == 0 and all(f"{n}:" in out for n in ("server-administrators", "desktop-administrators",
                                                 "network-administrators", "desktops"))
      and "templates: helpdesk, limited-directory-administrator" in out, out)
check("all four reach nobody yet: no person and no machine in their groups",
      out.count("reaches nobody") == 4, out)
gplink = ldb("(distinguishedName=" + MACHINES + ")", "gPLink")
fallback = ldb("(displayName=fabric: access none)", "cn")
fb_guid = fallback.split("cn: ", 1)[1].split()[0] if "cn: " in fallback else "?"
check("the fallback GPO `fabric: access none` is linked at OU=machines, first in gPLink (the lowest precedence)",
      gplink.split("gPLink: ", 1)[-1].startswith(f"[LDAP://CN={fb_guid},"), gplink)

# people: sam (server-admins), dana (desktop-admins), alice and bob (lan), lara (lab); adam a Directory Administrator
lab = {"site": "lab", "dc": "dc-0002", "dc_type": "writable", "root": False, "parent": "lan", "password_policy": POLICY,
       "networks": [], "root_ca_pem": open(dc["root_ca"]).read(), "groups": [],
       "accounts": {f"fabric-{k}-dc-0002": random_password() for k in ("agent", "keycloak", "radius")}, "radius_gid": 610}
sh(["docker", "exec", "-i", DC, "python3", "/fabric/converge.py"], input=json.dumps(lab))
lab_v = {**V, "site_name": "lab", "dc_name": "dc-0002"}
lab_s = {**SECRETS, "ad_agent_password": lab["accounts"]["fabric-agent-dc-0002"]}
for uid, sv, sec in (("sam", V, SECRETS), ("dana", V, SECRETS), ("alice", V, SECRETS), ("bob", V, SECRETS),
                     ("adam", V, SECRETS), ("lara", lab_v, lab_s)):
    run_op(sv, sec, "create_person", {"uid": uid, "first": uid.title(), "last": "Test", "email": f"{uid}@lan.test",
                                      "password": "Ot-" + random_password(20), "gid": 5000, "home_base": "/home",
                                      "shell": "/bin/bash"}, DC)
for group, uid in (("server-admins", "sam"), ("desktop-admins", "dana"), ("directory-admins", "adam")):
    run_op(V, SECRETS, "add_group_member", {"group": group, "uid": uid}, DC)
samba_tool("group", "add", "ops", "--groupou=OU=groups")
samba_tool("group", "addmembers", "ops", "alice")
set_pw = "import sys\nsys.path.insert(0, '/fabric')\nfrom open_samdb import open_samdb\nsamdb, lp = open_samdb('/data/etc/smb.conf')\n" \
         "pw = sys.stdin.readline().strip()\nfor u in ('sam', 'dana', 'alice', 'bob', 'adam', 'lara'):\n" \
         "    samdb.setpassword('(sAMAccountName=%s)' % u, pw, force_change_at_next_login=False)\nprint('set')"
check("people in the domain: sam, dana, alice, bob, adam (lan), lara (lab)",
      "set" in sh(["docker", "exec", "-i", DC, "python3", "-c", set_pw], input=PW + "\n", ok=False).stdout)

# the members, joined as tests/samba/linux_join.py joins them
os.makedirs(os.path.join(W, "www", "certs"), exist_ok=True)
with open(os.path.join(W, "www", "certs", "root-ca.crt"), "w") as f:
    f.write(open(dc["root_ca"]).read())
sh(["docker", "run", "-d", "--name", WEB, "--network", NET, "--ip", WEB_IP, "-v", f"{W}/www:/srv:ro",
    "--entrypoint", "python3", "fabric/samba:test", "-m", "http.server", "80", "--directory", "/srv"])
fp = sh(["openssl", "x509", "-in", dc["root_ca"], "-noout", "-fingerprint", "-sha256"]).stdout.strip().split("=")[1]
with open(os.path.join(W, "join-linux.sh"), "w") as f:
    f.write(dc["env"].get_template("nginx/www/certs/join-linux.sh.j2").render(**V))
shim = open(os.path.join(REPO, "tests", "samba", "linux_join.py")).read()
shim = shim[shim.index('SHIM = r"""') + 11:]
with open(os.path.join(W, "systemctl"), "w") as f:
    f.write(shim[:shim.index('"""')])
os.chmod(os.path.join(W, "systemctl"), 0o755)


def member(name, flags):
    box = f"gr-{name}"
    sh(["docker", "run", "-d", "--name", box, "--hostname", name, "--network", NET,
        f"--add-host={V['hostname_dc']}:{IP}", f"--add-host={V['hostname_stepca']}:{WEB_IP}",
        f"--add-host={V['hostname_ntp']}:{IP}", "--cap-add", "DAC_READ_SEARCH",
        "-v", f"{W}/join-linux.sh:/root/join-linux.sh:ro", "-v", f"{W}/systemctl:/usr/local/sbin/systemctl:ro",
        "ubuntu:24.04", "sleep", "infinity"])
    on(box, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq pamtester sudo "
            "procps libcap2-bin openssh-server >/dev/null; mkdir -p /run/sshd")
    code, out = on(box, f"bash /root/join-linux.sh {fp} --user adam {flags}", stdin=PW + "\n")
    check(f"{name}: joined ({flags})", code == 0 and "joined" in out, out[-600:])
    return box


S, D, L = member(SRV, "--type server"), member(DSK, "--type desktop"), member(LAB, "--type desktop --site lab")
# the join put each in its type's and site's groups with the admin's ticket, outside fabric: the timer's sync picks
# that up; here it runs at once
done = m_sync.sync_grants(V, "test", "timer", DC)
check("sync after the joins: the servers' and desktops' sets made, each with its own GPO (fabric: access <n>)",
      any("GPO fabric: access 1 created" in c for c in done["changed"])
      and any("GPO fabric: access 2 created" in c for c in done["changed"]), done)
sets = {name: ldb(f"(sAMAccountName={name.upper()}$)", "memberOf") for name in (SRV, DSK, LAB)}
check("each machine is in exactly one set's group (access-<n>), the two desktops in the same one",
      all(s.count("CN=access-") == 1 for s in sets.values())
      and sets[DSK].split("CN=access-")[1].split(",")[0] == sets[LAB].split("CN=access-")[1].split(",")[0]
      and sets[SRV].split("CN=access-")[1].split(",")[0] != sets[DSK].split("CN=access-")[1].split(",")[0], sets)


def sid_of(name):
    return ldb(f"(sAMAccountName={name.upper()}$)", "objectSid").split("objectSid: ", 1)[-1].split()[0]


def named(n):
    """The machine SIDs a set's GPO gives Apply Group Policy to on their own (2.1.6.94)."""
    sddl = ldb(f"(displayName=fabric: access {n})", "nTSecurityDescriptor")
    return {s for s in (sid_of(m) for m in (SRV, DSK, LAB))
            if f"OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;{s})" in sddl}


SET = {m: sets[m].split("CN=access-")[1].split(",")[0] for m in (SRV, DSK, LAB)}
check("each set's GPO names exactly its own computers by SID too, beside its group (sssd 2.8, 2.1.6.94)",
      named(SET[SRV]) == {sid_of(SRV)} and named(SET[DSK]) == {sid_of(DSK), sid_of(LAB)},
      (SET, named(SET[SRV]), named(SET[DSK])))
time.sleep(6)

print("--- the shipped grants on real members (sssd)")
check(f"{SRV}: a server administrator (sam) signs in at the keyboard and remotely",
      within(lambda: allowed(S, "sam", "login") and allowed(S, "sam", "sshd")))
out = sudo_list(S, "sam")
check(f"{SRV}: sam has sudo of every command (the grant's rule)", "(root) ALL" in out, out)
check(f"negative: {SRV}: a person (alice) and the Directory Administrator (adam) may not sign in at a server",
      not allowed(S, "alice", "login") and not allowed(S, "alice", "sshd") and not allowed(S, "adam", "login"))
out = sudo_list(S, "alice")
check(f"negative: {SRV}: alice has no sudo", "not allowed" in out, out)
check(f"{DSK}: every person signs in at a desktop's keyboard (alice, bob, lara, sam)",
      all(allowed(D, u, "login") for u in ("alice", "bob", "lara", "sam")))
check(f"negative: {DSK}: nobody but the desktops' administrators signs in remotely (alice, sam refused; dana in)",
      not allowed(D, "alice", "sshd") and not allowed(D, "sam", "sshd") and allowed(D, "dana", "sshd"))
out = sudo_list(D, "sam")
check(f"negative: {DSK}: the server administrator has no sudo at a desktop", "not allowed" in out, out)
check(f"{DSK}: the desktops' administrator (dana) has sudo there", "(root) ALL" in sudo_list(D, "dana"))

print("--- the owner's case: a restricting grant (2.1.6.77)")
code, out = grant("add", "lan-desktops", "--restrict", "--who", "site-lan", "--where", "site-lan,machines-desktops",
                  "--signin", "keyboard")
check("grant add --restrict: lan's desktops kept to lan's people at the keyboard, compiled at once",
      code == 0 and "added" in out and AUDIT[-2][0] == "GRANT_ADD" and AUDIT[-1][0] == "GRANT_COMPILE", out)
check(f"{DSK}: lan's people still sign in there (alice, bob)",
      within(lambda: allowed(D, "alice", "login") and allowed(D, "bob", "login")))
check(f"negative: {DSK}: a person of another site (lara) is refused at lan's desktop",
      within(lambda: not allowed(D, "lara", "login")))
check(f"{LAB}: every other desktop stays open: lara and alice sign in at lab's",
      allowed(L, "lara", "login") and allowed(L, "alice", "login"))
moved = ldb(f"(sAMAccountName={DSK.upper()}$)", "memberOf").split("CN=access-")[1].split(",")[0]
check(f"negative: {DSK} moved to a set of its own: its SID entry is taken out of its old set's GPO, which names "
      f"{LAB} alone (2.1.6.94)", moved != SET[DSK] and named(SET[DSK]) == {sid_of(LAB)}
      and named(moved) == {sid_of(DSK)}, (moved, named(SET[DSK]), named(moved)))
code, out = grant("explain", "lara", DSK)
check("grant explain lara grdsk: the restricting grant named, no keyboard there",
      code == 0 and "lan-desktops (restrict)" in out and "keyboard no" in out, out)

print("--- two grants on one machine, and a membership change")
code, out = grant("add", "server-ops", "--who", "ops", "--where", "machines-servers", "--signin", "remote",
                  "--description", "ops sign in to the servers remotely")
check("grant add: ops (alice) sign in remotely to the servers", code == 0, out)
check(f"{SRV}: both grants hold on one machine: alice remotely, sam at the keyboard and remotely",
      within(lambda: allowed(S, "alice", "sshd")) and allowed(S, "sam", "login") and allowed(S, "sam", "sshd"))
check(f"negative: {SRV}: alice is still refused at the keyboard (server-ops gives remote only)",
      not allowed(S, "alice", "login"))
READ_INF = ("import glob\nfor f in glob.glob('/data/state/sysvol/*/Policies/*/Machine/Microsoft/Windows NT/SecEdit/"
            "GptTmpl.inf'):\n    print(open(f, 'rb').read().decode('utf-16'))\n")
inf = sh(["docker", "exec", "-i", DC, "python3", "-c", READ_INF], ok=False).stdout
check("the sets' GPOs name the grants' who groups, BUILTIN\\Administrators and local-admin; a set with local "
      "administrators puts them in Administrators (Group Membership)",
      "*S-1-5-32-544,local-admin" in inf and "__Memberof = *S-1-5-32-544" in inf, inf[-900:])
done = m_group.set_person_group(V, "test", "ops", "alice", False, secrets=SECRETS, container=DC)
check("fabric takes alice out of ops: the grants are compiled at once (GRANT_COMPILE)",
      done["changed"] and AUDIT[-1][0] == "GRANT_COMPILE", (done, AUDIT[-2:]))
t0 = time.time()
gone = within(lambda: not allowed(S, "alice", "sshd"), 60)
check(f"{SRV}: alice loses her remote sign-in at her next sign-in ({round(time.time() - t0)} s)", gone)
samba_tool("group", "addmembers", "server-admins", "bob")
code, out = grant("sync")
check("a change made with samba-tool (bob into server-admins) is compiled by `grant sync` (the timer's run)",
      code == 0 and "grant-server-administrators-who: 1 added" in out, out)
check(f"{SRV}: bob now signs in there", within(lambda: allowed(S, "bob", "login")))

print("--- the fallback: a machine no grant reaches (2.1.6.87)")
samba_tool("group", "removemembers", "machines-servers", f"{SRV.upper()}$")
code, out = grant("sync")
check(f"{SRV} taken out of machines-servers: it leaves its set", code == 0 and "taken out" in out, out)
check(f"negative: {SRV}: reached by no grant, it admits nobody from the domain (sam, bob refused)",
      within(lambda: not allowed(S, "sam", "login") and not allowed(S, "sam", "sshd") and not allowed(S, "bob", "login")))
code, out = on(S, "id -u root && su -s /bin/true root; echo rc=$?")
check(f"{SRV}: local accounts are untouched (root)", "rc=0" in out, out)
# the owner's override (2.1.6.88): grants_fallback_open leaves such a machine to the open default
V["grants_fallback_open"] = True
opened = m_sync.sync_grants(V, "test", "timer", DC)
# covers: setting:grants_fallback_open +
check(f"grants_fallback_open on: the fallback GPO removed, and {SRV}, reached by no grant, admits every domain person "
      "(sam, bob: sssd's default)", "fabric: access none" not in ldb("(objectClass=groupPolicyContainer)", "displayName")
      and within(lambda: allowed(S, "sam", "login") and allowed(S, "bob", "login")), opened)
V["grants_fallback_open"] = False
closed = m_sync.sync_grants(V, "test", "timer", DC)
# covers: setting:grants_fallback_open -
check(f"negative: grants_fallback_open off again: the fallback is back, first in gPLink, and {SRV} admits nobody",
      "fabric: access none" in ldb("(objectClass=groupPolicyContainer)", "displayName")
      and within(lambda: not allowed(S, "sam", "login") and not allowed(S, "bob", "login")), closed)
V.pop("grants_fallback_open")
samba_tool("group", "addmembers", "machines-servers", f"{SRV.upper()}$")
grant("sync")
check(f"{SRV} back in machines-servers: sam signs in again", within(lambda: allowed(S, "sam", "login")))

print("--- the computed groups: written by fabric alone (1.6.13.4)")
srv_set = ldb(f"(sAMAccountName={SRV.upper()}$)", "memberOf").split("CN=access-")[1].split(",")[0]
who_dn = f"CN=grant-server-administrators-who,OU=fabric,OU=groups,{BASE}"
try_write = f"""
import sys
sys.path.insert(0, "/fabric")
import ldb
from directory_op import connect
user, pw = sys.stdin.readline().split()
samdb, lp = connect("lan", user, pw)
for dn in ({who_dn!r}, "CN=access-{srv_set},OU=fabric,OU=groups,{BASE}"):
    m = ldb.Message(ldb.Dn(samdb, dn))
    m["member"] = ldb.MessageElement(["CN=alice,OU=people,{BASE}"], ldb.FLAG_MOD_ADD, "member")
    try:
        samdb.modify(m)
        print("WRITTEN", dn)
    except ldb.LdbError as e:
        print("REFUSED", e.args[0])
"""
out = sh(["docker", "exec", "-i", DC, "python3", "-c", try_write], input=f"adam {PW}\n", ok=False).stdout
check("negative: a Directory Administrator (adam) may not add anyone to a grant's or a set's computed group",
      out.count("REFUSED 50") == 2 and "WRITTEN" not in out, out)
out = sh(["docker", "exec", "-i", DC, "python3", "-c", try_write],
         input=f"fabric-agent-dc-0001 {SECRETS['ad_agent_password']}\n", ok=False).stdout
check("negative: nor may fabric's agent account (only the compile, inside the DC, writes them)",
      out.count("REFUSED 50") == 2 and "WRITTEN" not in out, out)
samba_tool("group", "addmembers", f"access-{srv_set}", "alice")
code, out = grant("sync")
check(f"a person put in access-{srv_set} as the system is taken out at the next compile (computers only)",
      f"group access-{srv_set}: 0 added, 1 taken out" in out
      and "alice" not in ldb(f"(sAMAccountName=access-{srv_set})", "member"), out)

print("--- refusals, with why")
for args, words in (
        (["add", "xx", "--who", "directory-admins", "--where", "machines-servers", "--signin", "remote"],
         "one of the tiers' groups"),
        (["add", "xx", "--who", "Domain Admins", "--where", "machines-servers", "--signin", "remote"],
         "one of the tiers' groups"),
        (["add", "xx", "--who", "ops", "--where", "dc-hosts", "--signin", "remote"], "hosts that run a domain controller"),
        (["add", "xx", "--who", "Domain Users", "--where", "machines-servers", "--sudo", "ALL"],
         "every command for every person"),
        (["add", "xx", "--who", "site-lan", "--where", "machines-servers", "--sudo", "ALL"],
         "every command for every person"),
        (["add", "xx", "--where", "machines-servers", "--signin", "remote"], "who: at least one group"),
        (["add", "xx", "--who", "ops", "--signin", "remote"], "where: at least one group"),
        (["add", "xx", "--who", "nosuch", "--where", "machines-servers", "--signin", "remote"], "no group nosuch"),
        (["add", "xx", "--who", "grant-desktops-who", "--where", "machines-servers", "--signin", "remote"],
         "computed groups"),
        (["add", "xx", "--who", "ops", "--where", "machines-servers"], "at least one right"),
        (["add", "Bad_Name", "--who", "ops", "--where", "machines-servers", "--signin", "remote"], "a grant's name"),
        (["add", "sync", "--who", "ops", "--where", "machines-servers", "--signin", "remote"], "a grant's name"),
        (["add", "xx", "--restrict", "--who", "ops", "--where", "machines-servers", "--sudo", "ALL"],
         "narrows sign-in or local administrator only"),
        (["add", "xx", "--who", "ops", "--where", "machines-servers", "--signin", "everywhere"],
         "is not one of keyboard, remote"),
        (["add", "xx", "--who", "ops", "--where", "machines-servers", "--sudo", "ALL,/bin/ls"], "ALL (every command) alone"),
        (["add", "xx", "--who", "ops", "--where", "machines-servers", "--local-admin", "maybe"], "yes or no"),
        (["add", "xx", "--who", "ops", "--where", "machines-servers", "--sudo", "/bin/ls", "--run-as", "alice"],
         "runs every command as root, always"),
        (["set", "server-ops", "--run-as", "root,postgres"], "runs every command as root, always"),
        (["add", "xx", "--template", "nosuch", "--who", "ops", "--where", "site-lan"], "no template nosuch"),
        (["add", "server-ops", "--who", "ops", "--where", "machines-servers", "--signin", "remote"], "exists"),
        (["set", "server-ops", "--restrict"], "kind (allow or restrict) is kept"),
        (["set", "server-ops", "--who", "none"], "who: at least one group"),
        (["set", "nosuch", "--signin", "remote"], "no grant nosuch"),
        (["remove", "nosuch"], "no grant nosuch"),
        (["show", "nosuch"], "no grant nosuch"),
        (["explain", "nobody"], "no person nobody"),
        (["explain", "alice", "nomachine"], "no machine nomachine")):
    n_audit = len(AUDIT)
    code, out = grant(*args)
    # covers: cli:domain.grant -
    check(f"refused: grant {' '.join(args)} ({words}), nothing audited", code == 1 and words in out
          and len(AUDIT) == n_audit, out)
code, out = grant("frobnicate")
check("negative: an unknown subcommand prints the usage (exit 2)", code == 2 and "usage: fabricctl domain grant" in out)
try:
    grant_request({**V, "ad_dc_type": "rodc"}, {"op": "compile"}, DC)
    err = ""
except ValidationError as e:
    err = str(e)
check("negative: changes are refused at a DC that is not the root's writable one, saying where to run them",
      "root site's writable DC" in err, err)
check("…while the timer's sync there changes nothing and says why", "skipped" in m_sync.sync_grants(
    {**V, "ad_dc_type": "rodc"}, "test", "timer", DC))

print("--- templates, explain, show, remove")
code, out = grant("add", "lan-helpdesk", "--template", "helpdesk", "--who", "ops", "--where", "site-lan")
code2, shown = grant("show", "lan-helpdesk")
check("grant add --template helpdesk: people rights (edit, reset, unlock) on lan's people; show names them and says "
      "fabric-agent checks those rights (D4); the Directory Administrator (adam) is never among them",
      code == 0 and code2 == 0 and "people: edit,reset,unlock" in shown and "alice" in shown
      and "fabric-agent on every call" in shown and "adam" not in shown.split("people managed:")[-1], shown)
code, out = grant("explain", "sam", SRV)
check("grant explain sam grsrv: server-administrators reaches him; keyboard, remote and sudo ALL there",
      code == 0 and "server-administrators (allow): reaches them" in out and "keyboard yes, remote yes" in out
      and "sudo ALL" in out, out)
code, out = grant("explain", "alice")
check("grant explain alice: the grants whose who she is missing say which group", code == 0
      and "server-administrators (allow): not: missing server-admins" in out, out)
code, out = grant("set", "server-ops", "--signin", "keyboard,remote")
check("grant set: server-ops now gives both sign-ins, audited GRANT_SET", code == 0 and "changed" in out
      and any(a[0] == "GRANT_SET" and "signin=keyboard,remote" in a[1] for a in AUDIT[-3:]), out)
code, out = grant("remove", "lan-helpdesk")
check("grant remove: lan-helpdesk gone with its computed groups, audited GRANT_REMOVE",
      code == 0 and "grant-lan-helpdesk" not in ldb("(objectClass=group)", "sAMAccountName")
      and any(a[0] == "GRANT_REMOVE" for a in AUDIT[-2:]), out)
sudo = ldb("(cn=grant-server-administrators)", "sudoUser", "sudoHost", "sudoCommand")
check("the server administrators' sudo rule names %grant-server-administrators-who, every command, the server's names",
      "sudoUser: %grant-server-administrators-who" in sudo and "sudoCommand: ALL" in sudo
      and f"sudoHost: {SRV}" in sudo, sudo)
code, out = grant("set", "server-ops", "--description", "ops on the servers", "--run-as", "root")
runas = [ln for ln in ldb("(&(objectClass=sudoRole)(cn=grant-*))", "sudoRunAsUser").splitlines()
         if ln.startswith("sudoRunAsUser")]
check("--run-as root is taken (what a grant's sudo always is, 2.1.6.90); every grant's rule runs as root alone",
      code == 0 and runas and set(runas) == {"sudoRunAsUser: root"}, (out, runas))

print("--- the agent's routes (1.6.13.7)")
m_get.load_vars = m_post.load_vars = lambda: V
import fabriclib.grants.grant_request as m_req  # noqa: E402
real_request = m_req.grant_request


def in_test_dc(v, request, container="samba"):
    return real_request(v, request, DC)


for name in ("fabriclib.grants.list_grants", "fabriclib.grants.show_grant", "fabriclib.grants.explain_grant",
             "fabriclib.grants.add_grant", "fabriclib.grants.set_grant", "fabriclib.grants.remove_grant",
             "fabriclib.grants.sync_grants"):
    sys.modules[name].grant_request = in_test_dc
got = m_get.get_route(["domain", "grants"])
# covers: agent:get.domain.grants +
check("GET /v1/domain/grants: the grants and templates", {"server-administrators", "desktops", "server-ops",
                                                           "lan-desktops"} <= {g["name"] for g in got["grants"]}
      and "helpdesk" in got["templates"], got)
got = m_get.get_route(["domain", "grants", "server-administrators"])
# covers: agent:get.domain.grants.* +
check("GET /v1/domain/grants/server-administrators: its people and machines by name",
      "sam" in got["who_people"] and SRV in got["where_machines"], got)
got = m_get.get_route(["domain", "grants", "explain", "sam"])
# covers: agent:get.domain.grants.explain.* +
check("GET /v1/domain/grants/explain/sam: the grants that reach him",
      any(g["name"] == "server-administrators" and g["reaches"] for g in got["grants"]), got)
got = m_get.get_route(["domain", "grants", "explain", "sam", SRV])
# covers: agent:get.domain.grants.explain.*.* +
check("GET /v1/domain/grants/explain/sam/grsrv: what he may do there",
      got["on_machine"]["remote"] and got["on_machine"]["sudo"] == ["ALL"], got)
done = m_post.post_grants(["domain", "grants"], "alice", {"name": "web-ops", "who": ["ops"], "where": ["site-lan"],
                                                          "people": ["reset"]})
# covers: agent:post.domain.grants +
check("POST /v1/domain/grants: added from the web, audited so", done["grant"]["people"] == ["reset"]
      and any(a[0] == "GRANT_ADD" and a[2] == "web" for a in AUDIT[-2:]), done)
done = m_post.post_grants(["domain", "grants", "web-ops"], "alice", {"people": ["reset", "unlock"]})
# covers: agent:post.domain.grants.* +
check("POST /v1/domain/grants/web-ops: changed", done["grant"]["people"] == ["reset", "unlock"], done)
done = m_post.post_grants(["domain", "grants", "sync"], "alice", {})
# covers: agent:post.domain.grants.sync +
check("POST /v1/domain/grants/sync: compiled now (nothing to change)", done == {"changed": []}, done)
done = m_post.post_grants(["domain", "grants", "web-ops", "delete"], "alice", {})
# covers: agent:post.domain.grants.*.delete +
check("POST /v1/domain/grants/web-ops/delete: removed", done["name"] == "web-ops", done)
for method, route, body, words in (
        ("post", ["domain", "grants"], {"name": "yy", "who": "ops", "where": ["site-lan"]}, "who must be a list"),
        ("post", ["domain", "grants"], {"name": "yy", "who": ["ops"], "where": ["site-lan"], "sudo": ["/bin/ls"],
                                        "run_as": "postgres"}, "runs every command as root, always"),
        ("post", ["domain", "grants"], {"name": "yy", "who": ["directory-admins"], "where": ["site-lan"],
                                        "people": ["reset"]}, "tiers' groups"),
        ("post", ["domain", "grants", "nosuch"], {"people": ["reset"]}, "no grant nosuch"),
        ("post", ["domain", "grants", "nosuch", "delete"], {}, "no grant nosuch"),
        ("post", ["domain", "grants", "x", "frob"], {}, "unknown operation"),
        ("get", ["domain", "grants", "nosuch"], None, "no grant nosuch"),
        ("get", ["domain", "grants", "explain", "nobody"], None, "no person nobody"),
        ("get", ["domain", "grants", "explain", "sam", "nomachine"], None, "no machine nomachine")):
    n_audit = len(AUDIT)
    try:
        m_post.post_grants(route, "alice", body) if method == "post" else m_get.get_route(route)
        err = ""
    except ValidationError as e:
        err = str(e)
    # covers: agent:post.domain.grants agent:post.domain.grants.* agent:post.domain.grants.*.delete -
    # covers: agent:get.domain.grants.* agent:get.domain.grants.explain.* agent:get.domain.grants.explain.*.* -
    check(f"{method.upper()} /v1/{'/'.join(route)} refused ({words}), nothing audited", words in err
          and len(AUDIT) == n_audit, err)
for name in ("fabriclib.grants.list_grants", "fabriclib.grants.sync_grants"):
    sys.modules[name].grant_request = lambda v, request, container="samba": real_request(v, request, "no-such-dc")
for call, covers in ((lambda: m_get.get_route(["domain", "grants"]), "get"),
                     (lambda: m_post.post_grants(["domain", "grants", "sync"], "alice", {}), "post")):
    try:
        call()
        err = ""
    except ValidationError as e:
        err = str(e)
    # covers: agent:get.domain.grants agent:post.domain.grants.sync -
    check(f"{covers.upper()} with the DC not running: refused, saying so", "not running" in err, err)
check("the routes' permissions: reading needs domain:read, every change groups:admin",
      {required_permission("GET", r) for r in (["domain", "grants"], ["domain", "grants", "x"],
                                               ["domain", "grants", "explain", "a"],
                                               ["domain", "grants", "explain", "a", "b"])} == {"domain:read"}
      and {required_permission("POST", r) for r in (["domain", "grants"], ["domain", "grants", "x"],
                                                    ["domain", "grants", "sync"],
                                                    ["domain", "grants", "x", "delete"])} == {"groups:admin"})

print("--- idempotent")
again = converge_domain(V, os.path.join(W, "dc", "federation.yaml"), SECRETS, container=DC)
check("a second convergence compiles nothing new", again == [], again)

if not os.environ.get("FABRIC_TEST_KEEP"):
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
