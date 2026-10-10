"""The `samba` suite, sites joining the root's domain (manual 1.9.8.4, 1.6.5.22 S8.1-S8.2): a root DC (with BIND
serving the AD zone), and a site DC, writable, then another read-only, joining it the way a site's setup does — the
root prepares each site in its domain (prepare_site: OU, groups, service accounts, ACLs, id block, networks, a join
account that expires), the site's deploy_samba writes the join credentials and its compose file joins instead of
provisioning, its convergence then changes only what is the site's (an RODC's only what is local), and finish_join
deletes the join account. Proves: both join into their AD sites; the domain and the site's objects replicate both
ways; the site's agent works at its own DC with the id block the root gave; the join account is gone; an RODC's
convergence writes nothing and refuses writes; the password policy stays the root's; SYSVOL and NETLOGON are not
advertised yet reachable by path, and every DC copies the GPO folders it does not own from their owners over SMB
(S8.4), refusing a GPO whose object moved away from its owner's files.
    sudo python3 tests/samba/site_join.py
"""
import os
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_bind import start_bind  # noqa: E402
from start_dc import POLICY, dc_tls, run_dc, start_dc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.federation.next_id_block import next_id_block  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.samba.deploy_samba import deploy_samba  # noqa: E402
from fabriclib.samba.finish_join import finish_join  # noqa: E402
from fabriclib.samba.prepare_site import prepare_site  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-site-join")
NET, SUBNET = "sitejoin_net", "10.254.35.0/24"
ROOT, ROOT_IP, ROOT_BIND = "sjroot", "10.254.35.10", "sjroot-bind"
# site: (container, address, DC type, LAN, parent); lab2 is nested under lab, which prepares it in its own DC
SITES = {"lab": ("sjlab", "10.254.35.20", "writable", "10.77.0.0/24", "lan"),
         "edge": ("sjedge", "10.254.35.30", "rodc", "10.78.0.0/24", "lan"),
         "lab2": ("sjlab2", "10.254.35.40", "writable", "10.79.0.0/24", "lab")}
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def sh(cmd, ok=False, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd[:6]}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def search(container, expression, attrs, base=None):
    """An ldbsearch of a DC's own database: the output text."""
    args = ["docker", "exec", container, "ldbsearch", "-H", "/data/private/sam.ldb", expression, *attrs]
    if base:
        args[4:4] = ["-b", base]
    return sh(args).stdout


def until(pred, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(5)
    return False


def cleanup():
    sh(["docker", "rm", "-f", ROOT, ROOT_BIND, *[c for c, _, _, _, _ in SITES.values()],
        *[f"{c}-bind" for c, _, _, _, _ in SITES.values()]])
    sh(["docker", "network", "rm", NET])


cleanup()
root = start_dc(os.path.join(W, "root"), ROOT, NET, SUBNET, ROOT_IP)
RV, RS, ENV = root["v"], root["secrets"], root["env"]
start_bind(RV, ENV, ROOT, ROOT_BIND)
BASE = sh(["docker", "exec", ROOT, "ldbsearch", "-H", "/data/private/sam.ldb", "-s", "base", "-b", "", "defaultNamingContext"]
          ).stdout.split("defaultNamingContext: ")[1].split()[0]
check("the root's DC is up and BIND answers the AD zone", bool(BASE))

registry = {"sites": {}}
joined = {}
PARENT_OU = {"lan": "OU=lan,OU=sites"}
for site, (container, ip, dc_type, cidr, parent) in SITES.items():
    if parent != "lan" and parent not in joined:
        continue
    # ---- at the parent (the root, or a site with a writable DC): what accept_join does before it answers
    if parent == "lan":
        pv, pcontainer, pip, pname, reg = RV, ROOT, ROOT_IP, RV["hostname_dc"], registry
    else:       # a nested parent knows only its own registry: the block must come from the domain (AD)
        pcontainer, pv, _ = joined[parent]
        pip, pname, reg = SITES[parent][1], pv["hostname_dc"], {"sites": {}}
    block = next_id_block(pv, reg, container=pcontainer)
    accounts = {kind: random_password() for kind in ("agent", "keycloak", "radius")}
    join_pw = random_password()
    done = prepare_site(pv, site, [{"name": "lan", "cidr": cidr}], block, accounts, join_pw, container=pcontainer)
    registry["sites"][site] = {"id_range": block, "dc": dc_type}
    expires = search(pcontainer, f"(sAMAccountName=fabric-join-{site})", ["accountExpires", "memberOf"])
    check(f"{site}: its parent {parent} prepares the site in its own DC — its OU, groups, service accounts, id block, "
          "and a join account that expires", f"group {site}-admins created" in " ".join(done)
          and "Domain Admins" in expires and "accountExpires: 9223372036854775807" not in expires
          and "accountExpires:" in expires, done)
    PARENT_OU[site] = f"OU={site},{PARENT_OU[parent]}"
    # ---- at the site: what its setup does with the answer
    work = os.path.join(W, site)
    sh(["rm", "-rf", work])
    v = yaml.safe_load(ENV.get_template("vars.yaml.j2").render(
        domain=f"{site}.lan.j-j.family", hostname=f"dc-{site}", host_ip=ip, lan_cidr=cidr,
        lan_gateway=cidr.rsplit(".", 1)[0] + ".1", site_name=site, ad_domain=RV["ad_domain"],
        ad_password_policy=POLICY, deploy_base_dir=work, ad_ntp_signd_dir=os.path.join(work, "ntp_signd"),
        ad_dc_type=dc_type, ad_join_server=pip, ad_join_server_name=pname, posix_id_range=block,
        ad_site_ou=PARENT_OU[site], ad_org_ou="OU=organisation,OU=lan,OU=sites"))
    secrets = {"ad_admin_password": random_password(), **{f"ad_{k}_password": p for k, p in accounts.items()},
               "ad_join": {"user": f"fabric-join-{site}", "password": join_pw}}
    os.makedirs(os.path.join(work, "stepca", "data", "certs"))
    sh(["cp", root["root_ca"], os.path.join(work, "stepca", "data", "certs", "root_ca.crt")], ok=True)
    deploy_samba(v, secrets, ENV)
    # covers: setting:ad_join_server +
    check(f"{site}: deploy writes the join credentials (0600) and points the DC at its parent's DNS until it joined",
          oct(os.stat(os.path.join(work, "samba", "secrets", "join.auth")).st_mode & 0o777) == "0o600"
          and f"nameserver {pip}" in open(os.path.join(work, "samba", "resolv.conf")).read())
    dc_tls(v, root["root_ca"], root["root_key"])
    try:
        run_dc(v, container, NET, ENV, tries=120)
        up = True
    except RuntimeError as e:
        up = False
        print(f"    {e}")
    logs = sh(["docker", "logs", container]).stdout
    # covers: setting:ad_dc_type +
    check(f"{site}: its DC joins the domain as {'a read-only' if dc_type == 'rodc' else 'a writable'} DC "
          f"(not a domain of its own)", up and "joined" in logs and "provisioning" not in logs, logs[-800:])
    if not up:
        continue
    server = search(pcontainer, f"(&(objectClass=server)(cn=dc-{site}))", ["distinguishedName"],
                    base=f"CN=Sites,CN=Configuration,{BASE}")
    check(f"{site}: the DC sits in its own AD site", f"CN=Servers,CN={site},CN=Sites" in server, server)
    fed = os.path.join(work, "federation.yaml")
    with open(fed, "w") as f:
        yaml.safe_dump({"sites": {}, "upstream": {"site_name": parent}}, f)
    try:
        changed = converge_domain(v, fed, secrets, container=container)
        again = converge_domain(v, fed, secrets, container=container)
        conv_err = ""
    except ValidationError as e:
        changed, again, conv_err = [], ["error"], str(e)
    check(f"{site}: the site's convergence runs at its DC, a second time changes nothing, and never touches the "
          f"domain's policy", not conv_err and again == [] and not any("password policy" in c for c in changed),
          conv_err or (changed, again))
    note = finish_join(v, secrets, container)
    check(f"{site}: the join account is deleted at its parent's DC once joined",
          "deleted" in note and until(lambda: "sAMAccountName" not in search(
              pcontainer, f"(sAMAccountName=fabric-join-{site})", ["sAMAccountName"]), 60), note)
    joined[site] = (container, v, secrets)
    if any(p == site for *_, p in SITES.values()):    # a parent: its own BIND answers the AD zone, as on an install
        try:
            start_bind(v, ENV, container, f"{container}-bind")
        except RuntimeError as e:
            check(f"{site}: its BIND answers the AD zone (the sites below join through it)", False, e)

# ---- a writable site: its own writes, both directions of replication, its id block
if "lab" in joined:
    container, v, secrets = joined["lab"]
    info = run_op(v, secrets, "site_info", container=container)
    # covers: setting:posix_id_range +
    check("lab: its agent signs in at its own DC and reads its site's id block (the root's second block)",
          info["id_range"] == registry["sites"]["lab"]["id_range"], info)
    made = run_op(v, secrets, "create_person", {"uid": "labby", "first": "Lab", "last": "By", "email": "labby@lab.test",
                                                "password": "Ot-" + random_password(20), "gid": 5000,
                                                "home_base": "/home", "shell": "/bin/bash"}, container)
    first, last = (int(x) for x in registry["sites"]["lab"]["id_range"].split("-"))
    check("lab: a person made at the site takes a uid from the site's own block", first <= made["uidNumber"] <= last,
          made)
    # AD's KCC builds the return path from the site link within its 5-minute round
    check("lab -> root: the person reaches the root's DC (AD replication over the site link)",
          until(lambda: "sAMAccountName: labby" in search(ROOT, "(sAMAccountName=labby)", ["sAMAccountName"]), 900))
    run_op(RV, RS, "create_person", {"uid": "rooty", "first": "Root", "last": "Y", "email": "rooty@lan.test",
                                     "password": "Ot-" + random_password(20), "gid": 5000, "home_base": "/home",
                                     "shell": "/bin/bash"}, ROOT)
    check("root -> lab: a person made at the root reaches the site's DC",
          until(lambda: "sAMAccountName: rooty" in search(container, "(sAMAccountName=rooty)", ["sAMAccountName"])))

# ---- a site nested under a site that is not the root (2.1.6.20, manual 1.9.8.14)
if "lab2" in joined:
    container, v, secrets = joined["lab2"]
    # covers: setting:ad_site_ou +
    check("lab2: its OU sits in lab's, which sits in the root's (as the root sees it, once replicated)",
          until(lambda: f"OU=lab2,OU=lab,OU=lan,OU=sites,{BASE}" in search(
              ROOT, "(&(objectClass=fabricSiteInfo)(ou=lab2))", ["dn"]), 900))
    others = [registry["sites"][s]["id_range"] for s in ("lab", "edge")] + [RV.get("posix_id_range") or "5001-105000"]
    mine = registry["sites"]["lab2"]["id_range"]
    check("lab2: its id block, handed out by lab with no registry of the others, comes after every block in the domain",
          int(mine.split("-")[0]) > max(int(b.split("-")[1]) for b in others), (mine, others))

    def make_deepy():
        try:
            run_op(v, secrets, "create_person", {"uid": "deepy", "first": "Deep", "last": "Y", "email": "d@lab2.test",
                                                 "password": "Ot-" + random_password(20), "gid": 5000,
                                                 "home_base": "/home", "shell": "/bin/bash"}, container)
            return True
        except ValidationError:
            return False     # a new DC makes accounts only once the root's RID master gave it a pool (2.3.6.1.23)

    check("lab2: its agent creates a person at its own DC (once the DC has its RID pool)", until(make_deepy, 600))
    check("lab2 -> lab -> root: a person made two levels down reaches the root's DC",
          until(lambda: "sAMAccountName: deepy" in search(ROOT, "(sAMAccountName=deepy)", ["sAMAccountName"]), 900))
    lab_c, lab_v, lab_s = joined["lab"]

    def lab_resets_deepy():
        try:
            run_op(lab_v, lab_s, "reset_password", {"uid": "deepy", "password": "Rs-" + random_password(20)}, lab_c)
            return True
        except ValidationError:
            return False     # not replicated to lab's DC yet, or refused

    check("lab's agent resets a person of lab2, the site nested below it (inherited rights, 2.1.6.20)",
          until(lab_resets_deepy, 600))

    # ---- re-parenting (manual 1.9.8.14): lab2 moves from lab to the root, as the root's accept_join does for a
    # site already in the domain (no join account; its OU moves with everything in it)
    nets2 = [{"name": "lan", "cidr": SITES["lab2"][3]}]
    try:
        prepare_site({**RV, "site_name": "lab2"}, "lab", nets2, registry["sites"]["lab"]["id_range"], {}, None,
                     container=ROOT)
        loop = ""
    except ValidationError as e:
        loop = str(e)
    check("refused: moving lab under lab2, which sits below it", "sits below" in loop, loop)
    sid_before = search(ROOT, "(sAMAccountName=deepy)", ["objectSid"]).split("objectSid: ")[-1].split()[0]
    moved = prepare_site(RV, "lab2", nets2, registry["sites"]["lab2"]["id_range"],
                         {k: random_password() for k in ("agent", "keycloak", "radius")}, None, container=ROOT)
    deepy = search(ROOT, "(sAMAccountName=deepy)", ["objectSid"])
    check("the root moves lab2's OU under its own, with its people, who keep their SIDs",
          any("site lab2 moved" in c for c in moved) and f"OU=people,OU=lab2,OU=lan,OU=sites,{BASE}" in deepy
          and f"objectSid: {sid_before}" in deepy, (moved, deepy))
    links = search(ROOT, "(objectClass=siteLink)", ["cn"], base=f"CN=Sites,CN=Configuration,{BASE}")
    check("lab2's site link now goes to the root, the one to lab is gone",
          "cn: lan-lab2" in links and "cn: lab-lab2" not in links, links)
    check("no join account was made for a site already in the domain",
          "sAMAccountName" not in search(ROOT, "(sAMAccountName=fabric-join-lab2)", ["sAMAccountName"]))
    check("lab2's agent still signs in at its own DC with its own password (the move kept the service accounts)",
          until(lambda: run_op(v, secrets, "site_info", container=container)["dn"].startswith("OU=lab2,OU=lan,"), 600))
    with open(os.path.join(W, "lab2", "federation.yaml"), "w") as f:      # what reparent writes: the new parent
        yaml.safe_dump({"sites": {}, "upstream": {"site_name": "lan"}}, f)
    try:
        after = converge_domain(v, os.path.join(W, "lab2", "federation.yaml"), secrets, container=container)
    except ValidationError as e:
        after = [f"error: {e}"]
    check("lab2's own convergence after the move rewrites its log-on GPO for its new parents (its own DC owns it)",
          any("log-on rights: version" in c for c in after) and not any(c.startswith("error") for c in after), after)

    def lab_refused_on_deepy():
        try:
            run_op(lab_v, lab_s, "reset_password", {"uid": "deepy", "password": "Rs-" + random_password(20)}, lab_c)
            return False
        except ValidationError:
            return True      # lab no longer sits above lab2 (once the move reached lab's DC)

    check("lab's agent no longer reaches lab2's people", until(lab_refused_on_deepy, 600))

# ---- a read-only site: the domain to read, nothing to write
if "edge" in joined:
    container, v, secrets = joined["edge"]
    check("edge: the domain replicated to the RODC (the site's OU, nested in its parent's, and the root's people)",
          "OU=edge,OU=lan,OU=sites" in search(container, "(ou=edge)", ["dn"]))
    try:
        run_op(v, secrets, "create_person", {"uid": "edgy", "first": "E", "last": "D", "email": "e@edge.test",
                                             "password": "Ot-" + random_password(20), "gid": 5000,
                                             "home_base": "/home", "shell": "/bin/bash"}, container)
        wrote = True
    except ValidationError:
        wrote = False
    check("edge: writes at the RODC are refused (they belong to a writable DC)", not wrote)

# ---- Group Policy between sites (S8.4, manual 1.9.8.15): hidden shares, folders copied from their owners over SMB
EXEC = ["docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "KRB5_CONFIG=/data/private/krb5.conf"]
GPO_STATE = ("import os,sys; sys.path.insert(0,'/fabric'); import ldb; from open_samdb import open_samdb; "
             "s,lp=open_samdb('/data/etc/smb.conf'); r=lp.get('realm').lower(); p=os.path.join(lp.get('path','sysvol'),r,'Policies'); "
             "[print(str(g['cn'][0]).upper(), str(g.get('versionNumber',['0'])[0]), "
             "(open(os.path.join(p,str(g['cn'][0]),'GPT.INI')).read().split('Version=')[-1].strip() "
             "if os.path.exists(os.path.join(p,str(g['cn'][0]),'GPT.INI')) else '-')) "
             "for g in s.search(base='CN=Policies,CN=System,'+str(s.domain_dn()), scope=ldb.SCOPE_ONELEVEL, "
             "expression='(objectClass=groupPolicyContainer)', attrs=['cn','versionNumber'])]")


def pull(container):
    return sh([*EXEC, container, "python3", "/fabric/pull_sysvol.py"]).stdout


def gpo_state(container):
    """{guid: (object version, folder version or '-')} at one DC."""
    out = sh([*EXEC, container, "python3", "-c", GPO_STATE]).stdout.split("\n")
    return {f[0]: (f[1], f[2]) for f in (line.split() for line in out) if len(f) == 3}


def in_step(container):
    return all(obj == files for obj, files in gpo_state(container).values())


hidden = all(sh(["docker", "exec", ROOT, "testparm", "-s", "--section-name", share, "--parameter-name", "browseable",
                 "/data/etc/smb.conf"]).stdout.strip() == "No" for share in ("sysvol", "netlogon"))
check("SYSVOL and NETLOGON are not browseable, and mDNS is off (never advertised: 2.1.6.16)",
      hidden and "multicast dns register = no" in sh(["docker", "exec", ROOT, "cat", "/data/etc/smb.conf"]).stdout)
listing = sh([*EXEC, ROOT, "smbclient", "-s", "/data/etc/smb.conf", "-P", "-L", f"//{RV['hostname_dc']}"])
check("...so a share list leaves them out", listing.returncode == 0 and "Sharename" in listing.stdout
      and "sysvol" not in listing.stdout.lower() and "netlogon" not in listing.stdout.lower(),
      listing.stdout + listing.stderr)
reach = sh([*EXEC, ROOT, "smbclient", "-s", "/data/etc/smb.conf", "-P",
            f"//{RV['hostname_dc']}/sysvol", "-c", "ls"])
check("...yet SYSVOL is still reached by its path (as Windows reads policy)",
      reach.returncode == 0 and RV["ad_domain"].lower() in reach.stdout.lower(), reach.stdout + reach.stderr)
dcs = [ROOT, *[joined[s][0] for s in ("lab", "edge", "lab2") if s in joined]]
copied = {c: "" for c in dcs}


def all_in_step():
    for c in dcs:
        copied[c] += pull(c)
    return all(in_step(c) for c in dcs)


def copies(c):
    """What a DC copied: by the test's own pulls and by its entrypoint's 5-minute round (in its log)."""
    return copied[c] + sh(["docker", "logs", c]).stdout


check("every DC holds every GPO's folder at its object's version (copied from each owner over SMB, as the DC's "
      "machine account)", until(all_in_step, 600), {c: gpo_state(c) for c in dcs})
if "lab" in joined:
    check("the root copies the writable site's own GPOs from the site's DC", "copied from dc-lab" in copies(ROOT),
          copied[ROOT])
if "edge" in joined:
    check("the RODC copies what it does not hold from their owners, its own site's from the root (who wrote them)",
          "copied from dc1" in copies(SITES["edge"][0]).lower(), copied[SITES["edge"][0]])
    # a change away from the owner: the object's version moves, the owner's files do not -> refused, not copied
    if "lab" in joined:
        lab_gpo = search(ROOT, "(&(objectClass=groupPolicyContainer)(displayName=*lab*))", ["cn", "versionNumber"])
        guid = lab_gpo.split("cn: ")[1].split()[0]
        ver = int(lab_gpo.split("versionNumber: ")[1].split()[0])
        dn = f"CN={guid},CN=Policies,CN=System,{BASE}"
        sh(["docker", "exec", "-i", ROOT, "ldbmodify", "-H", "/data/private/sam.ldb"],
           input=f"dn: {dn}\nchangetype: modify\nreplace: versionNumber\nversionNumber: {ver + 1}\n")
        refused = ""

        def seen_refusal():
            global refused
            refused += pull(SITES["edge"][0])
            return f"{guid}: not copied" in refused

        check("a GPO whose object changed away from its owner is reported and never copied half",
              until(seen_refusal, 300) and gpo_state(SITES["edge"][0]).get(guid.upper(), ("", ""))[1] == str(ver),
              refused)

# ---- the Federation tab's view of it (S8.5): AD's own replication state and conflict objects, at the root
from fabriclib.samba.list_conflicts import list_conflicts  # noqa: E402
from fabriclib.samba.replication_status import replication_status  # noqa: E402
def partners(container):
    rep = replication_status(container)
    return rep, {n["from"].split(",")[1].upper() for n in rep["neighbours"] if "," in n["from"] and not n["failures"]}


rep, got = partners(ROOT)
check("the root's replication status: the writable site's DC is an inbound neighbour, every partition succeeding "
      "(an RODC only pulls)", not rep["error"] and "CN=DC-LAB" in got and "CN=DC-EDGE" not in got
      and all(n["last_success"] for n in rep["neighbours"]), rep)
rep, got = partners(SITES["edge"][0])
check("the RODC's replication status: it pulls from the root", not rep["error"] and "CN=DC1" in got, rep)
check("no conflict objects in the domain", list_conflicts(ROOT) == [], list_conflicts(ROOT))

if not os.environ.get("FABRIC_TEST_KEEP"):
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
