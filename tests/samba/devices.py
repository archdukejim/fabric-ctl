"""The `samba` suite, devices and device roles (manual 1.6.3.4, S3): fabric's own device and role functions — exactly
what fabric-agent calls — against a real DC, as the DC's agent account (fabric-agent-dc-0001). The DC runs under the product's container
name, `samba`, on a private test network; fabric's secrets and audit log are stood in for.
    sudo python3 tests/samba/devices.py
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import start_dc  # noqa: E402
import fabriclib.directory.add_device as m_add_device  # noqa: E402
import fabriclib.directory.add_role as m_add_role  # noqa: E402
import fabriclib.directory.common.read_directory as m_read  # noqa: E402
import fabriclib.directory.link_device_cert as m_link  # noqa: E402
import fabriclib.directory.remove_device as m_remove_device  # noqa: E402
import fabriclib.directory.remove_role as m_remove_role  # noqa: E402
import fabriclib.directory.update_device as m_update_device  # noqa: E402
import fabriclib.directory.update_role as m_update_role  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.ensure_default_device_roles import ensure_default_device_roles  # noqa: E402
from fabriclib.directory.list_devices import list_devices  # noqa: E402
from fabriclib.directory.list_roles import list_roles  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-devices")
NET, SUBNET, IP = "sambadev_net", "10.254.32.0/24", "10.254.32.10"
DC = "samba"            # the product's own name: fabric's functions use it
FAILED = 0
AUDIT = []


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def refused(fn, *args, match=""):
    """True only if fn(*args) raises a ValidationError whose message contains `match`."""
    try:
        fn(*args)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {match!r}: {exc}")
    return False


if subprocess.run(["docker", "inspect", "samba"], capture_output=True).returncode == 0 and \
        not subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", "samba"], capture_output=True,
                           text=True).stdout.strip().endswith(":test"):
    sys.exit("a container named samba that is not a test DC runs here: not touching it")
dc = start_dc(W, DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
for mod in (m_add_device, m_add_role, m_read, m_link, m_remove_device, m_remove_role, m_update_device, m_update_role):
    if hasattr(mod, "load_secrets"):
        mod.load_secrets = lambda: SECRETS
    if hasattr(mod, "write_audit"):
        mod.write_audit = lambda actor, event, detail, source: AUDIT.append(event)
add_device, add_role = m_add_device.add_device, m_add_role.add_role
update_device, update_role = m_update_device.update_device, m_update_role.update_role
remove_device, remove_role, link_device_cert = m_remove_device.remove_device, m_remove_role.remove_role, \
    m_link.link_device_cert


def dev(name):
    return next((d for d in list_devices(V) if d["name"] == name), None)


# ---- fabric's default roles, once, in the domain's OU=device-roles (1.6.13.2)
BASE = "DC=" + V["ad_domain"].replace(".", ",DC=")
marker = os.path.join(W, ".default-device-roles")
added = ensure_default_device_roles(V, SECRETS, marker)
check("fabric's six default device roles are made once, in the domain's OU=device-roles",
      len(added) == 6 and ensure_default_device_roles(V, SECRETS, marker) == []
      and all(r["dn"].endswith(f",OU=device-roles,{BASE}") for r in m_read.read_directory(V)["roles"]),
      added)
for name in added:                       # the rest of the test starts from no roles, as the 389-DS suite did
    remove_role(V, "alice", name)

# ---- roles
add_role(V, "alice", "trusted", {"permissions": ["network:eap-tls", "dns:dhcp-register", "pki:acme"],
                                 "vlan": "10", "priority": "10", "description": "Managed laptops"})
add_role(V, "alice", "iot", {"permissions": ["network:mab", "dns:dhcp-register"], "vlan": "30", "priority": "50"})
add_role(V, "alice", "guest", {})
roles = {r["name"]: r for r in list_roles(V)}
check("roles created (an empty role too), ordered by priority, in OU=device-roles",
      [r["name"] for r in list_roles(V)] == ["trusted", "iot", "guest"] and roles["trusted"]["vlan"] == 10
      and roles["guest"]["permissions"] == [] and roles["guest"]["priority"] == 100
      and m_read.read_directory(V)["roles"][0]["dn"].endswith(f",OU=device-roles,{BASE}"), roles)
check("unknown permission refused", refused(add_role, V, "alice", "x", {"permissions": ["root:everything"]},
                                            match="unknown"))
check("VLAN out of range refused", refused(add_role, V, "alice", "x", {"vlan": "5000"}, match="1 to 4094"))
check("bad role name refused", refused(add_role, V, "alice", "Bad Name", {}, match="role name"))
check("duplicate role refused", refused(add_role, V, "alice", "iot", {}, match="taken"))

# ---- devices (their owner a person in OU=people)
run_op(V, SECRETS, "create_person", {"uid": "jim", "first": "Jim", "last": "J", "email": "jim@lan.test",
                                     "password": "Pw-" + random_password(20), "gid": 5000, "home_base": "/home",
                                     "shell": "/bin/bash"}, DC)
add_device(V, "alice", "laptop1", {"type": "laptop", "macs": ["AA-BB-CC-00-11-22"], "owner": "jim",
                                   "roles": ["trusted"], "description": "Jim's laptop"})
d = dev("laptop1")
check("device added: MAC normalised, owner, roles, effective permissions and VLAN",
      d and d["macs"] == ["aa:bb:cc:00:11:22"] and d["owner"] == "jim" and d["roles"] == ["trusted"]
      and d["permissions"] == ["dns:dhcp-register", "network:eap-tls", "pki:acme"] and d["vlan"] == 10, d)
add_device(V, "alice", "printer1", {"type": "printer", "macs": ["aabb.cc00.1133"], "roles": ["iot", "trusted"]})
p = dev("printer1")
check("several roles: permissions add up, VLAN from the lowest priority number",
      "network:mab" in p["permissions"] and "network:eap-tls" in p["permissions"] and p["vlan"] == 10
      and p["vlan_from"] == "trusted", p)
check("a MAC can belong to one device only",
      refused(add_device, V, "alice", "clone", {"macs": ["aa:bb:cc:00:11:22"]}, match="already belongs"))
check("multicast MAC refused", refused(add_device, V, "alice", "x1", {"macs": ["01:00:5e:00:00:01"]},
                                       match="multicast"))
check("garbage MAC refused", refused(add_device, V, "alice", "x2", {"macs": ["nope"]}, match="not a MAC"))
check("bad device name refused", refused(add_device, V, "alice", "Bad_Name!", {}, match="device name"))
check("unknown role refused", refused(add_device, V, "alice", "x3", {"roles": ["directory-admins"]},
                                       match="no such role"))
check("unknown owner refused", refused(add_device, V, "alice", "x4", {"owner": "nobody"}, match="no such user"))
check("unknown type refused", refused(add_device, V, "alice", "x5", {"type": "toaster"}, match="type must be"))
check("duplicate device refused", refused(add_device, V, "alice", "laptop1", {}, match="already exists"))
check("refused adds left nothing behind", sorted(x["name"] for x in list_devices(V)) == ["laptop1", "printer1"])

update_device(V, "alice", "laptop1", {"type": "laptop", "macs": ["aa:bb:cc:00:11:22", "aa:bb:cc:00:11:23"],
                                      "owner": "jim", "roles": ["iot"], "enabled": False})
d = dev("laptop1")
check("update: roles swapped, second MAC, disabled -> no permissions, no VLAN",
      d["roles"] == ["iot"] and len(d["macs"]) == 2 and not d["enabled"] and d["permissions"] == []
      and d["vlan"] is None, d)
check("update: role membership really moved",
      "laptop1" not in {r["name"]: r for r in list_roles(V)}["trusted"]["members"])
update_role(V, "alice", "iot", {"permissions": ["network:mab"], "vlan": "", "priority": "50"})
check("role update: permissions and VLAN replaced", {r["name"]: r for r in list_roles(V)}["iot"]["vlan"] is None)

FP = ":".join(["AB"] * 32)
link_device_cert(V, "alice", "printer1", FP)
link_device_cert(V, "alice", "printer1", FP)
check("certificate fingerprint linked (idempotent)", dev("printer1")["certs"] == [FP], dev("printer1"))
link_device_cert(V, "alice", "printer1", FP, link=False)
check("certificate fingerprint unlinked", dev("printer1")["certs"] == [])
check("malformed fingerprint refused", refused(link_device_cert, V, "alice", "printer1", "abc", match="SHA-256"))

check("a role with devices cannot be removed", refused(remove_role, V, "alice", "iot", match="still has"))
remove_device(V, "alice", "laptop1")
remove_device(V, "alice", "printer1")
check("devices removed and taken out of their roles",
      list_devices(V) == [] and all(not r["members"] for r in list_roles(V)))
for r in ("trusted", "iot", "guest"):
    remove_role(V, "alice", r)
check("empty roles removed", list_roles(V) == [])
check("every change audited", all(a in AUDIT for a in ("ROLE_ADD", "DEVICE_ADD", "DEVICE_UPDATE", "DEVICE_CERT_LINK",
                                                       "DEVICE_REMOVE", "ROLE_REMOVE")), AUDIT)

# ---- machines (S7.4): pre-created, listed, disabled and enabled, removed — as the DC's agent
import fabriclib.directory.add_machine as m_add_machine  # noqa: E402
import fabriclib.directory.remove_machine as m_remove_machine  # noqa: E402
import fabriclib.directory.set_machine_enabled as m_set_machine  # noqa: E402
from fabriclib.directory.list_machines import list_machines  # noqa: E402
for mod in (m_add_machine, m_remove_machine, m_set_machine):
    mod.write_audit = lambda actor, event, detail, source: AUDIT.append(event)
m_add_machine.add_machine(V, "alice", "ws01", secrets=SECRETS, container=DC)
listed = list_machines(V, SECRETS, DC)
check("a pre-created machine with no type is listed, enabled, in OU=machines itself, in its site's group",
      [(m["name"], m["enabled"], m["type"], m["sites"]) for m in listed] == [("ws01", True, "", ["lan"])]
      and listed[0]["dn"] == f"CN=WS01,OU=machines,{BASE}", listed)
off = m_set_machine.set_machine_enabled(V, "alice", "ws01", False, secrets=SECRETS, container=DC)
again = m_set_machine.set_machine_enabled(V, "alice", "ws01", False, secrets=SECRETS, container=DC)
check("a machine is disabled (once: a second time changes nothing)",
      off["changed"] and not again["changed"] and not list_machines(V, SECRETS, DC)[0]["enabled"], (off, again))
m_set_machine.set_machine_enabled(V, "alice", "ws01", True, secrets=SECRETS, container=DC)
check("...and enabled again", list_machines(V, SECRETS, DC)[0]["enabled"])
check("refused: a machine name that is not one", refused(m_add_machine.add_machine, V, "alice", "Bad_Name",
                                                         match="machine name"))
m_remove_machine.remove_machine(V, "alice", "ws01", secrets=SECRETS, container=DC)
check("a machine is removed from the domain", list_machines(V, SECRETS, DC) == [])
try:
    m_remove_machine.remove_machine(V, "alice", "ws01", secrets=SECRETS, container=DC)
    gone = False
except ValidationError as e:
    gone = "no such" in str(e).lower() or "no machine" in str(e).lower()
check("refused: removing a machine the domain does not have", gone)

# ---- machines filed by type (manual 1.6.13.3, 2.1.6.72): OU=servers, OU=desktops, OU=network and their groups;
# add-machine --type; the Windows sort by operatingSystem
import functools  # noqa: E402
import io  # noqa: E402
import json as _json  # noqa: E402
import tempfile  # noqa: E402
from contextlib import redirect_stdout  # noqa: E402
import fabriclib.directory.sort_machines as m_sort  # noqa: E402
import fabriclib.samba.run_domain_command as m_domain  # noqa: E402


def domain(*argv):
    """fabricctl domain …, as the CLI routes it: its exit status and output."""
    out = io.StringIO()
    with redirect_stdout(out):
        code = m_domain.run_domain_command(V, list(argv))
    return code, out.getvalue()


def members_of(group):
    out = subprocess.run(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", f"(sAMAccountName={group})",
                          "member"], capture_output=True, text=True).stdout
    return {line.split("CN=", 1)[1].split(",", 1)[0].lower() for line in out.splitlines() if line.startswith("member:")}


def description(name):
    out = subprocess.run(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                          f"(sAMAccountName={name.upper()}$)", "description"], capture_output=True, text=True).stdout
    return next((line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("description:")), "")


def dn_of(name):
    """A computer account's DN line, or "" when there is none."""
    return subprocess.run(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                           f"(sAMAccountName={name.upper()}$)", "dn"], capture_output=True, text=True).stdout


def samba_tool(*argv):
    return subprocess.run(["docker", "exec", DC, "samba-tool", *argv, "-s", "/data/etc/smb.conf"],
                          capture_output=True, text=True)


m_domain.add_machine = functools.partial(m_add_machine.add_machine, secrets=SECRETS, container=DC)
_record = os.path.join(tempfile.mkdtemp(), "machines-sorted.json")
m_domain.sort_machines = functools.partial(m_sort.sort_machines, secrets=SECRETS, container=DC, record=_record)
m_sort.write_audit = lambda actor, event, detail, source: AUDIT.append(event)
code, out = domain("add-machine", "lx01", "--type", "server")
# covers: cli:domain.add-machine +
check("add-machine --type server: pre-created in OU=servers,OU=machines, in machines-servers and site-lan (1.6.13.3)",
      code == 0 and f"dn: CN=LX01,OU=servers,OU=machines,{BASE}" in dn_of("lx01")
      and "lx01" in members_of("machines-servers") and "lx01" in members_of("site-lan"), (code, out, dn_of("lx01")))
m_add_machine.add_machine(V, "alice", "desk01", secrets=SECRETS, container=DC, type="desktop")
code, out = domain("add-machine", "sw01", "--type", "network")
check("...--type desktop in OU=desktops and machines-desktops; --type network in OU=network and machines-network",
      f"OU=desktops,OU=machines,{BASE}" in dn_of("desk01") and "desk01" in members_of("machines-desktops")
      and code == 0 and f"OU=network,OU=machines,{BASE}" in dn_of("sw01") and "sw01" in members_of("machines-network"),
      (dn_of("desk01"), dn_of("sw01")))
listed = {m["name"]: m for m in list_machines(V, SECRETS, DC)}
check("the machines list shows each one's type and sites",
      (listed["lx01"]["type"], listed["desk01"]["type"], listed["sw01"]["type"]) == ("server", "desktop", "network")
      and listed["lx01"]["sites"] == ["lan"], listed)
code, out = domain("add-machine", "mac01", "--type", "linux")
# covers: cli:domain.add-machine -
check("refused: a type fabric has no OU for, saying which there are; nothing created",
      code == 1 and "type: one of server, desktop, network" in out and "MAC01" not in dn_of("mac01"), (code, out))
code, out = domain("add-machine", "lx02", "--os", "linux")
check("refused: the retired --os is a usage error (exit 2), nothing created",
      code == 2 and "usage:" in out and "LX02" not in dn_of("lx02"), (code, out))
code, out = domain("add-machine", "lx02", "--type")
check("refused: --type without a type is a usage error (exit 2)", code == 2 and "usage:" in out, (code, out))
check("refused: add_machine with an unknown type, before anything is made",
      refused(m_add_machine.add_machine, V, "alice", "lx04", "cli", SECRETS, DC, "printer", match="type:")
      and "LX04" not in dn_of("lx04"))
# a Windows machine that joined itself lands in OU=machines; a Linux one made there by hand is not Windows'
for name, osname in (("SELFJOIN", "Windows 11 Pro"), ("WINSRV", "Windows Server 2025 Standard"), ("PLAINBOX", "Ubuntu")):
    samba_tool("computer", "add", name, "--computerou=OU=machines")
    where = dn_of(name).split("dn: ", 1)[1].split("\n")[0].strip()
    subprocess.run(["docker", "exec", "-i", DC, "ldbmodify", "-H", "/data/private/sam.ldb"], capture_output=True,
                   text=True, input=f"dn: {where}\nchangetype: modify\nreplace: operatingSystem\n"
                                    f"operatingSystem: {osname}\n")
code, out = domain("sort-machines")
# covers: cli:domain.sort-machines +
check("sort-machines: by operatingSystem, a Windows desktop moves to OU=desktops and machines-desktops, a Windows "
      "Server to OU=servers and machines-servers, audited; a Linux one stays",
      code == 0 and "selfjoin" in out and f"CN=SELFJOIN,OU=desktops,OU=machines,{BASE}" in dn_of("selfjoin")
      and "selfjoin" in members_of("machines-desktops")
      and f"CN=WINSRV,OU=servers,OU=machines,{BASE}" in dn_of("winsrv") and "winsrv" in members_of("machines-servers")
      and f"CN=PLAINBOX,OU=machines,{BASE}" in dn_of("plainbox") and "MACHINE_SORT" in AUDIT,
      (code, out, dn_of("selfjoin"), dn_of("winsrv")))
samba_tool("computer", "move", "SELFJOIN", "OU=machines")
code, out = domain("sort-machines", "--scheduled")
check("...once: an admin's move back to OU=machines is kept (the record), the timer's run changes nothing",
      code == 0 and "nothing to sort" in out and "OU=desktops" not in dn_of("selfjoin")
      and len(_json.load(open(_record))["sorted"]) == 2, (code, out, dn_of("selfjoin")))
code, out = domain("sort-machines", "--now")
# covers: cli:domain.sort-machines -
check("refused: sort-machines with an option it does not take (usage, exit 2), nothing moved",
      code == 2 and "usage:" in out and "OU=desktops" not in dn_of("selfjoin"), (code, out))
check("machine changes audited", {"MACHINE_CREATE", "MACHINE_DISABLE", "MACHINE_ENABLE", "MACHINE_REMOVE"} <= set(AUDIT),
      AUDIT)


# ---- machines fabric manages (manual 1.6.11.6, 2.1.6.40): pre-created ones in fabric-managed unless --unmanaged;
# Linux machines an admin joined (into their type's OU and site group) adopted by the sort, once; an unmanaged join's
# mark respected
check("add-machine: a pre-created machine is managed by default (in fabric-managed)",
      "lx01" in members_of("fabric-managed"), members_of("fabric-managed"))
code, out = domain("add-machine", "lx03", "--type", "server", "--unmanaged")
check("add-machine --unmanaged: not in fabric-managed, marked unmanaged on its account",
      code == 0 and "lx03" not in members_of("fabric-managed")
      and description("lx03") == "fabric: unmanaged (manual 1.6.11.6)", (code, out, description("lx03")))
code, out = domain("add-machine", "--unmanaged")
check("refused: add-machine without a name (usage, exit 2)", code == 2 and "usage:" in out, (code, out))
# joined with an admin's password: join-linux.sh files them in their type's OU and their site's group; OTHERSITE is
# another site's, which this site's sort leaves alone
for name, group in (("ADMINJOIN", "site-lan"), ("PLAINJOIN", "site-lan"), ("OTHERSITE", "site-elsewhere")):
    samba_tool("computer", "add", name, "--computerou=OU=servers,OU=machines",
               *(["--description=fabric: unmanaged (manual 1.6.11.6)"] if name == "PLAINJOIN" else []))
    subprocess.run(["docker", "exec", "-i", DC, "ldbmodify", "-H", "/data/private/sam.ldb"], capture_output=True,
                   text=True, input=f"dn: CN={name},OU=servers,OU=machines,{BASE}\nchangetype: modify\n"
                                    "replace: operatingSystem\noperatingSystem: Ubuntu\n")
    if group == "site-lan":
        samba_tool("group", "addmembers", group, f"{name}$")
code, out = domain("sort-machines")
check("sort-machines: an admin-joined Linux machine of the site becomes managed (fabric-managed), audited; one whose "
      "join said unmanaged does not; another site's is left alone",
      code == 0 and "adminjoin" in out and "adminjoin" in members_of("fabric-managed")
      and "plainjoin" not in members_of("fabric-managed") and "othersite" not in members_of("fabric-managed")
      and "MACHINE_ADOPT" in AUDIT, (code, out))
samba_tool("group", "removemembers", "fabric-managed", "ADMINJOIN$")
code, out = domain("sort-machines", "--scheduled")
check("...once: a machine an admin took out of fabric-managed stays out",
      code == 0 and "adminjoin" not in members_of("fabric-managed")
      and len(_json.load(open(_record))["adopted"]) == 1, (code, out))

# ---- the site's fabric host (manual 1.6.11.11, 2.1.6.49, 1.6.13.6): OU=fabric-hosts, placed once, managed, in
# dc-hosts and no site's group
import fabriclib.directory.place_fabric_host as m_place  # noqa: E402

m_place.write_audit = lambda actor, event, detail, source: AUDIT.append(event)
ou = subprocess.run(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb",
                     "(&(objectClass=organizationalUnit)(ou=fabric-hosts))", "dn"], capture_output=True, text=True)
check("the domain's OU=fabric-hosts exists beside OU=machines (made by the convergence)",
      f"dn: OU=fabric-hosts,{BASE}" in ou.stdout, ou.stdout + ou.stderr)
m_add_machine.add_machine(V, "setup", "fabhost", secrets=SECRETS, container=DC, managed=False, in_site=False)
placed = m_place.place_fabric_host(V, "setup", "FABHOST", secrets=SECRETS, container=DC)
check("place_fabric_host: the host's account (made in OU=machines, unmanaged, in no site's group) moved into "
      "OU=fabric-hosts, made a member of fabric-managed and dc-hosts, marked as a fabric host, audited",
      placed["moved"] and placed["joined"] == ["fabric-managed", "dc-hosts"]
      and f"CN=FABHOST,OU=fabric-hosts,{BASE}" in dn_of("fabhost")
      and "fabhost" in members_of("fabric-managed") and "fabhost" in members_of("dc-hosts")
      and "fabhost" not in members_of("site-lan") and description("fabhost").startswith("fabric: a fabric host")
      and "MACHINE_PLACE" in AUDIT, (placed, dn_of("fabhost"), description("fabhost")))
AUDIT.clear()
again = m_place.place_fabric_host(V, "setup", "fabhost", secrets=SECRETS, container=DC)
check("...a second time changes nothing and audits nothing", not again["moved"] and not again["joined"]
      and "MACHINE_PLACE" not in AUDIT, again)
check("the fabric host is one of the domain's machines: listed (Directory → Machines), found to disable",
      "fabhost" in [m["name"] for m in list_machines(V, SECRETS, DC)]
      and m_set_machine.set_machine_enabled(V, "alice", "fabhost", True, secrets=SECRETS, container=DC) is not None)
check("refused: placing a machine the domain does not have (nothing made)",
      refused(m_place.place_fabric_host, V, "setup", "nosuchhost", "setup", SECRETS, DC, match="no such")
      and "NOSUCHHOST" not in dn_of("nosuchhost"))
m_remove_machine.remove_machine(V, "setup", "fabhost", secrets=SECRETS, container=DC)
check("the fabric host's account is removed as other machines are (the undo of setup's member step)",
      "FABHOST" not in dn_of("fabhost"), dn_of("fabhost"))

subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
subprocess.run(["docker", "network", "rm", NET], capture_output=True)
sys.exit(1 if FAILED else 0)
