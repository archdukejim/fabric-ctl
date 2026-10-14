#!/usr/bin/env python3
"""Remote access by machine class (decision 2.1.7.14 as revised 2026-10-13; 2.1.6.36's revision; manual 1.6.11.5,
1.6.11.9.13), container-free: the class GPOs the DC writes (and status shows the same), so a member of
`<site>-server-remote-users` holds the remote log-on right — RDP on Windows, SSH through SSSD's GPO mapping on Linux —
on the site's servers and not its desktops, a member of `<site>-desktop-remote-users` the reverse, and central IT (the
organisation's fabric-admins, the root's admins, nested in both) on both; the layered default nesting; the machines
placed by class (pre-created, sorted, adopted, moved by `fabricctl domain machine class`, the fabric host refused); the
signing side's grants; the command line. The DC itself: tests/samba/logon.py, linux_join.py, hostgroups.py (written,
not run).

    python3 tests/samba/class_logon_test.py
"""
import contextlib
import io
import os
import re
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "src", "containers", "samba")]

# ---------------------------------------------------------------- a stand-in for Samba's ldb module (not installed)
ldb = types.ModuleType("ldb")
ldb.SCOPE_BASE, ldb.SCOPE_ONELEVEL, ldb.SCOPE_SUBTREE = 0, 1, 2
ldb.ERR_NO_SUCH_OBJECT, ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS = 32, 50
ldb.FLAG_MOD_REPLACE, ldb.FLAG_MOD_DELETE = 2, 3


class LdbError(Exception):
    pass


ldb.LdbError = LdbError
ldb.binary_encode = lambda s: s


class Message(dict):
    def __init__(self, dn=None):
        super().__init__()
        self.dn = dn

    def get(self, name, default=None, idx=None):
        value = super().get(name, default)
        if idx is not None:
            return value[idx] if value else default
        return value

    @staticmethod
    def from_dict(samdb, d, flag):
        m = Message(d["dn"])
        m.update({k: v for k, v in d.items() if k != "dn"})
        return m


ldb.Message = Message
sys.modules["ldb"] = ldb

import paths  # noqa: E402

DOMAIN = "DC=ad"
SITES = {"org": "OU=org,OU=sites,DC=ad", "site2": "OU=site2,OU=org,OU=sites,DC=ad"}
paths.site_dn = lambda samdb, site: SITES[site]
paths.sites_dn = lambda samdb: "OU=sites,DC=ad"
paths.relative = lambda samdb, dn: dn[: -len("," + DOMAIN)]
paths.ancestors = lambda samdb, site: [] if site == "org" else ["org"]

from create_machine import create_machine  # noqa: E402
from sort_windows_machines import sort_windows_machines  # noqa: E402
from adopt_linux_machines import adopt_linux_machines, UNMANAGED  # noqa: E402
from set_machine_class import set_machine_class as dc_set_machine_class  # noqa: E402
from list_machines import list_machines  # noqa: E402
from ssh_user_sites import ssh_user_sites  # noqa: E402
from plan_logon_entries import plan_logon_entries  # noqa: E402
from logon_rights_policy import logon_rights_policy  # noqa: E402
from remote_defaults import remote_defaults  # noqa: E402
import site_roles  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.samba.plan_class_logon import CLASSES as HOST_CLASSES, plan_class_logon  # noqa: E402
import fabriclib.directory.set_machine_class as hsmc  # noqa: E402
import fabriclib.directory.add_machine as ham  # noqa: E402
import fabriclib.samba.run_domain_command as cli  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def raises(fn, *a, kind=ValueError, match="", **kw):
    try:
        fn(*a, **kw)
    except kind as e:
        return match.lower() in str(e).lower()
    return False


class SamDB:
    """A directory in memory: OUs, computers (attributes as lists), groups' members."""

    def __init__(self):
        self.entries, self.members, self.renames = {}, {}, []
        site = SITES["site2"]
        for ou in ["OU=machines", "OU=fabric-hosts", "OU=groups"] + [
                f"OU={os_},OU={cls},OU=machines" for cls in ("servers", "desktops") for os_ in ("linux", "windows")] + [
                f"OU={cls},OU=machines" for cls in ("servers", "desktops")]:
            self.entries[f"{ou},{site}".lower()] = (f"{ou},{site}", Message(f"{ou},{site}"))

    def domain_dn(self):
        return DOMAIN

    def add_computer(self, dn, **attrs):
        m = Message(dn)
        cn = dn.split(",", 1)[0][3:]
        m.update({"cn": [cn], "sAMAccountName": [f"{cn}$"], "objectGUID": [f"guid-{cn.lower()}"],
                  "objectClass": ["computer"], "userAccountControl": ["4096"]})
        m.update({k: [v] for k, v in attrs.items()})
        self.entries[dn.lower()] = (dn, m)
        return m

    def newcomputer(self, account, computerou):
        self.add_computer(f"CN={account},{computerou},{DOMAIN}")

    def setpassword(self, *a, **kw):
        pass

    def add_remove_group_members(self, group, names, add_members_operation=True):
        self.members.setdefault(group, set()).update(names) if add_members_operation else None

    def modify(self, msg):
        dn, m = self.entries[str(msg.dn).lower()]
        m.update({k: [v] if isinstance(v, str) else v for k, v in msg.items()})

    def rename(self, old, new):
        _, m = self.entries.pop(old.lower())
        m.dn = new
        self.entries[new.lower()] = (new, m)
        self.renames.append((old, new))

    def schema_format_value(self, attr, value):
        return value.encode()

    def search(self, base, scope, expression="", attrs=None):
        if base.lower() not in self.entries:
            raise LdbError(ldb.ERR_NO_SUCH_OBJECT, base)
        out = []
        for key, (dn, m) in self.entries.items():
            if scope == ldb.SCOPE_BASE:
                ok = key == base.lower()
            elif scope == ldb.SCOPE_ONELEVEL:
                ok = key.split(",", 1)[1] == base.lower() if "," in key else False
            else:
                ok = key == base.lower() or key.endswith("," + base.lower())
            if not ok or (scope != ldb.SCOPE_BASE and "computer" not in m.get("objectClass", [])):
                continue
            name = re.search(r"sAMAccountName=([^)]*)\)", expression)
            if name and str(m["sAMAccountName"][0]).lower() != name.group(1).lower():
                continue
            if "operatingSystem=Windows*" in expression and not str(m.get("operatingSystem", idx=0) or "") \
                    .startswith("Windows"):
                continue
            out.append(m)
        return out


S2 = SAMDB = None
M = "OU=machines,OU=site2,OU=org,OU=sites,DC=ad"

# ---------------------------------------------------------------- the class GPOs: who holds the remote log-on right
print("--- the class GPOs (what the DC writes, what status shows)")
GROUPS = {   # who is in which group (nesting): the layered default of a site below the root, and three people
    "site2-server-remote-users": ["fabric-admins", "org-admins", "site2-fabric-admins", "sam"],
    "site2-desktop-remote-users": ["fabric-admins", "org-admins", "site2-admins", "dana"],
    "fabric-admins": ["ivan"], "site2-admins": ["ada"], "site2-fabric-admins": ["hal"]}


def member(person, group, seen=()):
    return person == group or any(member(person, g, seen + (group,)) for g in GROUPS.get(group, ())
                                  if g not in seen)


def remote_right(plan, ou, person):
    """The remote log-on right at a machine in `ou`: the nearest policy at or above it that sets it (rights are not
    merged between GPOs: the nearest one that sets a right wins)."""
    path = ou
    while True:
        if path in plan:
            return any(member(person, g) for g in plan[path]["remote"])
        if not path:
            return False
        path = path.rsplit("/", 1)[0] if "/" in path else ""


for label, policies, legacy in (("per-OU policies naming nothing above", {}, []),
                                ("the legacy single policy", None, ["site2-admins"]),
                                ("a policy on machines", {"machines": {"console": ["site2-admins"],
                                                                       "remote": ["site2-machine-admins"]}}, [])):
    plan = plan_logon_entries("site2", policies, legacy)
    check(f"{label}: the host's status shows exactly what the DC writes", plan == plan_class_logon("site2", policies,
                                                                                                   legacy),
          (plan, plan_class_logon("site2", policies, legacy)))
    for ou in ("machines/servers/linux", "machines/servers/windows"):
        right = "SSH (SSSD)" if ou.endswith("linux") else "RDP"
        check(f"{label}: the server group's member reaches a server ({ou}) by {right}", remote_right(plan, ou, "sam"))
        check(f"{label}: negative: the desktop group's member is refused on a server ({ou})",
              not remote_right(plan, ou, "dana"))
        check(f"{label}: central IT (fabric-admins, nested in both) reaches a server ({ou})",
              remote_right(plan, ou, "ivan"))
    for ou in ("machines/desktops/linux", "machines/desktops/windows"):
        check(f"{label}: the desktop group's member reaches a desktop ({ou})", remote_right(plan, ou, "dana"))
        check(f"{label}: negative: the server group's member is refused on a desktop ({ou})",
              not remote_right(plan, ou, "sam"))
        check(f"{label}: central IT reaches a desktop ({ou})", remote_right(plan, ou, "ivan"))
    if policies is None:      # the legacy groups (an upgrade's) stay on every machine, so nobody loses access
        check(f"{label}: the legacy groups keep both classes", remote_right(plan, "machines/servers/linux", "ada")
              and remote_right(plan, "machines/desktops/windows", "ada"))
        continue
    check(f"{label}: the site's admins reach its desktops, not its servers (the layered default)",
          remote_right(plan, "machines/desktops/windows", "ada") and not remote_right(plan, "machines/servers/linux",
                                                                                      "ada"))
    check(f"{label}: the site's fabric admins reach its servers, not its desktops",
          remote_right(plan, "machines/servers/linux", "hal") and not remote_right(plan, "machines/desktops/linux",
                                                                                   "hal"))
    check(f"{label}: negative: no class group above the class OUs (it would reach the other class)",
          all("remote-users" not in g for p, e in plan.items() for g in e["remote"]
              if not p.startswith("machines/servers") and not p.startswith("machines/desktops")), plan)
plan = plan_logon_entries("site2", None, ["site2-admins"])
check("legacy: each class GPO repeats what it inherits (rights do not merge), its class group added",
      plan["machines/servers"] == {"console": ["site2-admins"], "remote": ["site2-admins",
                                                                           "site2-server-remote-users"]}, plan)
plan = plan_logon_entries("site2", {}, [])
check("nothing above: the class GPO leaves the keyboard right unset (None: a GPO above decides it)",
      plan["machines/desktops"]["console"] is None, plan)
plan = plan_logon_entries("site2", {"machines/servers": {"console": ["a"], "remote": ["b"]},
                                    "machines/servers/linux": {"console": ["c"], "remote": ["d"]}}, [])
check("a policy the setting names at or below a class OU gets that class's group, nothing else is added",
      plan["machines/servers"]["remote"] == ["b", "site2-server-remote-users"]
      and plan["machines/servers/linux"]["remote"] == ["d", "site2-server-remote-users"], plan)
check("the fabric host's OU keeps its own default: no class group (2.1.6.53)",
      plan["fabric-hosts"]["remote"] == ["fabric-admins", "site2-fabric-admins"], plan)
check("the host's classes are the DC's", dict(HOST_CLASSES) == site_roles.CLASSES)
text = logon_rights_policy(None, (), ["S-1-5-21-1"]).decode("utf-16")
check("a class GPO with the keyboard right unset writes only the remote right",
      "SeInteractiveLogonRight" not in text and "SeRemoteInteractiveLogonRight = *S-1-5-21-1" in text, text)
text = logon_rights_policy(None, ["S-1-5-21-9"], ["S-1-5-21-1"], ["S-1-5-21-1"]).decode("utf-16")
check("a class GPO puts its remote users in each machine's Remote Desktop Users (RDP needs it beside the right), "
      "the windows-admins still in Administrators", "*S-1-5-21-1__Memberof = *S-1-5-32-555" in text
      and "*S-1-5-21-9__Memberof = *S-1-5-32-544" in text, text)
check("negative: no Remote Desktop Users entry unless asked (the other OUs' policies)",
      "S-1-5-32-555" not in logon_rights_policy(["S-1-5-21-2"], ["S-1-5-21-9"]).decode("utf-16"))
check("negative: a policy with no one remotely is refused", raises(logon_rights_policy, None, (), [], match="SID"))

# ---------------------------------------------------------------- the groups and their layered default
print("--- the groups")
check("names: <site>-server-remote-users, <site>-desktop-remote-users",
      site_roles.remote_users("site2", "server") == "site2-server-remote-users"
      and site_roles.remote_users("site2", "desktop") == "site2-desktop-remote-users")
check("negative: no group for another class", raises(site_roles.remote_users, "site2", "laptop", kind=KeyError))
check("the remote roles a site above grants (2.1.9.21 on dev/0.9.0-roles): server- and desktop-remote-users",
      sorted(site_roles.REMOTE_ROLES) == ["desktop-remote-users", "server-remote-users"])
check("layered default, server group: central IT (fabric-admins, the root's admins) and the site's fabric admins",
      remote_defaults(None, "site2", "server") == ["fabric-admins", "org-admins", "site2-fabric-admins"])
check("layered default, desktop group: central IT and the site's admins",
      remote_defaults(None, "site2", "desktop") == ["fabric-admins", "org-admins", "site2-admins"])
check("at the root: central IT once (its admins are the site's)",
      remote_defaults(None, "org", "desktop") == ["fabric-admins", "org-admins"])
src = open(os.path.join(REPO, "src", "containers", "samba", "ensure_groups.py"), encoding="utf-8").read()
# directory_ops imports Samba's own modules: read as text
OPS_SRC = open(os.path.join(REPO, "src", "containers", "samba", "directory_ops.py"), encoding="utf-8").read()
check("made, and nested, only by convergence (ensure_groups), never through a directory operation",
      "remote_defaults(samdb, site, cls)" in src and not re.search(r'"[a-z_]*remote[a-z_]*":', OPS_SRC), OPS_SRC)

# ---------------------------------------------------------------- machines placed by class
print("--- machines placed by class")
db = SamDB()
done = create_machine(db, None, "site2", "web1", "pw", os="linux")
check("add-machine --os linux: a server, in OU=linux,OU=servers", done["class"] == "server"
      and done["dn"] == f"CN=WEB1,OU=linux,OU=servers,{M}", done)
done = create_machine(db, None, "site2", "ws1", "pw", os="windows")
check("add-machine --os windows: a desktop, in OU=windows,OU=desktops", done["dn"] == f"CN=WS1,OU=windows,OU=desktops,{M}")
done = create_machine(db, None, "site2", "kiosk", "pw", os="linux", machine_class="desktop")
check("add-machine --os linux --class desktop: OU=linux,OU=desktops", done["dn"] == f"CN=KIOSK,OU=linux,OU=desktops,{M}")
done = create_machine(db, None, "site2", "any1", "pw")
check("no OS, no class: OU=machines itself (sorted later)", done["dn"] == f"CN=ANY1,{M}" and done["class"] == "")
check("negative: another class refused", raises(create_machine, db, None, "site2", "x1", "pw", os="linux",
                                                machine_class="laptop", match="machine class"))
db.add_computer(f"CN=SRV22,{M}", operatingSystem="Windows Server 2022 Datacenter")
db.add_computer(f"CN=PC7,{M}", operatingSystem="Windows 11 Pro")
moved = {m["name"]: m for m in sort_windows_machines(db, None, "site2")}
check("sorted: Windows Server into OU=windows,OU=servers; Windows 11 into OU=windows,OU=desktops",
      moved["srv22"]["to"] == f"CN=SRV22,OU=windows,OU=servers,{M}" and moved["srv22"]["class"] == "server"
      and moved["pc7"]["to"] == f"CN=PC7,OU=windows,OU=desktops,{M}", moved)
db.add_computer(f"CN=LX1,OU=linux,OU=servers,{M}")
db.add_computer(f"CN=LX2,OU=linux,OU=desktops,{M}")
db.add_computer(f"CN=LX3,OU=linux,OU=desktops,{M}", description=UNMANAGED)
adopted = sorted(m["name"] for m in adopt_linux_machines(db, None, "site2"))
check("adopted from both classes' OU=linux; an unmanaged one left out", "lx1" in adopted and "lx2" in adopted
      and "lx3" not in adopted, adopted)
listed = {m["name"]: m["class"] for m in list_machines(db, None, "site2")}
check("listed with their class", listed.get("web1") == "server" and listed.get("ws1") == "desktop"
      and listed.get("any1") == "", listed)

# covers: cli:domain.machine +
done = dc_set_machine_class(db, None, "site2", "web1", "desktop")
check("machine class web1 desktop: moved to OU=linux,OU=desktops, its OS family kept",
      done["changed"] and done["dn"] == f"CN=WEB1,OU=linux,OU=desktops,{M}", done)
done = dc_set_machine_class(db, None, "site2", "WEB1", "desktop")
check("a second time: nothing changes", not done["changed"], done)
done = dc_set_machine_class(db, None, "site2", "any1", "server")
check("a machine in OU=machines itself: its OS family from operatingSystem (Linux when not Windows)",
      done["dn"] == f"CN=ANY1,OU=linux,OU=servers,{M}", done)
db.add_computer("CN=FAB,OU=fabric-hosts,OU=site2,OU=org,OU=sites,DC=ad")
# covers: cli:domain.machine -
check("negative: the site's fabric host is refused (a policy of its own)",
      raises(dc_set_machine_class, db, None, "site2", "fab", "server", match="fabric host"))
check("negative: another class refused", raises(dc_set_machine_class, db, None, "site2", "ws1", "laptop",
                                                match="machine class"))
check("negative: not a machine of the site", raises(dc_set_machine_class, db, None, "site2", "nope", "server",
                                                    kind=LdbError))
check("the operation is registered (a write: it goes to a writable DC)",
      '"set_machine_class": set_machine_class,' in OPS_SRC and "set_machine_class" not in open(os.path.join(
          REPO, "src", "fabriclib", "directory", "run_op.py"), encoding="utf-8").read().split("READS", 1)[1][:2000])

# ---------------------------------------------------------------- the signing side's grants
print("--- whose certificate names which class")


class Groups(SamDB):
    def search(self, base, scope, expression="", attrs=None):
        if "objectCategory=person" in expression:
            return [Message("CN=alice,OU=people,OU=site2,OU=org,OU=sites,DC=ad")] if "alice" in expression else []
        out = []
        for dn in ("CN=site2-server-remote-users,OU=groups,OU=site2,OU=org,OU=sites,DC=ad",
                   "CN=org-desktop-remote-users,OU=groups,OU=org,OU=sites,DC=ad",
                   "CN=site2-desktop-remote-users,OU=people,OU=site2,OU=org,OU=sites,DC=ad",   # not in OU=groups
                   "CN=site2-laptop-remote-users,OU=groups,OU=site2,OU=org,OU=sites,DC=ad",
                   "CN=site2-ssh-users,OU=groups,OU=site2,OU=org,OU=sites,DC=ad"):
            m = Message(dn)
            m["sAMAccountName"] = [dn.split(",", 1)[0][3:]]
            out.append(m)
        return out


got = ssh_user_sites(Groups(), None, "site2", "alice")
check("grants: each <site>-<class>-remote-users in its site's own OU=groups",
      got == {"uid": "alice", "grants": [{"site": "org", "class": "desktop"}, {"site": "site2", "class": "server"}]},
      got)
check("negative: no such person", raises(ssh_user_sites, Groups(), None, "site2", "zed", match="no such user"))

# ---------------------------------------------------------------- the host and the command line
print("--- the host side and the command line")
AUDIT, CALLS = [], []
hsmc.write_audit = lambda actor, event, detail, source="cli": AUDIT.append((event, detail))


def fake_op(v, secrets, op, args=None, container="samba", server=None):
    CALLS.append((op, args))
    if args.get("name") == "fab":
        raise ValidationError("fab is this site's fabric host: it has a log-on policy of its own (2.1.6.53), no class")
    return {"name": args["name"], "class": args["machine_class"], "dn": "CN=X", "changed": args["name"] != "same"}


hsmc.run_op = fake_op
V = {"site_name": "site2"}
done = hsmc.set_machine_class(V, "ada", "web1", "server", secrets={})
check("the host asks the DC's operation and audits MACHINE_CLASS", CALLS[-1] == (
    "set_machine_class", {"name": "web1", "machine_class": "server"}) and AUDIT[-1] == (
    "MACHINE_CLASS", "machine=web1 class=server"), (CALLS, AUDIT))
n = len(AUDIT)
hsmc.set_machine_class(V, "ada", "same", "desktop", secrets={})
check("nothing changed: nothing audited", len(AUDIT) == n)
n = len(CALLS)
check("negative: another class refused before the DC is asked",
      raises(hsmc.set_machine_class, V, "ada", "web1", "laptop", secrets={}, kind=ValidationError, match="class:")
      and len(CALLS) == n)
cli.set_machine_class = lambda v, actor, name, cls: hsmc.set_machine_class(v, actor, name, cls, secrets={})


def run(args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.run_domain_command(V, args)
    return rc, out.getvalue()


rc, out = run(["machine", "class", "web1", "desktop"])
check("fabricctl domain machine class web1 desktop: done, naming who may sign in", rc == 0
      and "site2-desktop-remote-users" in out, out)
rc, out = run(["machine", "class", "fab", "server"])
check("negative: the fabric host: refused, saying why", rc == 1 and "fabric host" in out, out)
rc, out = run(["machine", "class", "web1", "laptop"])
check("negative: another class: refused", rc == 1 and "class:" in out, out)
for bad in (["machine"], ["machine", "class", "web1"], ["machine", "kind", "web1", "server"],
            ["machine", "class", "--x", "server"]):
    rc, out = run(bad)
    check(f"negative: usage for {' '.join(bad)}", rc == 2 and "usage:" in out, out)
ADDED = []
cli.add_machine = lambda v, actor, name, os=None, managed=True, machine_class=None: ADDED.append(
    (name, os, managed, machine_class)) or "pw"
# covers: cli:domain.add-machine +
rc, out = run(["add-machine", "kiosk", "--class", "desktop", "--os", "linux", "--unmanaged"])
check("add-machine with --class, --os and --unmanaged in any order", rc == 0 and ADDED[-1] == (
    "kiosk", "linux", False, "desktop"), (rc, out, ADDED))
# covers: cli:domain.add-machine -
for bad in (["add-machine", "k", "--class"], ["add-machine", "k", "--kind", "server"],
            ["add-machine", "k", "--os", "linux", "--os"]):
    rc, out = run(bad)
    check(f"negative: usage for {' '.join(bad)}", rc == 2, out)
ham.run_op = lambda *a, **kw: None
ham.people_password = lambda v: "pw"
ham.write_audit = lambda *a, **kw: None
check("negative: the host refuses another class before the DC is asked",
      raises(ham.add_machine, V, "ada", "k1", secrets={}, os="linux", machine_class="laptop", kind=ValidationError,
             match="class:"))

print("\nall passed (0 failures)" if not FAILED else f"\nFAILED ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
