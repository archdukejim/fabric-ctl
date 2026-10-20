"""The `samba` suite, host groups and sudo rules (manual 1.6.11.7, 2.1.6.31): a real DC converged by fabric's code,
edited with `fabricctl machines` and `fabricctl sudo`, the agent's routes and the web console's forms. Proves: host
groups `hosts-<name>` in the domain's OU=groups, machines in and out; sudo rules as `sudoRole` objects in the
domain's OU=sudoers (2.1.6.80), marked as the editor's, their sudoHost the
host group's machines (short and DNS names) and following the group as machines come and go (and at convergence, for
a member added with other tools); `sudo list` showing fabric's and an admin's own rule; the refusals (ALL
commands to everyone or a whole site, someone not in the domain, a relative command, an unknown host group or machine,
bad names, a taken name, removing an admin's rule, deleting a host group a rule names); the routes' permissions.
    sudo python3 tests/samba/hostgroups.py
"""
import contextlib
import io
import os
import subprocess
import sys
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from start_dc import start_dc  # noqa: E402
import agent.get_route as m_get  # noqa: E402
import agent.post_host_access as m_post  # noqa: E402
import fabriclib.directory.add_sudo_rule as m_add_rule  # noqa: E402
import fabriclib.directory.create_host_group as m_create  # noqa: E402
import fabriclib.directory.list_host_groups as m_list_groups  # noqa: E402
import fabriclib.directory.list_sudo_rules as m_list_rules  # noqa: E402
import fabriclib.directory.remove_host_group as m_remove  # noqa: E402
import fabriclib.directory.remove_sudo_rule as m_remove_rule  # noqa: E402
import fabriclib.directory.run_machines_command as m_machines  # noqa: E402
import fabriclib.directory.run_sudo_command as m_sudo  # noqa: E402
import fabriclib.directory.set_host_group_member as m_member  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = os.path.join(os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests"), "samba-hostgroups")
NET, SUBNET, IP, DC = "hostgroups_net", "10.254.37.0/24", "10.254.37.10", "hgdc"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def cleanup():
    subprocess.run(["docker", "rm", "-f", DC], capture_output=True)
    subprocess.run(["docker", "network", "rm", NET], capture_output=True)


cleanup()
dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
V, SECRETS = dc["v"], dc["secrets"]
AUDIT = []
for mod in (m_add_rule, m_create, m_list_groups, m_list_rules, m_remove, m_remove_rule, m_member):
    mod.run_op = lambda v, s, op, args=None, container="samba": run_op(v, s, op, args, DC)
    mod.load_secrets = lambda: SECRETS
    mod.write_audit = lambda actor, event, detail, source="cli": AUDIT.append((event, detail, source))
m_post.load_vars = m_get.load_vars = lambda: dict(V)

# the domain's machines and people: web1, web2, db1 (pre-created, as add-machine makes them), alice and bob, and a
# group of people, web-ops
for name in ("web1", "web2", "db1"):
    run_op(V, SECRETS, "create_machine", {"name": name, "password": "Ot-" + random_password(20), "type": "server"}, DC)
subprocess.run(["docker", "exec", DC, "samba-tool", "group", "add", "web-ops", "--groupou=OU=groups", "-s",
                "/data/etc/smb.conf"], capture_output=True)
for uid in ("alice", "bob"):
    run_op(V, SECRETS, "create_person", {"uid": uid, "first": uid.title(), "last": "Test", "email": f"{uid}@lan.test",
                                         "password": "Ot-" + random_password(20), "gid": 5000, "home_base": "/home",
                                         "shell": "/bin/bash"}, DC)


def machines(*args):
    """fabricctl machines as root runs it: (exit status, what it printed)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_machines.run_machines_command(dict(V), list(args))
    return code, out.getvalue()


def sudo(*args):
    """fabricctl sudo as root runs it: (exit status, what it printed)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_sudo.run_sudo_command(dict(V), list(args))
    return code, out.getvalue()


def ldb(expression, *attrs):
    """An ldbsearch on the DC's own database: the entries' text."""
    out = subprocess.run(["docker", "exec", DC, "ldbsearch", "-H", "/data/private/sam.ldb", expression, *attrs],
                         capture_output=True, text=True).stdout
    return out.replace("\n ", "")              # LDIF folds long lines: a continuation starts with one space


def rule_hosts(name):
    """A sudo rule's sudoHost values, sorted."""
    return sorted(line.split(": ", 1)[1] for line in ldb(f"(&(objectClass=sudoRole)(cn={name}))", "sudoHost")
                  .splitlines() if line.startswith("sudoHost: "))


def host_names(*machines_):
    """What sudo matches for machines: each one's short name, and its DNS name when its account has one (a machine
    pre-created by add-machine has none until it joins; one joined by adcli has)."""
    names = list(machines_)
    for m in machines_:
        names += [line.split(": ", 1)[1].lower() for line in ldb(f"(sAMAccountName={m}$)", "dNSHostName").splitlines()
                  if line.startswith("dNSHostName: ")]
    return sorted(names)


print("--- host groups: fabricctl machines")
code, out = machines("groups")
# covers: cli:machines cli:machines.groups +
check("machines groups, before any: none yet, how to make one", code == 0 and "no host groups yet" in out, out)
code, out = machines("group", "create", "web")
# covers: cli:machines.group +
check("machines group create web: the AD group hosts-web (no site prefix: the domain's), audited",
      code == 0 and "host group hosts-web created" in out and AUDIT[-1][0] == "HOST_GROUP_CREATE", (out, AUDIT))
entry = ldb("(sAMAccountName=hosts-web)", "distinguishedName", "groupType", "description")
check("...in OU=groups, a security group, marked as fabric's",
      f"CN=hosts-web,OU=groups,{V['ad_base_dn']}" in entry and "groupType: -2147483646" in entry
      and "fabric: a host group (manual 1.6.11.7)" in entry, entry)
code, out = machines("group", "create", "hosts-db")
check("a host group given by its AD name: the same group (hosts-db)", code == 0 and "host group hosts-db created" in out
      and "hosts-hosts-db" not in out, out)
for m in ("web1", "web2"):
    code, out = machines("group", "add", "web", m)
    check(f"machines group add web {m}: in, audited", code == 0 and f"{m}: in hosts-web" in out
          and AUDIT[-1][:2] == ("HOST_GROUP_MEMBER_ADD", f"group=hosts-web machine={m}"), (out, AUDIT[-1:]))
code, out = machines("group", "add", "web", "web1")
check("adding a machine already in it changes nothing, nothing audited", code == 0 and "(already)" in out
      and AUDIT[-1][1].endswith("web2"), out)
code, out = machines("groups")
check("machines groups: each host group with its machines", code == 0 and "hosts-web: web1, web2" in out
      and "hosts-db: (no machines)" in out, out)

print("--- sudo rules: fabricctl sudo")
code, out = sudo("add", "web-restart", "--who", "alice,%web-ops", "--commands",
                 "/usr/bin/systemctl restart nginx,/usr/bin/journalctl -u nginx", "--hosts", "web")
# covers: cli:sudo cli:sudo.add +
check("sudo add on a host group: added, its hosts the group's machines", code == 0 and "web-restart added" in out
      and "web1" in out and "web2" in out, out)
rule = ldb("(&(objectClass=sudoRole)(cn=web-restart))", "distinguishedName", "sudoUser", "sudoCommand",
           "sudoRunAsUser", "description")
check("...a sudoRole in the domain's OU=sudoers: who, the commands, as root, marked as the editor's on hosts-web",
      f"CN=web-restart,OU=sudoers,{V['ad_base_dn']}" in rule and "sudoUser: alice" in rule
      and "sudoUser: %web-ops" in rule and "sudoCommand: /usr/bin/systemctl restart nginx" in rule
      and "sudoCommand: /usr/bin/journalctl -u nginx" in rule and "sudoRunAsUser: root" in rule
      and "description: fabric: a sudo rule of fabric's editor (manual 1.6.11.7); hosts: hosts-web" in rule, rule)
check("...its sudoHost: each machine's short name and DNS name (what sssd matches)",
      rule_hosts("web-restart") == host_names("web1", "web2"), rule_hosts("web-restart"))
check("...audited as SUDO_RULE_ADD with who, what and where", AUDIT[-1][0] == "SUDO_RULE_ADD"
      and "who=alice,%web-ops" in AUDIT[-1][1] and "hosts=hosts-web" in AUDIT[-1][1], AUDIT[-1:])
code, out = machines("group", "add", "web", "db1")
check("a machine put in the host group: the rule names it at once", code == 0 and "sudo rule web-restart" in out
      and rule_hosts("web-restart") == host_names("db1", "web1", "web2"), (out, rule_hosts("web-restart")))
code, out = machines("group", "remove", "web", "web2")
check("a machine taken out: the rule no longer names it, audited",
      code == 0 and "web2: out of hosts-web" in out and rule_hosts("web-restart") == host_names("db1", "web1")
      and AUDIT[-1][0] == "HOST_GROUP_MEMBER_REMOVE", (out, rule_hosts("web-restart")))
code, out = sudo("add", "db-all", "--who", "bob", "--commands", "ALL", "--hosts", "hosts-db")
check("a person given ALL on an empty host group: added, applying nowhere yet (no sudoHost)",
      code == 0 and "no machines yet" in out and rule_hosts("db-all") == [], (out, rule_hosts("db-all")))
code, out = sudo("add", "everyone-uptime", "--who", "%site-lan", "--commands", "/usr/bin/uptime", "--as", "nobody")
check("a whole site may be given a named command (not ALL), on every joined machine, as another account",
      code == 0 and rule_hosts("everyone-uptime") == ["ALL"]
      and "sudoRunAsUser: nobody" in ldb("(cn=everyone-uptime)", "sudoRunAsUser"), out)

# an admin's own rule, made with their own tools: listed, never changed by fabric
own = (f"dn: CN=backup-ops,OU=sudoers,{V['ad_base_dn']}\nobjectClass: sudoRole\n"
       "sudoUser: bob\nsudoHost: ALL\nsudoCommand: /usr/bin/rsync\ndescription: our backups\n")
made = subprocess.run(["docker", "exec", "-i", DC, "ldbadd", "-H", "/data/private/sam.ldb"], input=own,
                      capture_output=True, text=True)
check("an admin's own sudo rule, made with other tools", made.returncode == 0, made.stderr)
code, out = sudo("list")
# covers: cli:sudo.list +
check("sudo list: fabric's rules and the admin's own, each marked; no site default rule (2.1.6.80)",
      code == 0 and "web-restart [fabric]: " in out and "%web-ops" in out and "on hosts-web (db1, " in out
      and "default" not in out and "backup-ops [not fabric's: read-only here]" in out, out)

before_rules, n_audit = ldb("(objectClass=sudoRole)", "cn", "sudoHost"), len(AUDIT)
for args, why, words in (
        (("add", "all-all", "--who", "ALL", "--commands", "ALL"), "ALL commands to ALL", "everyone is refused"),
        (("add", "users-all", "--who", "alice,%site-lan", "--commands", "ALL"), "ALL commands to a whole site",
         "everyone is refused"),
        (("add", "users-all", "--who", "%users", "--commands", "ALL"), "ALL commands to fabric's users",
         "everyone is refused"),
        (("add", "du-all", "--who", "%Domain Users", "--commands", "/bin/true,ALL", "--hosts", "web"),
         "ALL commands to Domain Users", "everyone is refused"),
        (("add", "ghost", "--who", "ghost", "--commands", "/bin/true"), "someone not in the domain",
         "no person or group ghost"),
        (("add", "ghost", "--who", "%no-such-group", "--commands", "/bin/true"), "a group not in the domain",
         "no person or group %no-such-group"),
        (("add", "rel", "--who", "alice", "--commands", "bin/true"), "a relative command", "not an absolute path"),
        (("add", "nl", "--who", "alice", "--commands", "/bin/true\nALL"), "a command with a newline",
         "not an absolute path"),
        (("add", "nogroup", "--who", "alice", "--commands", "/bin/true", "--hosts", "nope"), "an unknown host group",
         "no host group hosts-nope"),
        (("add", "Bad Name", "--who", "alice", "--commands", "/bin/true"), "a bad rule name", "rule name"),
        (("add", "bad-who", "--who", "a(b)", "--commands", "/bin/true"), "a bad user name", "is not a user name"),
        (("add", "web-restart", "--who", "alice", "--commands", "/bin/true"), "a taken name", "already taken"),
        (("remove", "backup-ops"), "removing an admin's own rule", "not made by fabric's sudo editor"),
        (("remove", "nope"), "removing a rule that does not exist", "no sudo rule nope")):
    code, out = sudo(*args)
    # covers: cli:sudo.add cli:sudo.remove -
    check(f"sudo {args[0]} refused: {why}, saying why, nothing changed or audited",
          code == 1 and words in out and len(AUDIT) == n_audit
          and ldb("(objectClass=sudoRole)", "cn", "sudoHost") == before_rules, out)
code, out = sudo("add", "x", "--who", "alice")
# covers: cli:sudo cli:sudo.list -
check("usage: add without --commands, an unknown option, list with words, no subcommand (exit 2)",
      code == 2 and "fabricctl sudo add <name>" in out and sudo("add", "x", "--who", "a", "--commands", "/x",
                                                                 "--ssh", "y")[0] == 2
      and sudo("list", "all")[0] == 2 and sudo()[0] == 2, out)

before_groups = ldb("(sAMAccountName=hosts-*)", "member")
for args, why, words in (
        (("group", "create", "Web_Servers"), "a bad host group name", "host group: 1-32 characters"),
        (("group", "create", "web"), "a taken name", "already taken"),
        (("group", "add", "web", "nosuch"), "a machine the domain does not have", "no machine nosuch in OU=machines"),
        (("group", "add", "web", "web 1"), "a bad machine name", "machine name"),
        (("group", "add", "nope", "web1"), "an unknown host group", "no host group hosts-nope"),
        (("group", "delete", "web"), "deleting a host group a sudo rule names", "named by sudo rule(s) web-restart"),
        (("group", "delete", "nope"), "deleting a host group that does not exist", "no host group hosts-nope")):
    code, out = machines(*args)
    # covers: cli:machines.group -
    check(f"machines {' '.join(args[:2])} refused: {why}, saying why, nothing changed or audited",
          code == 1 and words in out and len(AUDIT) == n_audit
          and ldb("(sAMAccountName=hosts-*)", "member") == before_groups, out)
code, out = machines("groups", "all")
# covers: cli:machines cli:machines.groups -
check("usage: groups with words, group without its arguments, no subcommand (exit 2)",
      code == 2 and "fabricctl machines group add" in out and machines("group", "add", "web")[0] == 2
      and machines()[0] == 2, out)

print("--- convergence: a member added with other tools")
subprocess.run(["docker", "exec", DC, "samba-tool", "group", "addmembers", "hosts-web", "WEB2$", "-s",
                "/data/etc/smb.conf"], capture_output=True)
done = converge_domain(V, os.path.join(W, "dc", "federation.yaml"), SECRETS, container=DC)
check("converge names a machine added to the host group outside fabric (RSAT, samba-tool) in its rules",
      any(c.startswith("sudo rule web-restart: hosts") for c in done)
      and rule_hosts("web-restart") == host_names("db1", "web1", "web2"), (done, rule_hosts("web-restart")))
again = converge_domain(V, os.path.join(W, "dc", "federation.yaml"), SECRETS, container=DC)
check("converge again changes nothing (idempotent)", again == [], again)
check("...and the admin's own rule is as they made it", "sudoHost: ALL" in ldb("(cn=backup-ops)", "sudoHost")
      and "our backups" in ldb("(cn=backup-ops)", "description"))

code, out = sudo("remove", "db-all")
# covers: cli:sudo.remove +
check("sudo remove: one of fabric's rules removed, audited", code == 0 and "db-all removed" in out
      and "db-all" not in ldb("(objectClass=sudoRole)", "cn") and AUDIT[-1][0] == "SUDO_RULE_REMOVE", out)
code, out = machines("group", "delete", "db")
check("machines group delete: a host group no rule names, removed, audited", code == 0 and "hosts-db removed"
      in out and "hosts-db" not in ldb("(sAMAccountName=hosts-*)", "cn")
      and AUDIT[-1][0] == "HOST_GROUP_REMOVE", out)

print("--- the agent's routes (the web console's Machines section)")
got = m_get.get_route(["host-groups"])
# covers: agent:get.host-groups +
check("GET /v1/host-groups: each host group, its machines, the rules on it",
      [g["name"] for g in got] == ["hosts-web"] and got[0]["machines"] == ["db1", "web1", "web2"]
      and got[0]["rules"] == ["web-restart"] and got[0]["fabric"], got)
got = m_get.get_route(["sudo"])
# covers: agent:get.sudo +
check("GET /v1/sudo: every rule of the domain, each with who made it (no default rule)",
      {r["name"]: r["kind"] for r in got} == {"backup-ops": "other", "everyone-uptime": "fabric",
                                              "grant-desktop-administrators": "grant",
                                              "grant-network-administrators": "grant",
                                              "grant-server-administrators": "grant",
                                              "web-restart": "fabric"}, got)
done = m_post.post_host_access(["host-groups"], "alice", {"name": "app"})
# covers: agent:post.host-groups +
check("POST /v1/host-groups: created, audited from the web", done == {"name": "hosts-app"}
      and AUDIT[-1] == ("HOST_GROUP_CREATE", "group=hosts-app", "web"), (done, AUDIT[-1:]))
done = m_post.post_host_access(["host-groups", "app", "members"], "alice", {"action": "add", "machine": "web2"})
# covers: agent:post.host-groups.*.members +
check("POST /v1/host-groups/app/members add: the machine in", done["member"] and done["changed"], done)
done = m_post.post_host_access(["sudo"], "alice", {"name": "app-logs", "users": ["bob"],
                                                   "commands": ["/usr/bin/journalctl"], "hosts": "app"})
# covers: agent:post.sudo +
check("POST /v1/sudo: added on the host group, its hosts web2's names",
      done == {"name": "app-logs", "hosts": host_names("web2")} and AUDIT[-1][2] == "web", done)
done = m_post.post_host_access(["sudo", "app-logs", "delete"], "alice", {})
# covers: agent:post.sudo.*.delete +
check("POST /v1/sudo/app-logs/delete: removed", done == {"name": "app-logs"}
      and "app-logs" not in ldb("(objectClass=sudoRole)", "cn"), done)
done = m_post.post_host_access(["host-groups", "app", "members"], "alice", {"action": "remove", "machine": "web2"})
check("POST /v1/host-groups/app/members remove: the machine out", not done["member"] and done["changed"], done)
done = m_post.post_host_access(["host-groups", "app", "delete"], "alice", {})
# covers: agent:post.host-groups.*.delete +
check("POST /v1/host-groups/app/delete: removed", done == {"name": "hosts-app"}
      and "hosts-app" not in ldb("(sAMAccountName=hosts-*)", "cn"), done)
n_audit = len(AUDIT)
for route, body, words, covers in (
        (["host-groups"], {"name": "a b"}, "host group: 1-32", "agent:post.host-groups"),
        (["host-groups", "web", "members"], {"action": "join", "machine": "web1"}, "action: add or remove",
         "agent:post.host-groups.*.members"),
        (["host-groups", "web", "members"], {"action": "add", "machine": "nosuch"}, "no machine nosuch",
         "agent:post.host-groups.*.members"),
        (["host-groups", "web", "delete"], {}, "named by sudo rule(s)", "agent:post.host-groups.*.delete"),
        (["sudo"], {"name": "x", "users": "alice", "commands": ["/bin/true"]}, "users must be a list",
         "agent:post.sudo"),
        (["sudo"], {"name": "x", "users": ["ALL"], "commands": ["ALL"]}, "everyone is refused", "agent:post.sudo"),
        (["sudo", "nope", "delete"], {}, "no sudo rule nope", "agent:post.sudo.*.delete"),
        (["sudo", "backup-ops", "delete"], {}, "not made by fabric's sudo editor", "agent:post.sudo.*.delete")):
    try:
        m_post.post_host_access(route, "alice", body)
        err = ""
    except ValidationError as e:
        err = str(e)
    # covers: agent:post.host-groups agent:post.host-groups.*.members agent:post.host-groups.*.delete -
    # covers: agent:post.sudo agent:post.sudo.*.delete -
    check(f"POST /v1/{'/'.join(route)} refused ({words}), nothing audited", words in err and len(AUDIT) == n_audit,
          err)
V_DOWN = {**V}
m_get.load_vars = lambda: V_DOWN
for mod in (m_list_groups, m_list_rules):
    mod.run_op = lambda v, s, op, args=None, container="samba": run_op(v, s, op, args, "no-such-dc")
for route in (["host-groups"], ["sudo"]):
    try:
        m_get.get_route(route)
        err = ""
    except ValidationError as e:
        err = str(e)
    # covers: agent:get.host-groups agent:get.sudo -
    check(f"GET /v1/{route[0]} with the directory down: refused, saying why (the page shows it)",
          "the directory is not reachable" in err, err)
for mod in (m_list_groups, m_list_rules):
    mod.run_op = lambda v, s, op, args=None, container="samba": run_op(v, s, op, args, DC)
check("the routes' permissions: reading needs domain:read, host groups machines:admin, sudo rules sudo:admin",
      required_permission("GET", ["host-groups"]) == required_permission("GET", ["sudo"]) == "domain:read"
      and {required_permission("POST", r) for r in (["host-groups"], ["host-groups", "x", "members"],
                                                    ["host-groups", "x", "delete"])} == {"machines:admin"}
      and required_permission("POST", ["sudo"]) == required_permission("POST", ["sudo", "x", "delete"])
      == "sudo:admin")
check("sudo:admin is the admin bundle's only: not the equipment operator's (who has machines:admin), nor the "
      "auditor's (who reads)", "sudo:admin" in BUNDLES["admin"]
      and all("sudo:admin" not in BUNDLES[b] for b in BUNDLES if b != "admin")
      and "machines:admin" in BUNDLES["fabric-equipment-operator"] and "domain:read" in BUNDLES["fabric-auditor"])

print("--- the web console's forms (their route code; the socket and the token are tests/webui's)")
import webui.agentclient as actions  # noqa: E402
from webui.routes.directory_post import directory_post  # noqa: E402


def agent(route, body=None):
    """The agent's route code as the client reaches it: a refusal as the client's 400."""
    try:
        return m_post.post_host_access(route, "alice", body or {})
    except ValidationError as e:
        raise actions.ValidationError(str(e))


def host_group_change(op, group, machine=""):
    if op == "create":
        return agent(["host-groups"], {"name": group})
    if op == "delete":
        return agent(["host-groups", group, "delete"])
    return agent(["host-groups", group, "members"], {"action": op, "machine": machine})


def sudo_rule_change(op, name, users=None, commands=None, run_as=None, hosts=""):
    if op == "delete":
        return agent(["sudo", name, "delete"])
    return agent(["sudo"], {"name": name, "users": users or [], "commands": commands or [], "run_as": run_as or [],
                            "hosts": hosts})


class Handler:
    def redirect(self, location):
        self.sent = (303, location)

    def deny(self, code, message):
        self.sent = (code, message)


actions.host_group_change, actions.sudo_rule_change = host_group_change, sudo_rule_change
h = Handler()


def form(parts, fields):
    """Post a form of the Machines section; the message it redirects with."""
    directory_post(h, {"user": "alice"}, parts, {"csrf": "x", **fields})
    return h.sent[0], urllib.parse.unquote_plus(h.sent[1])


code, loc = form(["hostgroups", "_new"], {"name": "ops"})
# covers: web:post.directory.hostgroups._new +
check("the New host group form: created, back to the Machines section", code == 303 and "view=machines" in loc
      and "host group hosts-ops created" in loc, loc)
code, loc = form(["hostgroups", "_form", "members"], {"group": "ops", "machine": "db1", "action": "add"})
# covers: web:post.directory.hostgroups._form.members +
check("the host group membership form: db1 in hosts-ops", "db1 in hosts-ops." in loc, loc)
code, loc = form(["sudo", "_new"], {"name": "ops-apt", "users": "alice, %web-ops", "commands": "/usr/bin/apt update",
                                    "run_as": "", "hosts": "hosts-ops"})
# covers: web:post.directory.sudo._new +
check("the Add sudo rule form: comma-separated who and commands, as root by default, on the host group",
      "sudo rule ops-apt added; hosts: db1" in loc and "sudoUser: %web-ops" in ldb("(cn=ops-apt)", "sudoUser")
      and "sudoRunAsUser: root" in ldb("(cn=ops-apt)", "sudoRunAsUser"), loc)
code, loc = form(["sudo", "_new"], {"name": "bad", "users": "%site-lan", "commands": "ALL", "hosts": "ALL"})
# covers: web:post.directory.sudo._new -
check("...its refusal shown there: ALL commands to everyone", code == 303 and "err=" in h.sent[1]
      and "everyone is refused" in loc and "cn: bad" not in ldb("(objectClass=sudoRole)", "cn"), loc)
code, loc = form(["hostgroups", "_form", "members"], {"group": "ops", "machine": "ghost", "action": "add"})
# covers: web:post.directory.hostgroups._form.members -
check("...the membership form's refusal: a machine the domain does not have", "no machine ghost in OU=machines" in loc,
      loc)
code, loc = form(["hostgroups", "_new"], {"name": "Ops!"})
# covers: web:post.directory.hostgroups._new -
check("...the New host group form's refusal: a bad name", "host group: 1-32 characters" in loc, loc)
code, loc = form(["hostgroups", "ops", "delete"], {})
# covers: web:post.directory.hostgroups.*.delete -
check("...a host group's Remove refused while a rule names it", "named by sudo rule(s) ops-apt" in loc, loc)
code, loc = form(["sudo", "backup-ops", "delete"], {})
# covers: web:post.directory.sudo.*.delete -
check("...a rule's Remove refused for an admin's own rule", "not made by fabric's sudo editor" in loc, loc)
code, loc = form(["sudo", "ops-apt", "delete"], {})
# covers: web:post.directory.sudo.*.delete +
check("a rule's Remove: removed", "sudo rule ops-apt removed" in loc
      and "ops-apt" not in ldb("(objectClass=sudoRole)", "cn"), loc)
code, loc = form(["hostgroups", "ops", "delete"], {})
# covers: web:post.directory.hostgroups.*.delete +
check("a host group's Remove: removed", "host group hosts-ops removed" in loc, loc)
code, loc = form(["hostgroups", "_new", "x"], {})
check("an unknown host group form: refused, saying so", "unknown operation" in loc, loc)

if not os.environ.get("FABRIC_TEST_KEEP"):
    cleanup()
print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
