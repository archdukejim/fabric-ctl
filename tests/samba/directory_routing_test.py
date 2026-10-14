"""Every directory write at a read-only DC's site goes to its writable DC (2.1.6.52, revised 2026-10-13; manual
1.6.11.13): the one routing point, fabriclib/directory/run_op, sends a write (every operation not in READS) to
`ad_join_server` and a read to the site's own DC; a write is refused before anything is asked when no writable DC is
known, and said plainly when that DC does not answer; at a writable DC's site nothing changes. Group Policy edits,
which only work on a DC's own copy, are refused at such a site. Pure logic: the DC's container is a stand-in (the
samba suite runs the real ones, tests/samba/dc.py).
    python3 tests/samba/directory_routing_test.py"""
import json
import os
import re
import subprocess
import sys
import types

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.samba.writable_server as _ws  # noqa: E402
_ws._answers = lambda server: True  # a pure test reaches no DC: every listed writable DC answers (2.1.6.57)
import fabriclib.directory.run_op as mod  # noqa: E402
import fabriclib.samba.gpo_request as gpo  # noqa: E402

PASS = FAIL = 0
RODC = {"site_name": "lab", "ad_dc_type": "rodc", "ad_join_server": " 10.0.9.5 "}
WRITABLE = {"site_name": "lab", "ad_dc_type": "dc", "ad_join_server": "10.0.9.5"}
SECRETS = {"ad_agent_password": "agent-pw"}


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


class Stand:
    """The DC's container: records each request, answers as set."""

    def __init__(self, answer=None):
        self.answer = answer if answer is not None else {"result": "ok"}
        self.requests = []

    def run(self, cmd, **kw):
        self.requests.append(json.loads(kw["input"]))
        return subprocess.CompletedProcess(cmd, 0, json.dumps(self.answer) + "\n", "")


def call(v, op, answer=None, server=None):
    s = Stand(answer)
    old = mod.subprocess
    mod.subprocess = types.SimpleNamespace(run=s.run)
    try:
        return mod.run_op(v, SECRETS, op, {}, "samba", server), None, s.requests
    except ValidationError as e:
        return None, str(e), s.requests
    finally:
        mod.subprocess = old


# every operation of the DC is either a read (READS) or a write; the reads change nothing
ops_file = open(os.path.join(REPO, "src", "containers", "samba", "directory_ops.py")).read()
ops = re.findall(r'^\s+"([a-z_]+)": [a-z_]+,$', ops_file, re.M)
ops_block = ops_file[ops_file.index("OPS = {"):]
ops_block = ops_block[:ops_block.index("\n}")]
check("the DC's whole operations list is read (every OPS entry, none missed by the pattern)",
      ops and len(ops) == ops_block.count('":') == len(set(ops)), (len(ops), ops_block.count('":')))
check("READS names only operations the DC has", ops and mod.READS <= set(ops), sorted(mod.READS - set(ops)))
check("SSH host certificates (2.1.7.13): list_ssh_hosts a read; prepare_ssh_hosts and set_ssh_host writes",
      {"list_ssh_hosts", "prepare_ssh_hosts", "set_ssh_host"} <= set(ops) and "list_ssh_hosts" in mod.READS
      and not {"prepare_ssh_hosts", "set_ssh_host"} & mod.READS, sorted(mod.READS))
writes = [op for op in ops if op not in mod.READS]
WRITES_CALLS = re.compile(r"\.(modify|add|delete|rename|add_remove_group_members|newuser|newgroup|setpassword)\(")
for op in sorted(mod.READS):
    code = open(os.path.join(REPO, "src", "containers", "samba", f"{op}.py")).read()
    check(f"read {op}: its code writes nothing", not WRITES_CALLS.search(code), WRITES_CALLS.findall(code))

# at a read-only DC's site: each write goes to the writable DC, each read stays at the site's own DC
for op in writes:
    result, why, reqs = call(RODC, op)
    check(f"read-only DC's site: write {op} sent to the writable DC", why is None and reqs
          and reqs[0].get("server") == "10.0.9.5" and reqs[0]["op"] == op, (why, reqs))
for op in sorted(mod.READS):
    result, why, reqs = call(RODC, op)
    check(f"read-only DC's site: read {op} answered by the site's own DC", why is None and "server" not in reqs[0],
          reqs)
result, why, reqs = call(RODC, "create_person", server="10.0.9.7")
check("a server the caller names is kept (the callers that already chose one)", reqs[0].get("server") == "10.0.9.7",
      reqs)
check("the agent's password goes on stdin, never the command line", reqs[0]["password"] == "agent-pw")

# at a writable DC's site: nothing changes, every operation at its own DC
for op in ("create_person", "remove_person", "set_person", "save_role", "write_plan", "list_people"):
    result, why, reqs = call(WRITABLE, op)
    check(f"writable DC's site: {op} at its own DC (no server)", why is None and "server" not in reqs[0], reqs)
result, why, reqs = call({"site_name": "lab"}, "create_person")
check("no DC type set: its own DC", why is None and "server" not in reqs[0], reqs)

# negatives: no writable DC known; the writable DC not answering; nothing changed
result, why, reqs = call({**RODC, "ad_join_server": ""}, "remove_person")
check("negative: a write at a read-only DC's site with no writable DC known: refused before anything is asked",
      result is None and "read-only" in why and "remove person" in why and not reqs, (why, reqs))
result, why, reqs = call({**RODC, "ad_join_server": ""}, "list_people")
check("...a read there still works (the site's own DC answers)", why is None and reqs, why)
result, why, reqs = call(RODC, "create_person", {"error": "connection refused", "kind": "unreachable"})
check("negative: the writable DC not answering: said plainly, naming it, nothing changed",
      result is None and "10.0.9.5 does not answer" in why and "nothing was changed" in why, why)
result, why, reqs = call(RODC, "create_person", {"error": "LDAP refused", "kind": "refused"})
check("negative: the writable DC refusing (not permitted): the usual refusal", why ==
      "the directory refused the change (not permitted for this site)", why)

# Group Policy: the editor works on the DC's own copy, so a change at a read-only DC's site is refused
for op in sorted(gpo.WRITES):
    try:
        gpo.gpo_request({"op": op, "site": "lab"}, "samba-not-asked", RODC)
        why = ""
    except ValidationError as e:
        why = str(e)
    check(f"negative: Group Policy {op} at a read-only DC's site: refused before the DC is asked, saying where",
          "read-only" in why and "site above" in why, why)
old = gpo.subprocess
asked = []
gpo.subprocess = types.SimpleNamespace(run=lambda cmd, **kw: asked.append(kw["input"]) or subprocess.CompletedProcess(
    cmd, 0, json.dumps({"result": []}) + "\n", ""))
try:
    shown = gpo.gpo_request({"op": "show", "site": "lab"}, "samba", RODC)
    gpo.gpo_request({"op": "set", "site": "lab"}, "samba", WRITABLE)
finally:
    gpo.subprocess = old
check("Group Policy reads at a read-only DC's site, and changes at a writable one, are asked of the DC",
      shown == [] and len(asked) == 2, asked)

# the container side: another DC that does not answer is "unreachable", not a refusal
dop = open(os.path.join(REPO, "src", "containers", "samba", "directory_op.py")).read()
check("directory_op: a sign-in at another DC that fails (not a wrong password) is kind unreachable",
      '"kind": "unreachable"' in dop and "ERR_INVALID_CREDENTIALS" in dop)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
