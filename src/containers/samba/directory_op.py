"""Run one directory operation for fabric-agent (manual 1.6.3, 1.6.5.16), inside the DC, signed in over LDAP as the
DC's fabric-agent account (fabric-agent-<dc>, 2.1.6.82) — so AD's ACLs apply to it (1.6.13.2) — never as the system.
    docker exec -i samba python3 /fabric/directory_op.py < request.json
    docker exec -i samba python3 /fabric/directory_op.py --serve      (fabric-agent's held process, 2.1.8.35)
The request on stdin (never a command line: it holds the account's password): {"op", "args" {…}, "site", "dc" (the
DC asking, dc-NNNN: the record ids are taken from), "account", "password", optional "server" (another DC's address: a
read-only DC's site writes at its writable partner, 2.1.6.52)}. Prints one JSON object: {"result": …} or {"error":
message, "kind": refused|exists|missing|rejected|invalid|other} (exit 0 either way: the caller maps the kind to its
own errors). An operation's own refusal (a ValueError: "no such user: …") is kind "invalid", its message meant for the
person asking. With --serve: one request a line on stdin, one such object a line on stdout, until stdin ends or nothing
has come for IDLE_SECONDS; a request may instead be {"local": one of LOCAL_READS}, the DC's own database read as the
system, as those scripts do alone, or {"tool": one of TOOLS, "request": its request}, answered as that script
answers."""
import importlib
import inspect
import json
import os
import select
import sys
import time

import ldb
from samba.credentials import DONT_USE_KERBEROS, Credentials
from samba.param import LoadParm
from samba.samdb import SamDB

from directory_ops import OPS

CONF = "/data/etc/smb.conf"
FILES = "/fabric"
IDLE_SECONDS = 300          # a held process nobody asks gives its memory back (it counts in the DC's limit)
REUSE_SECONDS = 60          # a sign-in is kept this long: its groups are fixed when it is made (1.8.8.2)
LOCAL_READS = {"read_site_tree", "read_sites", "read_replication", "read_dc_names", "read_conflicts"}
TOOLS = {"grants_tool", "gpo_tool"}
# LDAP result codes -> what the caller is told
KINDS = {ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS: "refused", ldb.ERR_ENTRY_ALREADY_EXISTS: "exists",
         ldb.ERR_NO_SUCH_OBJECT: "missing", ldb.ERR_CONSTRAINT_VIOLATION: "rejected",
         ldb.ERR_OBJECT_CLASS_VIOLATION: "rejected", ldb.ERR_UNWILLING_TO_PERFORM: "refused"}


def connect(site, account, password, server="127.0.0.1"):
    """Purpose: the domain's database over LDAP, on loopback or at another DC, signed in as a site's account (NTLM:
             no Kerberos configuration needed inside the DC).
    Inputs:  site — str (for messages only); account — sAMAccountName; password — str; server — the DC's address
             (loopback: this DC).
    Returns: (SamDB, LoadParm).
    Fails:   ldb.LdbError when the sign-in is refused.
    Feeds:   run."""
    lp = LoadParm()
    lp.load(CONF)
    creds = Credentials()
    creds.guess(lp)
    creds.set_username(account)
    creds.set_password(password)
    creds.set_domain(lp.get("workgroup"))
    creds.set_kerberos_state(DONT_USE_KERBEROS)
    return SamDB(url=f"ldap://{server}", credentials=creds, lp=lp), lp


class HeldSignIn:
    """One sign-in kept between a held process's requests. Purpose: the connection reused while the same account asks
    within REUSE_SECONDS. Feeds: run, serve."""

    def __init__(self):
        """Purpose: nothing signed in yet.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   serve."""
        self.key, self.db, self.used = None, None, 0.0

    def connect(self, site, account, password, server="127.0.0.1"):
        """Purpose: the kept connection when it may be reused, otherwise a new one.
        Inputs:  as connect.
        Returns: (SamDB, LoadParm).
        Fails:   as connect.
        Feeds:   run."""
        key = (account, password, server)
        if self.key != key or time.monotonic() - self.used > REUSE_SECONDS:
            self.drop()
            self.db = connect(site, account, password, server)
            self.key = key
        self.used = time.monotonic()
        return self.db

    def drop(self):
        """Purpose: forget the connection, after an LDAP error or when it is too old.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   connect, run."""
        self.key, self.db = None, None


def run(request, signin=None):
    """Purpose: one operation of directory_ops.OPS, as the request's account; an operation that takes a `dc` (it
             takes ids from the DC's record, or names its groups) is given the request's.
    Inputs:  request — dict: op (a key of OPS), args (dict), site, dc, account, password, server (optional);
             signin — a held process's HeldSignIn, or None for a sign-in of its own.
    Returns: dict {"result": the operation's result} or {"error", "kind"}.
    Fails:   never for the directory's errors, which become {"error", "kind"} (an unknown op: kind "invalid").
    Feeds:   this script's main, serve."""
    op = OPS.get(request.get("op"))
    if op is None:
        return {"error": f"unknown directory operation {request.get('op')!r}", "kind": "invalid"}
    try:
        samdb, lp = (signin.connect if signin else connect)(request["site"], request["account"], request["password"],
                                                            request.get("server") or "127.0.0.1")
        args = dict(request.get("args") or {})
        if "dc" in inspect.signature(op).parameters:
            args["dc"] = request.get("dc") or ""
        return {"result": op(samdb, lp, request["site"], **args)}
    except ldb.LdbError as e:
        if signin:
            signin.drop()
        code, message = e.args[0], (e.args[1] if len(e.args) > 1 else str(e))
        return {"error": message, "kind": KINDS.get(code, "other")}
    except ValueError as e:
        return {"error": str(e), "kind": "invalid"}


def _stamp():
    """Purpose: what tells a held process its code was replaced (an update copies new files to the DC).
    Inputs:  none (FILES).
    Returns: a tuple of the Python files' names and times.
    Fails:   OSError when the folder cannot be read.
    Feeds:   serve."""
    return tuple(sorted((e.name, e.stat().st_mtime_ns) for e in os.scandir(FILES) if e.name.endswith(".py")))


def _local(name):
    """Purpose: one of LOCAL_READS, in this process.
    Inputs:  name — str.
    Returns: {"result": what the script prints} or {"error", "kind"}.
    Fails:   never for what the read raises (the caller reports it).
    Feeds:   serve."""
    if name not in LOCAL_READS:
        return {"error": f"unknown read {name!r}", "kind": "invalid"}
    try:
        return {"result": getattr(importlib.import_module(name), name)()}
    except Exception as e:      # as the script alone: reported by the caller, the DC keeps running
        return {"error": f"{type(e).__name__}: {e}", "kind": "other"}


def _tool(name, request):
    """Purpose: one request of one of TOOLS, in this process, answered as that script answers.
    Inputs:  name — str; request — the tool's request.
    Returns: {"result": …} or {"error": …}.
    Fails:   never for what the tool raises.
    Feeds:   serve."""
    if name not in TOOLS:
        return {"error": f"unknown tool {name!r}"}
    try:
        return {"result": importlib.import_module(name).run(request)}
    except Exception as e:      # the tool's own refusal shown as it is; anything else, its kind
        return {"error": str(e) if isinstance(e, ValueError) else f"{type(e).__name__}: {e}"}


def _answer(request, signin):
    """Purpose: whichever a held process's request asks for.
    Inputs:  request — dict; signin — HeldSignIn.
    Returns: the answer's dict.
    Fails:   as run.
    Feeds:   serve."""
    if "local" in request:
        return _local(request["local"])
    if "tool" in request:
        return _tool(request["tool"], request.get("request") or {})
    return run(request, signin)


def serve():
    """Purpose: fabric-agent's held process (manual 1.8.8.2, decision 2.1.8.35): the requests of many pages, in one
             Python process, with no `docker exec` or Python start for each. Anything an operation prints goes to
             stderr, so the answers stay one a line. When this script's files have changed it answers {"restart":
             true}, does nothing, and ends. An error that is not the directory's ends it, so the caller says what a
             crashed operation always said: the directory did not answer.
    Inputs:  none (stdin, one JSON request a line).
    Returns: None, when stdin ends or after IDLE_SECONDS with nothing asked.
    Fails:   whatever an operation raises beyond the directory's errors.
    Feeds:   this script's main."""
    out = os.fdopen(os.dup(1), "w")
    os.dup2(2, 1)
    stamp, signin = _stamp(), HeldSignIn()
    while select.select([0], [], [], IDLE_SECONDS)[0]:
        line = sys.stdin.readline()
        if not line:
            return
        if _stamp() != stamp:
            out.write(json.dumps({"restart": True}) + "\n")
            out.flush()
            return
        out.write(json.dumps(_answer(json.loads(line), signin)) + "\n")
        out.flush()


if __name__ == "__main__":
    if sys.argv[1:] == ["--serve"]:
        serve()
    else:
        print(json.dumps(run(json.load(sys.stdin))))
