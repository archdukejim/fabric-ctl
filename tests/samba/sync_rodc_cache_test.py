"""Caching a read-only DC's site's people and machines (decision 2.1.6.55, manual 1.6.11.14, 4.6.5.6): the lists
checked first (the cache group allowed, the denied list whole) and nothing changed when they are not; the site's
cache group kept by the site's agent at the writable DC; the site's own accounts preloaded from it, one on the denied
list reported; another site's account reached through the site's groups refused loudly, never preloaded; and
`fabricctl domain rodc-cache`. Pure logic: the DC's container and the directory operation are stand-ins (the samba
suite runs the real ones, tests/samba/dc.py).
    python3 tests/samba/sync_rodc_cache_test.py"""
import contextlib
import io
import os
import subprocess
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.samba.sync_rodc_cache as mod  # noqa: E402
import fabriclib.samba.run_domain_command as cli  # noqa: E402

PASS = FAIL = 0
BASE = "DC=ad,DC=lan,DC=test"
SITE = f"OU=lab,OU=lan,OU=sites,{BASE}"
V = {"site_name": "lab", "ad_dc_type": "rodc", "ad_join_server": "10.0.9.5", "dc_name": "rodc1.ad.lan.test",
     "ad_domain": "ad.lan.test"}
ALLOW = [f"CN=Allowed RODC Password Replication Group,CN=Users,{BASE}", f"CN=lab-rodc-cache,OU=groups,{SITE}"]
NEVER = [f"CN=Denied RODC Password Replication Group,CN=Users,{BASE}", f"CN=Administrators,CN=Builtin,{BASE}",
         f"CN=Server Operators,CN=Builtin,{BASE}", f"CN=Backup Operators,CN=Builtin,{BASE}",
         f"CN=Account Operators,CN=Builtin,{BASE}"]
DENIED = [f"CN=Domain Admins,CN=Users,{BASE}", f"CN=Enterprise Admins,CN=Users,{BASE}",
          f"CN=Schema Admins,CN=Users,{BASE}", f"CN=krbtgt,CN=Users,{BASE}"]
ANN, HOST = f"CN=ann,OU=people,{SITE}", f"CN=LABHOST,OU=fabric-hosts,{SITE}"
BOSS = f"CN=boss,OU=people,{SITE}"


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


class Stand:
    """The read-only DC's container and the directory operation, as the test sets them; every call recorded."""

    def __init__(self, allow=ALLOW, never=NEVER, denied=DENIED, op=None, refused=(), preload_rc=0):
        self.allow, self.never, self.denied, self.refused, self.preload_rc = allow, never, denied, refused, preload_rc
        self.op = op if op is not None else {"added": [], "removed": [], "accounts": [ANN, HOST], "foreign": []}
        self.calls, self.ops, self.preloaded = [], [], None

    def run(self, cmd, **kw):
        self.calls.append(cmd)
        if "ldbsearch" in cmd:
            attr = cmd[-1]
            values = {"msDS-RevealOnDemandGroup": self.allow, "msDS-NeverRevealGroup": self.never,
                      "member": self.denied}[attr]
            out = f"# record 1\ndn: {cmd[cmd.index('-b') + 1]}\n" + "".join(f"{attr}: {x}\n" for x in values)
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if "preload" in cmd:
            self.preloaded = kw.get("input", "")
            out = "".join(f"Replicating DN {d}\n" for d in self.preloaded.split())
            err = "".join(f"\nPreload encountered problematic users:\n    Error replicating DN {d}\n"
                          for d in self.refused)
            return subprocess.CompletedProcess(cmd, self.preload_rc, out, err or ("boom" if self.preload_rc else ""))
        raise AssertionError(cmd)

    def run_op(self, v, secrets, op, args=None, container="samba", server=None):
        self.ops.append((op, args, container, server))
        return self.op


@contextlib.contextmanager
def stand(s):
    old_sub, old_op = mod.subprocess, mod.run_op
    mod.subprocess, mod.run_op = types.SimpleNamespace(run=s.run), s.run_op
    try:
        yield s
    finally:
        mod.subprocess, mod.run_op = old_sub, old_op


def sync(s, v=V):
    with stand(s):
        try:
            return mod.sync_rodc_cache(v, {"ad_agent_password": "x"}), None
        except ValidationError as e:
            return None, str(e)


# where the site's DC is not read-only: nothing at all
s = Stand()
check("a writable DC's site: nothing to do, nothing asked", sync(s, {**V, "ad_dc_type": "dc"}) == ([], None)
      and not s.calls and not s.ops)

# a read-only DC's site with the lists as needed: the group kept at the writable DC, the site's accounts preloaded
s = Stand(op={"added": [f"CN=lab-users,OU=groups,{SITE}", f"CN=LABPC,OU=machines,{SITE}"],
              "removed": [f"CN=GONE,OU=machines,OU=old,OU=sites,{BASE}"], "accounts": [ANN, HOST], "foreign": []})
lines, why = sync(s)
check("the cache group kept by the site's agent at the writable DC (ad_join_server), never at the read-only DC",
      s.ops == [("sync_rodc_cache", {}, "samba", "10.0.9.5")], s.ops)
check("...what changed is said: groups and machines added, a machine no longer the site's taken out",
      why is None and "lab-rodc-cache: lab-users added" in lines and "lab-rodc-cache: LABPC added" in lines
      and "lab-rodc-cache: GONE taken out (no longer the site's)" in lines, (lines, why))
pre = next(c for c in s.calls if "preload" in c)
check("...the site's own accounts preloaded from the writable DC, as DNs on stdin (never a long command line)",
      s.preloaded.split("\n")[:2] == [ANN, HOST] and "--file=-" in pre and "--server=10.0.9.5" in pre
      and ANN not in pre, pre)
check("...and the count said", "read-only DC: 2 of the site's accounts cached" in lines, lines)
check("...the lists read from the read-only DC's own copy (no credentials, no network)",
      all("/data/private/sam.ldb" in c for c in s.calls if "ldbsearch" in c)
      and any(f"CN=RODC1,OU=Domain Controllers,{BASE}" in c for c in s.calls), s.calls)

# a second run: nothing to change; the preload only refreshes
s = Stand()
lines, why = sync(s)
check("a second run changes no membership (nothing added or taken out)",
      why is None and not [x for x in lines if "added" in x or "taken out" in x], lines)

# a Domain Admin nested in the site's admins: the denied list refuses the preload; reported, not retried
s = Stand(op={"added": [], "removed": [], "accounts": [ANN, BOSS], "foreign": []}, refused=[BOSS])
lines, why = sync(s)
check("an account the denied list refuses (a Domain Admin among the site's admins) is reported, never cached",
      why is None and f"read-only DC: not cached (refused by its denied list): {BOSS}" in lines
      and "read-only DC: 1 of the site's accounts cached" in lines, (lines, why))

# negatives: nothing changed when the lists are not as fabric needs them
s = Stand(allow=ALLOW[:1])
lines, why = sync(s)
check("negative: the cache group not on the allow list (a site joined before 0.7.1): refused, saying what to do, "
      "nothing changed", lines is None and "lab-rodc-cache is not on" in why and "join account" in why
      and not s.ops and s.preloaded is None, why)
s = Stand(never=NEVER[1:])
lines, why = sync(s)
check("negative: the denied list without the Denied RODC Password Replication Group: refused, nothing changed",
      lines is None and "denied rodc password replication group" in why and not s.ops and s.preloaded is None, why)
s = Stand(denied=DENIED[1:])
lines, why = sync(s)
check("negative: Domain Admins taken out of the denied group: refused (the denied list is never weakened)",
      lines is None and "domain admins (in denied rodc password replication group)" in why and not s.ops, why)
lines, why = sync(Stand(), {**V, "ad_join_server": ""})
check("negative: no writable DC known: refused before anything is read or written", lines is None
      and "ad_join_server" in why, why)
s = Stand(preload_rc=1)
lines, why = sync(s)
check("negative: the preload failing (the writable DC not answering): refused, saying where", lines is None
      and "10.0.9.5" in why, why)

# an account of another site reached through the site's groups: never preloaded, refused loudly after the rest
OTHER = f"CN=eve,OU=people,OU=lan,OU=sites,{BASE}"
s = Stand(op={"added": [], "removed": [], "accounts": [ANN], "foreign": [[OTHER, f"CN=lab-users,OU=groups,{SITE}"]]})
lines, why = sync(s)
check("negative: another site's person nested in the site's users: named with the group to remove them from, "
      "never preloaded (the site's own still are)", lines is None and OTHER in why and "through lab-users" in why
      and OTHER not in (s.preloaded or "") and ANN in (s.preloaded or ""), (why, s.preloaded))


# fabricctl domain rodc-cache
def run_cli(v, args, result=None, error=None):
    old = cli.sync_rodc_cache

    def fake(v):
        if error:
            raise ValidationError(error)
        return result or []
    cli.sync_rodc_cache = fake
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            code = cli.run_domain_command(v, ["rodc-cache", *args])
    finally:
        cli.sync_rodc_cache = old
    return code, out.getvalue()


# covers: cli:domain.rodc-cache +
code, out = run_cli(V, [], ["lab-rodc-cache: lab-users added", "read-only DC: 3 of the site's accounts cached"])
check("fabricctl domain rodc-cache: done, each line said", code == 0 and "lab-users added" in out
      and "3 of the site's accounts cached" in out, out)
code, out = run_cli({**V, "ad_dc_type": "dc"}, ["--scheduled"])
check("...--scheduled (the timer) at a writable DC's site: nothing to do, exit 0", code == 0
      and out.startswith("nothing to do"), out)
# covers: cli:domain.rodc-cache -
code, out = run_cli({**V, "ad_dc_type": "dc"}, [])
check("negative: by hand at a writable DC's site: refused, saying why", code == 1 and out.startswith("refused")
      and "not read-only" in out, out)
code, out = run_cli(V, [], error="lab-rodc-cache is not on this site's read-only DC's password replication allow list")
check("negative: the sync refused: refused, its reason said, exit 1", code == 1 and "allow list" in out, out)
code, out = run_cli(V, ["--now"])
check("negative: an unknown option: the usage, exit 2", code == 2 and "rodc-cache [--scheduled]" in out, out)

# the timer is installed only at a read-only DC's site
import fabriclib.deploy.install_timers as timers  # noqa: E402
flags = timers.OPTIONAL["fabric-rodc-cache"]
check("fabric-rodc-cache.timer: on at a read-only DC's site, off elsewhere",
      all(f(V) for f in flags) and not all(f({**V, "ad_dc_type": "dc"}) for f in flags))
repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
unit = open(os.path.join(repo, "templates", "systemd", "fabric-rodc-cache.service")).read()
check("...its service runs `fabricctl domain rodc-cache --scheduled`",
      "ExecStart=/usr/bin/fabricctl domain rodc-cache --scheduled" in unit)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
