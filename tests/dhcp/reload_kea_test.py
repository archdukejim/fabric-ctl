#!/usr/bin/env python3
"""Kea takes a changed file by `config-reload` over its control socket, a restart only when a daemon does not take
it (decision 2.1.10.45, manual 1.10.4.42); Kea's control sockets stood in for (the real daemons: tests/kea/reload.py).

    python3 tests/dhcp/reload_kea_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.reload_kea import reload_kea  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

FAILED = 0
V = {"deploy_base_dir": "/nowhere"}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def kea(refuse=()):
    """A stand-in for kea_command: records each command, refuses for the daemons named."""
    sent = []

    def command(v, cmd, daemon="dhcp4"):
        sent.append((cmd, daemon))
        if daemon in refuse:
            raise ValidationError(f"Kea refused {cmd}: Configuration parsing failed")
        return {}
    return command, sent


def restarter(fail=False):
    done = []

    def restart(unit, container, restart=False):
        done.append((unit, container, restart))
        if fail:
            raise SetupError("kea did not become healthy within 60 s")
    return restart, done


command, sent = kea()
restart, done = restarter()
out = reload_kea(V, {"kea-dhcp-ddns.conf", "kea-dhcp4.conf"}, command=command, restart=restart)
check("both files changed: config-reload to kea-dhcp4, then kea-dhcp-ddns; nothing restarted",
      sent == [("config-reload", "dhcp4"), ("config-reload", "ddns")] and not done
      and out == {"reloaded": ["dhcp4", "ddns"], "restarted": False, "why": ""}, (sent, done, out))
command, sent = kea()
out = reload_kea(V, {"kea-dhcp-ddns.conf"}, command=command, restart=restart)
check("only the DDNS file changed (Kea's key replaced, 2.1.10.42): kea-dhcp-ddns alone reloaded",
      sent == [("config-reload", "ddns")] and out["reloaded"] == ["ddns"] and not done, (sent, out))
command, sent = kea(refuse=("dhcp4",))
restart, done = restarter()
out = reload_kea(V, {"kea-dhcp4.conf", "kea-dhcp-ddns.conf"}, command=command, restart=restart)
check("a daemon that does not take the reload: Kea restarted instead (health-checked), saying why; the rest not "
      "reloaded after it", out["restarted"] is True and done == [("kea", "kea-dhcp4", True)]
      and sent == [("config-reload", "dhcp4")] and "kea-dhcp4 did not reload" in out["why"], (out, done, sent))
command, sent = kea(refuse=("ddns",))
restart, done = restarter(fail=True)
try:
    reload_kea(V, {"kea-dhcp-ddns.conf"}, command=command, restart=restart)
    check("refused loudly: Kea not healthy after the fallback restart", False)
except ValidationError as e:
    check("refused loudly: Kea not healthy after the fallback restart, naming why it was restarted",
          "did not come back healthy" in str(e) and "kea-ddns did not reload" in str(e), e)
command, sent = kea()
out = reload_kea(V, set(), command=command, restart=restart)
check("nothing changed: nothing sent", sent == [] and out == {"reloaded": [], "restarted": False, "why": ""}, out)
check("the sockets: kea-dhcp4's in run/, kea-dhcp-ddns's in run-ddns/ (shared with the host since 2.1.10.45)",
      __import__("fabriclib.dhcp.kea_command", fromlist=["SOCKETS"]).SOCKETS
      == {"dhcp4": ("run", "kea4-ctrl-socket"), "ddns": ("run-ddns", "kea-ddns-ctrl-socket")})
try:
    from fabriclib.dhcp.kea_command import kea_command
    kea_command({"deploy_base_dir": "/nonexistent-fabric"}, "config-reload", daemon="ddns", timeout=1)
    check("no socket: refused, saying Kea is not answering", False)
except ValidationError as e:
    check("no socket: refused, saying Kea is not answering", "Kea is not answering" in str(e), e)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
