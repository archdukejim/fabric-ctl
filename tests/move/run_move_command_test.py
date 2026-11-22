#!/usr/bin/env python3
"""`fabricctl move prepare <address> [--network <subnet>]` (move/run_move_command; manual 4.2.4.8): the words read,
the network passed on and audited, a wrong form refused with the usage. The DC stood in for: the real announce is
tests/samba/linux_join.py's.

    python3 tests/move/run_move_command_test.py
"""
import contextlib
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.move.run_move_command as rmc  # noqa: E402

FAILED = 0
V = {"site_name": "hq", "dc_name": "dc-0001", "host_ip": "10.77.0.10", "lan_cidr": "10.77.0.0/24",
     "lan_gateway": "10.77.0.1"}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


sent, audits = [], []
rmc.move_request = lambda request, container="samba": sent.append(request) or {"changed": True, "done": []}


def run(args):
    sent.clear()
    audits.clear()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = rmc.run_move_command(V, args, registry={}, audit=lambda *a: audits.append(a))
    return code, out.getvalue()


code, out = run(["prepare", "10.79.0.10", "--network", "10.79.0.0/24"])
# covers: cli:move.prepare +
check("positive: another subnet named: announced, audited with its network, pointing to 4.2.4.8 and the route",
      code == 0 and sent and sent[0]["new"] == "10.79.0.10" and "network=10.79.0.0/24" in audits[0][2]
      and "4.2.4.8" in out and "route" in out, (code, sent, audits, out))
code, out = run(["prepare", "--network", "10.79.0.0/24", "10.79.0.10"])
check("positive: --network before the address reads the same", code == 0 and sent[0]["new"] == "10.79.0.10", out)
code, out = run(["prepare", "10.77.0.13"])
check("positive: an address on the LAN, as before: 4.2.4.2", code == 0 and "4.2.4.2" in out
      and "network=" not in audits[0][2], (out, audits))
code, out = run(["prepare", "10.79.0.10"])
# covers: cli:move.prepare -
check("negative: off the LAN without --network: refused, nothing announced", code == 1 and not sent
      and "--network" in out, out)
code, out = run(["prepare", "10.79.0.10", "--network"])
check("negative: --network with no value: the usage, nothing announced", code == 2 and not sent, out)
code, out = run(["status", "--network", "10.79.0.0/24"])
check("negative: --network on another operation: the usage", code == 2 and not sent, out)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
