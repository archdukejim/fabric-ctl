#!/usr/bin/env python3
"""Another machine answering at the host's address (setup/common/address_in_use; manual 1.3.7.7, decision 2.1.1.107),
probed for real: a second machine is a network namespace on a veth pair, as root, with the package's arping; then the
refusals when the probe cannot run (stood in for: no arping, a failing arping).

    sudo python3 tests/setup/common/address_in_use_test.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.setup.common.address_in_use import address_in_use  # noqa: E402

FAILED = 0
NS, HOST, PEER = "fabtest-arp", "fabtest-arp0", "fabtest-arp1"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def sh(*cmd):
    return subprocess.run(list(cmd), capture_output=True, text=True)


def refused(run):
    try:
        address_in_use("10.231.0.1", run=run)
    except ValidationError as exc:
        return str(exc)
    return None


def stand_in(arping):
    """ip's real answer for 10.231.0.1 on HOST; arping as given."""
    def run(cmd, **kw):
        if cmd[0] == "ip":
            return subprocess.CompletedProcess(cmd, 0, f"5: {HOST}    inet 10.231.0.1/24 scope global {HOST}\n", "")
        return arping(cmd)
    return run


def missing(cmd):
    raise FileNotFoundError(cmd[0])


if os.geteuid() != 0:
    sys.exit("run as root (sudo): the probe needs a network namespace and a raw socket")
sh("ip", "netns", "del", NS)
sh("ip", "link", "del", HOST)
try:
    for cmd in (["ip", "netns", "add", NS], ["ip", "link", "add", HOST, "type", "veth", "peer", "name", PEER],
                ["ip", "link", "set", PEER, "netns", NS], ["ip", "addr", "add", "10.231.0.1/24", "dev", HOST],
                ["ip", "link", "set", HOST, "up"],
                ["ip", "-n", NS, "addr", "add", "10.231.0.2/24", "dev", PEER], ["ip", "-n", NS, "link", "set", PEER, "up"]):
        res = sh(*cmd)
        if res.returncode != 0:
            sys.exit(f"could not make the test network ({' '.join(cmd)}): {res.stderr.strip()}")
    peer_mac = sh("ip", "-n", NS, "-o", "link", "show", PEER).stdout.split("link/ether ")[1].split()[0].lower()

    check("positive: an address no other machine answers at: free", address_in_use("10.231.0.1") == "")
    check("an address no interface here holds: nothing to probe from (network_problem refuses it first)",
          address_in_use("10.231.0.99") == "")
    sh("ip", "addr", "add", "10.231.0.7/24", "dev", HOST)
    sh("ip", "-n", NS, "addr", "add", "10.231.0.7/24", "dev", PEER)
    got = address_in_use("10.231.0.7")
    check("negative: the second machine holds it too: in use, naming its MAC address", got == peer_mac,
          (got, peer_mac))
    # the agent's own sandbox has no packet socket (fabric-agent.service): the probe, run from inside one, still works
    agent = sh("systemd-run", "--quiet", "--wait", "--pipe", "--collect",
               "-p", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", "-p", "NoNewPrivileges=yes",
               "--", sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
               "from fabriclib.setup.common.address_in_use import address_in_use as a; print(a('10.231.0.7'))",
               os.path.join(ROOT, "src"))
    check("negative: ...probed from the agent's sandbox (no packet sockets there): still found, naming its MAC",
          agent.stdout.strip() == peer_mac, (agent.returncode, agent.stdout, agent.stderr))
finally:
    sh("ip", "link", "del", HOST)
    sh("ip", "netns", "del", NS)

err = refused(stand_in(missing))
check("negative: no arping: refused, never skipped, saying what to install", err and "iputils-arping" in err, err)
try:
    address_in_use("10.231.0.1", run=stand_in(lambda cmd: None), which=lambda name: None)
    err = None
except ValidationError as exc:
    err = str(exc)
check("negative: ...found missing before the probe's unit starts (inside it, it would be only exit 203)",
      err and "iputils-arping" in err, err)
err = refused(stand_in(lambda cmd: subprocess.CompletedProcess(cmd, 2, "", "arping: socket: Operation not permitted")))
check("negative: arping failing (not a reply): refused with its words", err and "Operation not permitted" in err, err)


def slow(cmd):
    raise subprocess.TimeoutExpired(cmd, 10)


err = refused(stand_in(slow))
check("negative: arping not finishing: refused", err and "did not finish" in err, err)
check("a reply arping printed no MAC for: still in use", address_in_use(
    "10.231.0.1", run=stand_in(lambda cmd: subprocess.CompletedProcess(cmd, 1, "", ""))) == "an unknown machine")
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
