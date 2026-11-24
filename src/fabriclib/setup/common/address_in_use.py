import re
import shutil
import subprocess

from fabriclib.common.errors import ValidationError

REPLY = re.compile(r"reply from \S+ \[([0-9A-Fa-f:]{17})\]")
# arping runs as a unit of its own with CAP_NET_RAW only: the agent's sandbox (RestrictAddressFamilies) has no packet
# socket, and stays so (1.2.8); the unit's user is a throwaway one.
PROBE_UNIT = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "-p", "DynamicUser=yes",
              "-p", "AmbientCapabilities=CAP_NET_RAW", "-p", "CapabilityBoundingSet=CAP_NET_RAW",
              "-p", "RestrictAddressFamilies=AF_PACKET AF_INET AF_UNIX AF_NETLINK", "-p", "RuntimeMaxSec=8", "--"]


def _interface_of(ip, run):
    """Purpose: the interface that holds an address.
    Inputs:  ip — str; run — subprocess.run.
    Returns: str, the interface's name, or None when no interface holds it.
    Fails:   FileNotFoundError when `ip` is missing.
    Feeds:   address_in_use."""
    out = run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[3].split("/")[0] == ip:
            return fields[1]
    return None


def address_in_use(ip, run=subprocess.run, which=shutil.which):
    """Purpose: whether another machine answers at an address this host holds (manual 1.3.7.7, decision 2.1.1.107;
             global Rule 9): a duplicate-address probe, `arping -D`, on the interface that holds it.
    Inputs:  ip — the address (str), one this host has (network_problem checks that first); run, which —
             subprocess.run and shutil.which (tests give their own).
    Returns: str, the MAC address that answered; "" when none did, or when no interface holds the address (nothing
             to probe from: network_problem refuses that). arping runs as a transient unit (systemd-run) with
             CAP_NET_RAW only, so callers in a sandbox without packet sockets (the agent) can still probe.
    Fails:   ValidationError when `arping` is not installed (never skipped: it comes with the package's dependency
             iputils-arping), or when the probe itself fails.
    Feeds:   backup/check_whole_restore, setup/run_reinstall_command."""
    try:
        iface = _interface_of(ip, run)
    except FileNotFoundError:
        return ""
    if iface is None:
        return ""
    missing = ValidationError("arping is not installed, so the new address cannot be checked for another machine "
                              "using it: sudo apt install iputils-arping")
    if which("arping") is None:
        raise missing
    try:
        res = run(PROBE_UNIT + ["arping", "-D", "-c", "2", "-w", "3", "-I", iface, ip], capture_output=True, text=True,
                  stdin=subprocess.DEVNULL, timeout=12)
    except FileNotFoundError:
        raise missing from None
    except subprocess.TimeoutExpired:
        raise ValidationError(f"the new address could not be checked for another machine using it (arping on {iface} "
                              "did not finish)") from None
    if res.returncode == 0:
        return ""
    if res.returncode != 1:                  # 1: a reply came; anything else: the probe itself failed
        why = (res.stderr or res.stdout or "").strip().splitlines()
        raise ValidationError(f"the new address could not be checked for another machine using it (arping on "
                              f"{iface}: {why[-1] if why else f'exit {res.returncode}'})")
    found = REPLY.search(res.stdout or "")
    return found.group(1).lower() if found else "an unknown machine"
