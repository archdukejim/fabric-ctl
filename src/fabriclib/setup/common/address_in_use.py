import re
import subprocess

from fabriclib.common.errors import ValidationError

REPLY = re.compile(r"reply from \S+ \[([0-9A-Fa-f:]{17})\]")


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


def address_in_use(ip, run=subprocess.run):
    """Purpose: whether another machine answers at an address this host holds (manual 1.3.7.7, decision 2.1.1.107;
             global Rule 9): a duplicate-address probe, `arping -D`, on the interface that holds it.
    Inputs:  ip — the address (str), one this host has (network_problem checks that first); run — subprocess.run.
    Returns: str, the MAC address that answered; "" when none did, or when no interface holds the address (nothing
             to probe from: network_problem refuses that).
    Fails:   ValidationError when `arping` is not installed (never skipped: it comes with the package's dependency
             iputils-arping), or when the probe itself fails.
    Feeds:   backup/check_whole_restore, setup/run_reinstall_command."""
    try:
        iface = _interface_of(ip, run)
    except FileNotFoundError:
        return ""
    if iface is None:
        return ""
    try:
        res = run(["arping", "-D", "-c", "2", "-w", "3", "-I", iface, ip], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        raise ValidationError("arping is not installed, so the new address cannot be checked for another machine "
                              "using it: sudo apt install iputils-arping") from None
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
