"""The scan's one contact with the network (decision 2.1.10.26): ping and the neighbour table, run inside Kea's own
container (host network, NET_RAW already granted for DHCP) by fixed argument lists, never a shell string."""
import ipaddress
import subprocess

from fabriclib.common.errors import ValidationError

KEA_CONTAINER = "kea-dhcp4"
# one probe every 10 ms, one retry, 500 ms to answer: a /24 in about 3 s, a /22 (the largest scanned) in about 12 s
FPING = ["fping", "-a", "-r", "1", "-t", "500", "-i", "10", "-g"]
TIMEOUT = 120


def _exec(container, argv):
    """Purpose: run one fixed command inside a container (docker exec with an argument list: nothing a shell parses).
    Inputs:  container — the container's name; argv — list of str.
    Returns: subprocess.CompletedProcess (text).
    Fails:   ValidationError when docker is missing, the container is not running, or the command times out.
    Feeds:   probe_subnet."""
    try:
        res = subprocess.run(["docker", "exec", container, *argv], capture_output=True, text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        raise ValidationError("docker is not installed: the scan runs inside Kea's container")
    except subprocess.TimeoutExpired:
        raise ValidationError(f"the scan did not finish in {TIMEOUT} s: nothing was recorded")
    if res.returncode != 0 and "No such container" in res.stderr + res.stdout:
        raise ValidationError(f"Kea's container ({container}) is not running: start DHCP first "
                              "(sudo fabricctl dhcp on)")
    return res


def _neighbours(text, net):
    """Purpose: the complete entries of the kernel's neighbour table (/proc/net/arp) inside a network.
    Inputs:  text — /proc/net/arp's content; net — IPv4Network.
    Returns: {ip str: mac str (lower case)}.
    Fails:   never: a line that is not an entry is skipped.
    Feeds:   probe_subnet."""
    found = {}
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 4:
            continue
        try:
            ip, flags = ipaddress.ip_address(f[0]), int(f[2], 16)
        except ValueError:
            continue
        mac = f[3].lower()
        if ip in net and flags & 0x2 and mac != "00:00:00:00:00:00":
            found[str(ip)] = mac
    return found


def probe_subnet(cidr, container=KEA_CONTAINER):
    """Purpose: which addresses of a network answer (manual 1.10.4.21, decision 2.1.10.26): fping over the network
             from Kea's container (rate-limited by its flags), then the neighbour table as the kernel holds it after
             (a device on a network the host is on answers ARP even when it drops pings; a routed VLAN shows only
             what its gateway lets ping through, and no MAC).
    Inputs:  cidr — the checked network (str, host bits zero; the caller decides it may be scanned); container — Kea's
             container (tests name their own).
    Returns: {ip: {"ping": bool, "mac": str ("" when ARP did not see it)}} for every address that answered either way.
    Fails:   ValidationError: docker or the container missing, a timeout, fping missing from Kea's image (an image
             older than 0.8.0: update it) or failing (its exit status 2 or more, with its message).
    Feeds:   ipam/scan_subnet."""
    net = ipaddress.ip_network(cidr, strict=True)
    res = _exec(container, [*FPING, str(net)])
    if res.returncode >= 2 or "executable file not found" in res.stderr + res.stdout:
        if "not found" in res.stderr + res.stdout:
            raise ValidationError("Kea's image has no fping (an image older than 0.8.0): update Kea's image, then scan")
        raise ValidationError(f"fping failed ({res.returncode}): {(res.stderr or res.stdout).strip()[-300:]}")
    alive = set()
    for line in res.stdout.splitlines():
        try:
            ip = ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        if ip in net:
            alive.add(str(ip))
    arp = _exec(container, ["cat", "/proc/net/arp"])
    seen = _neighbours(arp.stdout if arp.returncode == 0 else "", net)
    return {ip: {"ping": ip in alive, "mac": seen.get(ip, "")} for ip in sorted(alive | set(seen),
                                                                                key=ipaddress.ip_address)}
