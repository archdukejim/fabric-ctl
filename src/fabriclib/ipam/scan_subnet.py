import contextlib
import datetime
import fcntl
import ipaddress
import json
import os
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.common.plan_cache import load_plan_cache
from fabriclib.ipam.common.probe_subnet import KEA_CONTAINER, probe_subnet
from fabriclib.ipam.plan_rows import plan_rows
from fabriclib.ipam.planned_subnets import planned_subnets
from fabriclib.ipam.scannable_subnets import LARGEST

STATE_DIR = "/run/fabric-ipam-scan"   # root's, 0700: the lock and when each subnet was last scanned (gone at boot)
COOLDOWN = 60                         # seconds before the same subnet is scanned again
RECORDED = ("gateway", "static", "reservation", "infrastructure")


def _which(v, text):
    """Purpose: the subnet a scan names, by its name or its exact network, among those this site's Kea serves.
    Inputs:  v — fabric vars; text — what was typed.
    Returns: {"name", "cidr", "entry"}: the served subnet, entry its dhcp.subnets form (reservations, routers).
    Fails:   ValidationError: nothing typed, DHCP off, a network written wrong, one fabric does not serve (named),
             one larger than a /22.
    Feeds:   scan_subnet."""
    text = str(text or "").strip()
    if not text:
        raise ValidationError("name the subnet to scan: its name or its network (fabricctl ipam show lists them)")
    if not v.get("install_kea"):
        raise ValidationError("DHCP is off: fabric serves no subnet to scan")
    served = [{"name": str(s.get("name") or ""), "cidr": str(ipaddress.ip_network(str(s.get("subnet")),
                                                                               strict=False)), "entry": s}
              for s in planned_subnets(v)]
    if "/" in text:
        try:
            net = str(ipaddress.ip_network(text, strict=True))
        except ValueError:
            raise ValidationError(f"{text!r} is not a network like 10.1.20.0/24 (host bits zero)")
        found = [s for s in served if s["cidr"] == net]
    else:
        found = [s for s in served if s["name"] and s["name"] == text.lower()]
    if not found:
        raise ValidationError(f"{text} is not a subnet this site's DHCP serves: only those are scanned "
                              f"({', '.join(s['cidr'] for s in served) or 'none'})")
    net = ipaddress.ip_network(found[0]["cidr"])
    if net.num_addresses - 2 > LARGEST:
        raise ValidationError(f"{net} is larger than a /22: at most {LARGEST} addresses are scanned at once")
    return found[0]


@contextlib.contextmanager
def _slot(cidr, state_dir):
    """Purpose: one scan at a time on the host, and the same subnet at most once a minute (decision 2.1.10.26).
    Inputs:  cidr — the subnet; state_dir — where the lock and the last scan times are kept.
    Returns: a context manager; leaving it records the scan's time.
    Fails:   ValidationError: another scan running, or this subnet scanned less than COOLDOWN seconds ago (how long
             to wait); OSError writing the state.
    Feeds:   scan_subnet."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(state_dir, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValidationError("another scan is running: try again when it ends")
        path = os.path.join(state_dir, "last.json")
        try:
            with open(path) as f:
                last = json.load(f)
        except (FileNotFoundError, ValueError):
            last = {}
        ago = time.time() - float(last.get(cidr, 0))
        if ago < COOLDOWN:
            raise ValidationError(f"{cidr} was scanned {int(ago)} s ago: scan it again in {int(COOLDOWN - ago) + 1} s")
        yield
        last[cidr] = time.time()
        with open(path + ".new", "w") as f:
            json.dump(last, f)
        os.replace(path + ".new", path)
    finally:
        os.close(fd)


def _classify(ip, seen, row):
    """Purpose: one answering address beside what the plan and Kea know of it.
    Inputs:  ip — str; seen — probe_subnet's {"ping", "mac"}; row — plan_rows' row for it, or None.
    Returns: {"ip", "mac", "how" (ping, arp or ping+arp), "status" (recorded, lease or unrecorded), "kind", "name",
             "note"}.
    Fails:   never.
    Feeds:   scan_subnet."""
    how = "+".join(w for w, on in (("ping", seen["ping"]), ("arp", bool(seen["mac"]))) if on)
    out = {"ip": ip, "mac": seen["mac"], "how": how, "status": "unrecorded", "kind": "", "name": "", "note": ""}
    if row and row["kind"] in RECORDED:
        out.update(status="recorded", kind=row["kind"], name=row["name"])
        if row["mac"] and seen["mac"] and row["mac"].lower() != seen["mac"]:
            out["note"] = f"answered from {seen['mac']}, not the plan's {row['mac']}"
    elif row and row["kind"] == "lease" and not row["lease"].startswith("declined"):
        out.update(status="lease", kind="lease", name=row["name"])
    elif row:
        out["note"] = "Kea declined it: it answered Kea's ping before an offer"
    return out


def scan_subnet(v, actor, subnet, source="cli", container=KEA_CONTAINER, state_dir=STATE_DIR, probe=None,
                leases=None):
    """Purpose: scan one subnet on request (manual 1.10.4.22, decisions 2.1.10.13 and 2.1.10.26): which addresses
             answer, and which of them nobody recorded — neither a gateway, static, reservation or infrastructure
             address of the plan nor an active lease ("in use, unrecorded", with the MAC when ARP saw it), so the
             admin may make one a reservation. It only informs: nothing is recorded or blocked. Only a subnet this
             site's Kea serves, at most a /22, one scan at a time, the same subnet once a minute; audited.
    Inputs:  v — fabric vars (install_kea, dhcp, site_name); actor — who asks (audit); subnet — its name or exact
             network; source — "cli" or "web"; container — Kea's container; state_dir — the lock's folder; probe —
             function(cidr, container) -> probe_subnet's result (tests); leases — list_leases' rows (default: Kea's,
             none when Kea does not answer).
    Returns: {"subnet": {"name", "cidr"}, "scanned" (int, addresses probed), "answering": [_classify's rows],
             "unrecorded" (int), "at" (ISO time)}.
    Fails:   ValidationError: _which's refusals, _slot's (a scan running, too soon), probe_subnet's; OSError from the
             audit log or the state folder.
    Feeds:   run_ipam_command (scan); agent POST /v1/ipam/scan."""
    sub = _which(v, subnet)
    net = ipaddress.ip_network(sub["cidr"])
    if leases is None:
        try:
            leases = list_leases(v)
        except (ValidationError, OSError, ValueError, TypeError):
            leases = []
    with _slot(sub["cidr"], state_dir):
        seen = (probe or probe_subnet)(sub["cidr"], container)
    plan = load_plan_cache() or {"site": v.get("site_name", ""), "vlans": [], "subnets": []}
    rows = {r["ip"]: r for r in plan_rows(plan, leases) if ipaddress.ip_address(r["ip"]) in net}
    entry = sub.pop("entry")          # what Kea serves: a site not yet upgraded keeps its reservations there
    for r in entry.get("reservations") or []:
        rows.setdefault(r["ip"], {"ip": r["ip"], "kind": "reservation", "name": r.get("hostname") or "",
                                  "mac": r["mac"], "lease": ""})
    if entry.get("routers"):
        rows.setdefault(entry["routers"], {"ip": entry["routers"], "kind": "gateway", "name": "", "mac": "",
                                           "lease": ""})
    found = [_classify(ip, s, rows.get(ip)) for ip, s in seen.items() if ipaddress.ip_address(ip) in net]
    unrecorded = sum(1 for f in found if f["status"] == "unrecorded")
    write_audit(actor, "IPAM_SCAN", f"site={v.get('site_name', '')} subnet={sub['cidr']} answering={len(found)} "
                f"unrecorded={unrecorded}", source)
    return {"subnet": sub, "scanned": net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses,
            "answering": found, "unrecorded": unrecorded,
            "at": datetime.datetime.now().isoformat(timespec="seconds")}
