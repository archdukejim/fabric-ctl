import ipaddress
import re

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_client_classes import normalize_client_classes
from fabriclib.dhcp.normalize_option_defs import normalize_option_defs
from fabriclib.dhcp.normalize_options import normalize_options

IFACE_RE = re.compile(r"^[A-Za-z0-9._-]{1,15}$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
NOTES_MAX = 500


def _pool(text, net):
    """Purpose: Parse one pool "first - last" and check that it lies in its subnet.
    Inputs:  text — str "a.b.c.d - a.b.c.e"; net — the subnet (ipaddress network).
    Returns: (first, last) as ipaddress addresses.
    Fails:   ValidationError "pool …: 'first - last' addresses" or "pool …: must lie inside …, first <= last".
    Feeds:   normalize_dhcp.
    """
    try:
        lo, hi = (ipaddress.ip_address(p.strip()) for p in str(text).split("-"))
    except ValueError:
        raise ValidationError(f"pool {text!r}: 'first - last' addresses")
    if not (lo in net and hi in net and lo <= hi):
        raise ValidationError(f"pool {text}: must lie inside {net}, first <= last")
    return lo, hi


def _is_v4(text):
    """Purpose: whether text is an IPv4 address.
    Inputs:  text — anything.
    Returns: bool.
    Fails:   never.
    Feeds:   normalize_dhcp (dhcp.ntp)."""
    try:
        return ipaddress.ip_address(str(text)).version == 4
    except ValueError:
        return False


def _subnet_ids(subnets):
    """Purpose: a stable Kea subnet id for every subnet: leases are tied to it, so it must not follow the list's
             order (removing a subnet would move another's leases).
    Inputs:  subnets — the dhcp.subnets entries (dicts), some with "id".
    Returns: list of ints, one per subnet: its own id; a subnet without one gets its position (1, 2, …) — what
             fabric rendered before ids were stored — unless taken, else the next free number.
    Fails:   ValidationError for an id that is not 1-4294967294 or used twice.
    Feeds:   normalize_dhcp."""
    taken = set()
    for s in subnets:
        if "id" in s:
            i = s["id"]
            if isinstance(i, bool) or not isinstance(i, int) or not 1 <= i <= 4294967294:
                raise ValidationError(f"dhcp subnet {s.get('subnet')}: id is a number from 1 to 4294967294")
            if i in taken:
                raise ValidationError(f"dhcp subnet id {i} is used twice")
            taken.add(i)
    ids = []
    for pos, s in enumerate(subnets, 1):
        if "id" in s:
            ids.append(s["id"])
            continue
        i = pos if pos not in taken else max(taken | set(ids) | {0}) + 1
        taken.add(i)
        ids.append(i)
    return ids


def normalize_dhcp(v):
    """Purpose: Check `dhcp:` (and that nothing static collides with it) before anything is rendered.
    Inputs:  v — the vars dict: install_kea; dhcp {interfaces (names up to 15 characters), subnets [{subnet (IPv4
             network, host bits zero), id (Kea's subnet id), name (one DNS label, unique), vlan (1-4094, unique: a
             record, fabric configures no switch), notes (at most 500 characters), allow_overlap (why it may
             overlap another site's network, at most 200 characters), access ("full", the default, or "guest":
             DNS and NTP only, 2.1.10.4), relay (the DHCP relay's address when it lies outside the subnet: Kea
             picks a relayed subnet by that address, manual 1.10.3.2), pools, routers, options,
             reservations [{mac, ip, hostname, options}]}], options (every subnet), option_defs, client_classes
             (manual 1.10.2.3), ddns_subdomain (one label, default dhcp), ntp (IPv4 addresses, default
             this host), lease_time (int 300-2592000, default 86400)}; dns (its A records); fabric_subnet
             (default 10.255.0.0/24: no DHCP subnet may overlap it).
    Returns: a copy of `dhcp`, unchecked, when install_kea is off; else `dhcp` normalized: every subnet with its id
             (_subnet_ids: existing installs keep the ids their position gave them), subnet as str, name/vlan/
             notes/options only when set, reservations with lower-case colon MACs and a hostname / options only
             when set; options, option_defs and client_classes normalized (left out when empty).
    Fails:   ValidationError for missing or bad interfaces, bad ddns_subdomain, bad lease_time, a bad or non-IPv4
             subnet, a subnet overlapping fabric_subnet, a bad or repeated id, name or vlan, notes or
             allow_overlap too long, an access that is not full or guest, a relay that is not an IPv4 address, a
             bad pool or two pools overlapping
             (in any subnet), a router outside its subnet, a bad MAC, a reservation outside its subnet (inside a
             pool it is allowed since 0.8.0, manual 1.10.4.3.2), a duplicate MAC or address, a bad hostname, no
             subnets, or a static A record inside a pool; a plain ValueError (not a ValidationError) if routers is
             not an IP address; errors of normalize_options, normalize_option_defs and normalize_client_classes.
    Feeds:   deploy/check_settings (apply, before rendering), add_reservation; tests/kea/run.py, tests/render.py.
    Notes:   a static A record inside a pool is refused because Kea would hand that address out.
    """
    d = dict(v.get("dhcp") or {})
    if not v.get("install_kea"):
        return d
    ifaces = d.get("interfaces") or []
    if not ifaces or not all(isinstance(i, str) and IFACE_RE.match(i) for i in ifaces):
        raise ValidationError("dhcp.interfaces: the host interface(s) to serve, e.g. [eth0]")
    if not LABEL_RE.match(str(d.get("ddns_subdomain", "dhcp"))):
        raise ValidationError("dhcp.ddns_subdomain: one DNS label, e.g. dhcp")
    ntp = d.get("ntp", [])
    if not isinstance(ntp, list) or not all(_is_v4(a) for a in ntp):
        raise ValidationError("dhcp.ntp: IPv4 addresses of the time servers handed out, e.g. [192.168.4.2]")
    lease = d.get("lease_time", 86400)
    if not isinstance(lease, int) or not 300 <= lease <= 2592000:
        raise ValidationError("dhcp.lease_time: seconds, 300 to 2592000")
    raw = d.get("subnets") or []
    if not isinstance(raw, list) or not all(isinstance(s, dict) for s in raw):
        raise ValidationError("dhcp.subnets: a list of subnets")
    subnets, pools_all, seen_ips, seen_macs, names, vlans = [], [], set(), set(), set(), set()
    fabric_net = ipaddress.ip_network(str(v.get("fabric_subnet") or "10.255.0.0/24"), strict=False)
    for s, sid in zip(raw, _subnet_ids(raw)):
        try:
            net = ipaddress.ip_network(str(s.get("subnet")), strict=True)
        except ValueError:
            raise ValidationError(f"dhcp subnet {s.get('subnet')!r}: a network like 192.168.4.0/22")
        if net.version != 4:
            raise ValidationError(f"{net}: DHCPv4 subnets only")
        meta = {"id": sid}
        if s.get("name"):
            name = str(s["name"]).strip().lower()
            if not LABEL_RE.match(name) or name in names:
                raise ValidationError(f"{net}: name {s['name']!r} is one DNS label, unique on this site")
            names.add(name)
            meta["name"] = name
        if s.get("vlan") is not None:
            vlan = s["vlan"]
            if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094 or vlan in vlans:
                raise ValidationError(f"{net}: vlan {vlan!r} is a number from 1 to 4094, unique on this site")
            vlans.add(vlan)
            meta["vlan"] = vlan
        if s.get("notes"):
            notes = str(s["notes"])
            if len(notes) > NOTES_MAX:
                raise ValidationError(f"{net}: notes are at most {NOTES_MAX} characters")
            meta["notes"] = notes
        if s.get("allow_overlap"):
            reason = str(s["allow_overlap"]).strip()
            if len(reason) > 200 or "\n" in reason:
                raise ValidationError(f"{net}: allow_overlap is one line of at most 200 characters (why it may "
                                      "overlap another site's network)")
            meta["allow_overlap"] = reason
        access = s.get("access", "full")
        if access not in ("full", "guest"):
            raise ValidationError(f"{net}: access is full (fabric's services, the default) or guest (DNS and NTP only)")
        if access == "guest":
            meta["access"] = "guest"
        if s.get("relay"):
            try:
                relay = ipaddress.ip_address(str(s["relay"]))
            except ValueError:
                relay = None
            if relay is None or relay.version != 4:
                raise ValidationError(f"{net}: relay {s['relay']!r} is the DHCP relay's IPv4 address")
            meta["relay"] = str(relay)
        if net.overlaps(fabric_net):
            raise ValidationError(f"{net} overlaps fabric's own container network {fabric_net} (fabric_subnet): "
                                  "clients there could not reach this site's services")
        pools = [_pool(p, net) for p in s.get("pools") or []]
        for lo, hi in pools:
            other = next((f"{a} - {b}" for a, b in pools_all if lo <= b and a <= hi), None)
            if other:
                raise ValidationError(f"pool {lo} - {hi} overlaps pool {other}")
            pools_all.append((lo, hi))
        if s.get("routers") and ipaddress.ip_address(str(s["routers"])) not in net:
            raise ValidationError(f"{net}: router {s['routers']} is outside the subnet")
        reservations = []
        for r in s.get("reservations") or []:
            mac = str(r.get("mac", "")).lower().replace("-", ":")
            if not MAC_RE.match(mac):
                raise ValidationError(f"reservation {r}: MAC like aa:bb:cc:dd:ee:ff")
            try:
                ip = ipaddress.ip_address(str(r.get("ip", "")))
            except ValueError:
                raise ValidationError(f"reservation {mac}: address {r.get('ip')!r} is not an IPv4 address")
            if ip not in net:              # inside a pool is allowed: Kea hands it only to its MAC (1.10.4.3.2)
                raise ValidationError(f"reservation {ip}: must lie inside {net}")
            if ip in seen_ips or mac in seen_macs:
                raise ValidationError(f"reservation {mac} / {ip}: MAC and address must be unique")
            seen_ips.add(ip)
            seen_macs.add(mac)
            host = r.get("hostname") or ""
            if host and not LABEL_RE.match(host):
                raise ValidationError(f"reservation hostname {host!r}: one DNS label")
            ropts = normalize_options(r.get("options"), f"reservation {mac}")
            reservations.append({"mac": mac, "ip": str(ip), **({"hostname": host} if host else {}),
                                 **({"options": ropts} if ropts else {})})
        sopts = normalize_options(s.get("options"), f"subnet {meta.get('name', net)}")
        own = ("name", "vlan", "notes", "options", "allow_overlap", "access", "relay")
        subnets.append({**{k: x for k, x in s.items() if k not in own},
                        **meta, "subnet": str(net), "reservations": reservations,
                        **({"options": sopts} if sopts else {})})
    if not subnets:
        raise ValidationError("dhcp.subnets: at least one subnet with a pool")
    for zone in (v.get("dns") or {}).values():
        for rec in (zone or {}).get("A") or []:
            try:
                ip = ipaddress.ip_address(str(rec.get("ip")))
            except ValueError:
                continue
            if any(lo <= ip <= hi for lo, hi in pools_all):
                raise ValidationError(f"DNS record {rec.get('name')} = {ip} is inside a DHCP pool: make it a "
                                      "DHCP reservation, or move the pool")
    out = {**d, "subnets": subnets}
    for key, fn in (("options", lambda x: normalize_options(x, "dhcp.options")),
                    ("option_defs", normalize_option_defs), ("client_classes", normalize_client_classes)):
        value = fn(d.get(key))
        if value:
            out[key] = value
        else:
            out.pop(key, None)
    return out
