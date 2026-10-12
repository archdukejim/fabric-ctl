import ipaddress

from fabriclib.dhcp.normalize_dhcp import MAC_RE
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.plan_rows import plan_rows


def find_in_plan(read, text, leases=None, site=""):
    """Purpose: `fabricctl ipam find` (manual 1.10.4.16): an address, a name or a MAC across every site's plan. An
             address finds its row (recorded, the gateway or a lease) or, when nobody recorded it, the subnet and
             range it falls in (kind "unrecorded"); a MAC finds its addresses and leases; a name finds addresses and
             VLANs of that name.
    Inputs:  read — read_plan's result for every site; text — an IPv4 address, a MAC or a name; leases — this site's
             leases (list_leases) or None; site — this site's name (whose leases they are).
    Returns: list of row dicts (plan_rows' keys); a VLAN found by name is a row with kind "vlan" and no address.
    Fails:   never.
    Feeds:   run_ipam_command (find)."""
    want = str(text or "").strip().lower()
    try:
        ip = ipaddress.ip_address(want)
    except ValueError:
        ip = None
    mac = want.replace("-", ":") if MAC_RE.match(want.replace("-", ":")) else ""
    out = []
    for name in sorted((read.get("plans") or {})):
        plan = site_plan(read, name)
        rows = plan_rows(plan, leases if name == site else None)
        if ip is not None:
            hits = [r for r in rows if r["ip"] == str(ip)]
            if not hits:
                for s in plan["subnets"]:
                    if ip in ipaddress.ip_network(s["cidr"]):
                        kind = next((r["kind"] for r in s.get("ranges") or []
                                     if ipaddress.ip_address(r["first"]) <= ip <= ipaddress.ip_address(r["last"])),
                                    "")
                        vlan = next((v["name"] for v in plan["vlans"] if v["id"] == s.get("vlan")), "")
                        hits.append({"site": name, "vlan": s.get("vlan") or "", "vlan_name": vlan,
                                     "subnet": s["cidr"], "ip": str(ip), "kind": "unrecorded", "range": kind,
                                     "name": "", "mac": "", "owner": "", "dns": "", "lease": "", "notes": ""})
            out += hits
        elif mac:
            out += [r for r in rows if r["mac"].lower() == mac]
        else:
            out += [r for r in rows if r["name"].lower() == want]
            for v in plan["vlans"]:
                if v["name"] == want:
                    sub = next((s["cidr"] for s in plan["subnets"] if s.get("vlan") == v["id"]), "")
                    out.append({"site": name, "vlan": v["id"], "vlan_name": v["name"], "subnet": sub, "ip": "",
                                "kind": "vlan", "range": "", "name": v["name"], "mac": "", "owner": "", "dns": "",
                                "lease": "", "notes": v.get("notes") or ""})
    return out
