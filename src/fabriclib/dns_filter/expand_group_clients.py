from fabriclib.common.errors import ValidationError
from fabriclib.ipam.planned_subnets import planned_subnets

KINDS = ("dhcp", "device", "vlan")


def expand_group_clients(raw, name, v):
    """Purpose: a DNS-filter group's clients with its references to Kea's data turned into addresses on every apply
             (manual 1.10.3.7): `dhcp:<subnet name or network>` its network, `device:<reservation hostname or MAC>`
             its reserved address, `vlan:<n>` every DHCP subnet recorded with that VLAN (where an 802.1X role puts
             its devices). Plain addresses and subnets pass through.
    Inputs:  raw — the group's clients setting (a list, or anything: left for _clients to refuse); name — the group
             (for the messages); v — rendered vars: install_kea, dhcp.subnets [{subnet, name, vlan, reservations
             [{mac, ip, hostname}]}], or the plan's once the subnets live there (planned_subnets: vars.yaml keeps
             none, 2.3.10.10.4).
    Returns: the list with every reference replaced by its addresses (in order), or raw unchanged when it is not a
             list.
    Fails:   ValidationError: a reference while DHCP is off, an unknown kind, or one naming no subnet, reservation or
             VLAN DHCP serves.
    Feeds:   dns_filter/check_filter_groups."""
    if not isinstance(raw, list):
        return raw
    subnets = planned_subnets(v) if v.get("install_kea") else []     # the plan's once they live there
    out = []
    for item in raw:
        text = str(item).strip()
        kind, sep, ref = text.partition(":")
        if not sep or kind not in KINDS:      # an address or subnet (IPv6 too): checked by _clients
            out.append(text)
            continue
        if not v.get("install_kea"):
            raise ValidationError(f"group {name}: {text} names DHCP's data, and DHCP is off")
        ref = ref.strip().lower()
        if kind == "dhcp":
            found = [s["subnet"] for s in subnets if ref in (str(s.get("name", "")).lower(), s["subnet"])]
        elif kind == "device":
            found = [r["ip"] for s in subnets for r in s.get("reservations") or []
                     if ref in (str(r.get("hostname", "")).lower(), str(r.get("mac", "")).lower())]
        else:
            found = [s["subnet"] for s in subnets if str(s.get("vlan", "")) == ref]
        if not found:
            what = {"dhcp": "DHCP subnet", "device": "DHCP reservation", "vlan": "DHCP subnet with VLAN"}[kind]
            raise ValidationError(f"group {name}: no {what} {ref!r}")
        out.extend(found)
    return out
