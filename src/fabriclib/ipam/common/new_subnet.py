from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_range import check_range
from fabriclib.ipam.check_subnet import check_subnet
from fabriclib.ipam.suggestions import suggest_split


def new_subnet(v, plan, org, vlan, cidr, name, gateway="", dhcp=True, relay="", notes="", allow_overlap="",
               split=True):
    """Purpose: the changes that add one subnet to a VLAN of a site's plan (manual 1.10.4.16, 2.1.10.18): checked by
             check_subnet (an overlap anywhere in the domain refused unless a reason is given), its gateway
             (given, else the first host), the next Kea id, served by DHCP unless dhcp is off, and in a /24 the
             suggested split (gateway .1, static .2-.99, DHCP .100-.249, reserved .250-.254) unless split is off. A
             network convergence wrote under that name (the site's LAN) becomes the subnet when it is the same
             network.
    Inputs:  v — fabric vars (fabric_subnet); plan — the site's plan; org — every site's networks
             (read_address_plan); vlan — the VLAN's plan entry; cidr — the network (str); name — the subnet's name
             (one DNS label, unique in the site); gateway — "" for the first host; dhcp — bool; relay, notes,
             allow_overlap — str; split — bool.
    Returns: (changes for write_plan, the subnet as written, its ranges).
    Fails:   ValidationError from check_subnet or check_range; a name that is the site's network of another CIDR.
    Feeds:   add_vlan, add_subnet."""
    sug = suggest_split(cidr) if "/" in cidr else {"gateway": "", "ranges": []}
    legacy = next((n for n in plan["networks"] if n["name"] == str(name).strip().lower()), None)
    sub = check_subnet({"name": name, "cidr": cidr, "vlan": vlan["id"], "gateway": gateway or sug["gateway"],
                        "dhcp": dhcp, "relay": relay, "notes": notes, "allow_overlap": allow_overlap}, plan,
                       plan["site"], org, v.get("fabric_subnet") or "10.255.0.0/24",
                       current=str(name).strip().lower() if legacy else None)
    if legacy and legacy["cidr"] != sub["cidr"]:
        raise ValidationError(f"the name {sub['name']} is the site's network {legacy['cidr']}: choose another "
                              "name, or give that network as the subnet")
    sub["kind"] = "dhcp" if sub["dhcp"] else "subnet"
    sub["id"] = max([s.get("id") or 0 for s in plan["subnets"]] + [0]) + 1
    sub["options"] = []
    changes = [{"do": "set" if legacy else "add", "what": "subnet", "site": plan["site"], "key": sub["name"],
                "fields": sub}]
    held = {**sub, "ranges": [], "addresses": []}
    for r in (sug["ranges"] if split else []):
        if r["kind"] == "gateway" and r["first"] != sub["gateway"]:
            continue                       # a gateway elsewhere: its range is not the suggested .1
        rng = check_range(r, held)
        held["ranges"].append(rng)
        changes.append({"do": "add", "what": "range", "site": plan["site"], "subnet": sub["name"],
                        "key": f"{rng['kind']}-{rng['first']}", "fields": rng})
    return changes, sub, held["ranges"]
