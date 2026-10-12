from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_range import check_range
from fabriclib.ipam.check_subnet import check_subnet
from fabriclib.ipam.check_vlan import check_vlan
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.suggestions import suggest_block, suggest_split, suggest_subnet


def add_vlan(v, actor, vid, name, site="", subnet="", no_subnet=False, gateway="", purpose="", notes="",
             access="full", dhcp=True, relay="", allow_overlap="", split=True, secrets=None, container="samba",
             source="cli"):
    """Purpose: a VLAN added to a site's plan with its subnet (manual 1.10.4.3, 1.10.4.16): the subnet given, or the
             one fabric suggests (`10.<site>.<VLAN>.0/24`; a site without a number is given the suggested one,
             its order in the organisation), its gateway (given, else the first host) and, unless asked not to, the
             suggested split of a /24 (gateway .1, static .2-.99, DHCP .100-.249, reserved .250-.254). The subnet
             takes the VLAN's name and the next Kea id; served by DHCP unless dhcp is off. A network convergence
             wrote under that name (the site's LAN) becomes the VLAN's subnet when it is the same network.
    Inputs:  v — fabric vars (site_name, fabric_subnet); actor — who asks (audit); vid — the VLAN ID; name — one DNS
             label; site — whose plan ("" this site's); subnet — a network, "" for the suggestion; no_subnet — a VLAN
             as a record only; gateway — the router's address in the subnet ("" the first host); purpose, notes —
             text; access — "full" or "guest"; dhcp — bool; relay — the relay's address when it lies outside the
             subnet; allow_overlap — why it may overlap another network; split — bool, the suggested ranges of a
             /24; secrets, container, source — as edit_plan.
    Returns: edit_plan's result; result = {"vlan", "subnet" (None for a record only), "ranges", "block_set" (the
             site's number when this change gave it one, else None)}.
    Fails:   ValidationError from check_vlan, check_subnet (an overlap, named), check_range, edit_plan; "no subnet to
             suggest" for a VLAN above 255 or a site with no number to give, without --subnet; a name convergence
             already uses for another network.
    Feeds:   run_ipam_command (vlan add)."""
    def change(plan, read, org):
        vlan = check_vlan({"id": vid, "name": name, "purpose": purpose, "access": access, "notes": notes}, plan)
        changes = [{"do": "add", "what": "vlan", "site": plan["site"], "key": str(vlan["id"]), "fields": vlan}]
        out = {"vlan": vlan, "subnet": None, "ranges": [], "block_set": None}
        if no_subnet:
            return changes, out, f"vlan={vlan['id']} name={vlan['name']} (no subnet)", []
        cidr = str(subnet or "").strip()
        if not cidr:
            block = plan["block"]
            if block is None:
                block = suggest_block(read["sites"], plan["site"])
                if block:
                    changes.append({"do": "set", "what": "block", "site": plan["site"], "fields": {"block": block}})
                    out["block_set"] = block
            cidr = suggest_subnet(block, vlan["id"])
            if not cidr:
                raise ValidationError(f"no subnet to suggest for VLAN {vlan['id']}: give --subnet (or --no-subnet)")
        sug = suggest_split(cidr) if "/" in cidr else {"gateway": "", "ranges": []}
        legacy = next((n for n in plan["networks"] if n["name"] == vlan["name"]), None)
        sub = check_subnet({"name": vlan["name"], "cidr": cidr, "vlan": vlan["id"],
                            "gateway": gateway or sug["gateway"], "dhcp": dhcp, "relay": relay, "notes": "",
                            "allow_overlap": allow_overlap}, plan, plan["site"], org,
                           v.get("fabric_subnet") or "10.255.0.0/24", current=vlan["name"] if legacy else None)
        if legacy and legacy["cidr"] != sub["cidr"]:
            raise ValidationError(f"the name {sub['name']} is the site's network {legacy['cidr']}: choose another "
                                  "name, or give that network as the subnet")
        sub["kind"] = "dhcp" if sub["dhcp"] else "subnet"
        sub["id"] = max([s.get("id") or 0 for s in plan["subnets"]] + [0]) + 1
        sub["options"] = []
        changes.append({"do": "set" if legacy else "add", "what": "subnet", "site": plan["site"], "key": sub["name"],
                        "fields": sub})
        held = {**sub, "ranges": [], "addresses": []}
        for r in (sug["ranges"] if split else []):
            if r["kind"] == "gateway" and r["first"] != sub["gateway"]:
                continue                   # a gateway elsewhere: its range is not the suggested .1
            rng = check_range(r, held)
            held["ranges"].append(rng)
            changes.append({"do": "add", "what": "range", "site": plan["site"], "subnet": sub["name"],
                            "key": f"{rng['kind']}-{rng['first']}", "fields": rng})
        out.update(subnet=sub, ranges=held["ranges"])
        return changes, out, f"vlan={vlan['id']} name={vlan['name']} subnet={sub['cidr']}", []
    return edit_plan(v, actor, site, "IPAM_VLAN_ADD", change, secrets, container, source, networks=not no_subnet)
