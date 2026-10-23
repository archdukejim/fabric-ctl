from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.add_range import add_range
from fabriclib.ipam.add_subnet import add_subnet
from fabriclib.ipam.add_vlan import add_vlan
from fabriclib.ipam.common.apply_plan_change import apply_plan_change
from fabriclib.ipam.common.fields import KEEP
from fabriclib.ipam.remove_address import remove_address
from fabriclib.ipam.remove_range import remove_range
from fabriclib.ipam.remove_subnet import remove_subnet
from fabriclib.ipam.remove_vlan import remove_vlan
from fabriclib.ipam.set_address import set_address
from fabriclib.ipam.set_block import set_block
from fabriclib.ipam.set_subnet import set_subnet
from fabriclib.ipam.set_vlan import set_vlan

ON = (True, "on", "true", "1", "yes")
OFF = (False, "off", "false", "0", "no", "")


def _flag(data, key, default):
    """Purpose: an on/off field of the body (a checkbox or a select): on, off, or absent.
    Inputs:  data — the body; key — the field; default — what absent means (KEEP for a change).
    Returns: bool, or default when absent.
    Fails:   ValidationError "<key> is on or off" (-> 400).
    Feeds:   post_networks."""
    if key not in data:
        return default
    value = data[key].lower() if isinstance(data[key], str) else data[key]
    if value in ON:
        return True
    if value in OFF:
        return False
    raise ValidationError(f"{key} is on or off")


def _keep(data, key):
    """Purpose: a text field of a change: KEEP when absent, else its text ("" clears where the field allows it).
    Inputs:  data — the body; key — the field.
    Returns: KEEP or str.
    Fails:   ValidationError from read_text (-> 400).
    Feeds:   post_networks."""
    return read_text(data, key) if key in data else KEEP


def _vid(text):
    """Purpose: a VLAN ID from the path or the body.
    Inputs:  text — str.
    Returns: int.
    Fails:   ValidationError "VLAN ID … is a number from 1 to 4094" (-> 400).
    Feeds:   post_networks."""
    if not str(text).strip().isdigit():
        raise ValidationError(f"VLAN ID {text!r} is a number from 1 to 4094")
    return int(str(text).strip())


def _change(v, actor, site, sub, data, caller):
    """Purpose: route one Networks tab change to the fabriclib/ipam function it stands for.
    Inputs:  v — fabric vars; actor — the verified user; site — the site named in the path; sub — the segments after
             /v1/networks/<site>/; data — the body; caller — the signed-in person (None: a root peer).
    Returns: edit_plan's result ({"result", "warnings", "done", "site"}).
    Fails:   RouteNotFound for another path; ValidationError from the readers and fabriclib.
    Feeds:   post_networks."""
    web = {"source": "web", "caller": caller}
    t = read_text
    if sub == ["block"]:
        return set_block(v, actor, t(data, "number"), site, **web)
    if sub == ["vlans"]:
        return add_vlan(v, actor, _vid(t(data, "id")), t(data, "name"), site, t(data, "subnet"),
                        _flag(data, "no_subnet", False), t(data, "gateway"), t(data, "purpose"), t(data, "notes"),
                        t(data, "access") or "full", _flag(data, "dhcp", True), t(data, "relay"),
                        t(data, "allow_overlap"), _flag(data, "split", True), **web)
    if len(sub) == 2 and sub[0] == "vlans":
        return set_vlan(v, actor, _vid(sub[1]), site, name=_keep(data, "name"), purpose=_keep(data, "purpose"),
                        notes=_keep(data, "notes"), access=_keep(data, "access"), **web)
    if len(sub) == 3 and sub[0] == "vlans" and sub[2] == "delete":
        return remove_vlan(v, actor, _vid(sub[1]), site, _flag(data, "force", False), **web)
    if sub == ["subnets"]:
        return add_subnet(v, actor, _vid(t(data, "vlan")), t(data, "cidr"), site, t(data, "name"),
                          t(data, "gateway"), _flag(data, "dhcp", True), t(data, "relay"), t(data, "notes"),
                          t(data, "allow_overlap"), _flag(data, "split", True), **web)
    if len(sub) == 2 and sub[0] == "subnets":
        return set_subnet(v, actor, sub[1], site, gateway=_keep(data, "gateway"), dhcp=_flag(data, "dhcp", KEEP),
                          relay=_keep(data, "relay"), notes=_keep(data, "notes"),
                          allow_overlap=_keep(data, "allow_overlap"), **web)
    if len(sub) == 3 and sub[0] == "subnets" and sub[2] == "delete":
        return remove_subnet(v, actor, sub[1], site, _flag(data, "force", False), **web)
    if sub == ["ranges"]:
        return add_range(v, actor, _vid(t(data, "vlan")), t(data, "kind"), t(data, "first"), t(data, "last"), site,
                         t(data, "notes"), **web)
    if sub == ["ranges", "delete"]:
        return remove_range(v, actor, _vid(t(data, "vlan")), t(data, "first"), site, **web)
    if sub == ["addresses"]:
        vlan = t(data, "vlan")
        return add_address(v, actor, t(data, "ip"), t(data, "kind"), site, t(data, "name"), t(data, "mac"),
                           t(data, "owner"), t(data, "notes"), _flag(data, "dns", False),
                           _vid(vlan) if vlan else None, **web)
    if len(sub) == 2 and sub[0] == "addresses":
        return set_address(v, actor, sub[1], site, kind=_keep(data, "kind"), name=_keep(data, "name"),
                           mac=_keep(data, "mac"), owner=_keep(data, "owner"), notes=_keep(data, "notes"),
                           dns=_flag(data, "dns", KEEP), **web)
    if len(sub) == 3 and sub[0] == "addresses" and sub[2] == "delete":
        return remove_address(v, actor, sub[1], site, **web)
    raise RouteNotFound()


def post_networks(route, actor, data, caller=None, apply=True):
    """Purpose: the Networks tab's changes to a site's address plan (manual 1.10.4.21.5, 1.10.4.35): POST
             /v1/networks/<site>/block, /vlans, /vlans/<id>, /vlans/<id>/delete, /subnets, /subnets/<name>,
             /subnets/<name>/delete, /ranges, /ranges/delete, /addresses, /addresses/<ip>, /addresses/<ip>/delete.
             Any site of the domain; each change is the ipam function `fabricctl ipam` calls, which checks the
             signed-in person's networks `plan` right at that site first (fabric-agent's check_access, 1.10.4.34),
             writes as this site's agent account and audits, source web. Then apply_plan_change: this site's plan
             applied with the firewall in line, another site's left to its poll; a site's number is never applied
             (it shapes suggestions only).
    Inputs:  route — ["networks", <site>, …]; actor — the verified user; data — the body: number (block); id, name,
             subnet, no_subnet, gateway, purpose, notes, access, dhcp, relay, allow_overlap, split (a VLAN); name,
             purpose, notes, access (a VLAN changed: a field left out stays); vlan, cidr, name, gateway, dhcp, relay,
             notes, allow_overlap, split (a subnet); gateway, dhcp, relay, notes, allow_overlap (a subnet changed);
             force (a removal with its recorded addresses); vlan, kind, first, last, notes (a range); vlan, first (a
             range removed); ip, kind, name, mac, owner, notes, dns, vlan (an address); kind, name, mac, owner,
             notes, dns (an address changed); caller — the signed-in person (None: a root peer); apply — False
             when the Networks page's Apply runs it as a held change (its finish applies once, 1.10.4.40.3).
    Returns: apply_plan_change's result ({"result", "warnings", "site", "own", "applied", "output"}).
    Fails:   ValidationError (-> 400) from the readers and fabriclib (the grant refused, each rule named, no such
             site, the domain refusing); RouteNotFound (-> 404).
    Feeds:   agent/post_route.py."""
    if len(route) < 3 or not route[1].strip():
        raise RouteNotFound()
    v = load_vars()
    out = _change(v, actor, route[1], route[2:], data, caller)
    return apply_plan_change(v, actor, out, apply=apply and route[2:] != ["block"])
