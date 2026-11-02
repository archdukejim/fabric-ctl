from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import MAC_RE
from fabriclib.ipam.common.edit_plan import edit_plan


def remove_reservation_mac(v, actor, mac, secrets=None, container="samba", source="cli", caller=None):
    """Purpose: 0.7's `fabricctl dhcp unreserve <mac>` once the subnets live in the plan: an alias of `fabricctl ipam
             address remove` for the reservation that MAC holds in this site's plan (manual 1.10.4.9, 1.10.4.21,
             decision 2.1.10.27); its address leaves Kea, and its names their records, at the apply.
    Inputs:  v — fabric vars; actor — who asks (audit); mac — as typed (case, and - or :, do not matter); secrets,
             container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = the reservation removed.
    Fails:   ValidationError: not a MAC; no reservation of this site's plan holds it; what edit_plan refuses.
    Feeds:   dhcp/run_dhcp_alias (unreserve)."""
    want = str(mac or "").strip().lower().replace("-", ":")
    if not MAC_RE.match(want):
        raise ValidationError(f"{mac!r} is not a MAC address (aa:bb:cc:dd:ee:ff)")

    def change(plan, read, org):
        found = next(((a, s) for s in plan["subnets"] for a in s.get("addresses") or []
                      if a["kind"] == "reservation" and (a.get("mac") or "").lower() == want), None)
        if found is None:
            raise ValidationError(f"no reservation for {want} in {plan['site']}'s plan")
        addr, sub = found
        changes = [{"do": "remove", "what": "address", "site": plan["site"], "subnet": sub["name"],
                    "key": addr["ip"]}]
        return changes, addr, f"alias=dhcp unreserve {addr['ip']} mac={want} name={addr.get('name') or ''}", []
    return edit_plan(v, actor, "", "IPAM_ADDRESS_REMOVE", change, secrets, container, source, caller=caller)
