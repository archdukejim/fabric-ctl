from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_address


def remove_address(v, actor, ip, site="", secrets=None, container="samba", source="cli"):
    """Purpose: a recorded address removed from a site's plan (manual 1.10.4.16): a reservation leaves Kea, a name its
             A and PTR, at the site's next apply.
    Inputs:  v — fabric vars; actor — who asks (audit); ip — the address; site — whose plan ("" this site's);
             secrets, container, source — as edit_plan.
    Returns: edit_plan's result; result = the address removed.
    Fails:   ValidationError: no such address; what edit_plan refuses.
    Feeds:   run_ipam_command (address remove)."""
    def change(plan, read, org):
        addr, sub = find_address(plan, ip)
        changes = [{"do": "remove", "what": "address", "site": plan["site"], "subnet": sub["name"],
                    "key": addr["ip"]}]
        return changes, addr, f"{addr['ip']} kind={addr['kind']} name={addr['name']}", []
    return edit_plan(v, actor, site, "IPAM_ADDRESS_REMOVE", change, secrets, container, source)
