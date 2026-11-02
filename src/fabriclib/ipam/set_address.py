from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_address import check_address
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import KEEP, find_address


def set_address(v, actor, ip, site="", kind=KEEP, name=KEEP, mac=KEEP, owner=KEEP, notes=KEEP, dns=KEEP,
                secrets=None, container="samba", source="cli",
                caller=None):
    """Purpose: a recorded address changed (manual 1.10.4.16): its kind, name, MAC, owner, notes or DNS, under the same
             rules as when it was added (check_address); the address itself stays (remove and add to move it).
    Inputs:  v — fabric vars; actor — who asks (audit); ip — the address; site — whose plan ("" this site's); kind,
             name, mac, owner, notes ("" clears), dns (bool) — new values, KEEP leaves one as it is; secrets,
             container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = the address as recorded now; warnings = check_address's.
    Fails:   ValidationError: nothing to change, no such address, what check_address or edit_plan refuses.
    Feeds:   ipam/cli/run_plan_change (address set), agent/post_networks."""
    wanted = {"kind": kind, "name": name, "mac": mac, "owner": owner, "notes": notes, "dns": dns}
    if all(x is KEEP for x in wanted.values()):
        raise ValidationError("nothing to change: give --kind, --name, --mac, --owner, --notes or --dns")

    def change(plan, read, org):
        old, sub = find_address(plan, ip)
        addr, warnings = check_address({**old, **{k: x for k, x in wanted.items() if x is not KEEP}}, sub, plan,
                                       current=old["ip"])
        changes = [{"do": "set", "what": "address", "site": plan["site"], "subnet": sub["name"], "key": addr["ip"],
                    "fields": addr}]
        detail = " ".join(f"{k}={x}" for k, x in wanted.items() if x is not KEEP)
        return changes, addr, f"{addr['ip']} {detail}", warnings
    return edit_plan(v, actor, site, "IPAM_ADDRESS_SET", change, secrets, container, source, caller=caller)
