import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.check_address import check_address
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.common.fields import find_vlan, ipv4, subnet_holding


def _subnet_for(plan, ip, vid):
    """Purpose: the subnet of the site's plan an address goes in: the VLAN's when one is named, else the one subnet
             holding it.
    Inputs:  plan — the site's plan; ip — IPv4Address; vid — a VLAN ID or None.
    Returns: the subnet's plan entry.
    Fails:   ValidationError: the VLAN has no subnet; the address is in none of the site's subnets, or in more than
             one (allowed overlaps) and no VLAN was named.
    Feeds:   add_address."""
    if vid is not None:
        vlan, subs = find_vlan(plan, vid)
        return subnet_holding(vlan, subs, ip, "address")
    holding = [s for s in plan["subnets"] if ip in ipaddress.ip_network(s["cidr"])]
    if not holding:
        raise ValidationError(f"{ip} is in none of {plan['site']}'s subnets")
    if len(holding) > 1:
        raise ValidationError(f"{ip} is in more than one of {plan['site']}'s subnets: name its VLAN (--vlan)")
    return holding[0]


def add_address(v, actor, ip, kind, site="", name="", mac="", owner="", notes="", dns=False, vid=None,
                secrets=None, container="samba", source="cli",
                caller=None):
    """Purpose: an address recorded in a site's plan (manual 1.10.4.3, 1.10.4.16): a static address, a reservation (a
             MAC's fixed address, served by Kea) or infrastructure, with its name, MAC, owner and notes, and with
             DNS on an A and a PTR in the site's zone at its next apply (a reservation's beside DHCP's own name in
             dhcp.<domain>, 2.1.10.17). One claim per address; check_address's rules and warnings.
    Inputs:  v — fabric vars (site_name, dns: the settings' own records of this site's zone); actor — who asks
             (audit); ip — the address; kind — static, reservation or infrastructure; site — whose plan ("" this
             site's); name, mac, owner, notes — text; dns — bool; vid — the VLAN whose subnet holds it (only needed
             where subnets overlap); secrets, container, source, caller — as edit_plan.
    Returns: edit_plan's result; result = the address as recorded; warnings = check_address's (a static address
             outside the static ranges, a reservation in a subnet DHCP does not serve).
    Fails:   ValidationError: what _subnet_for or check_address refuses; a DNS name the settings already give this
             site's zone; what edit_plan refuses.
    Feeds:   run_ipam_command (address add), dhcp/run_dhcp_alias (reserve)."""
    addr_ip = ipv4(ip, "address")

    def change(plan, read, org):
        sub = _subnet_for(plan, addr_ip, vid)
        addr, warnings = check_address({"ip": str(addr_ip), "kind": kind, "name": name, "mac": mac, "owner": owner,
                                        "notes": notes, "dns": dns}, sub, plan)
        if addr["dns"] and plan["site"] == v.get("site_name"):
            zone = ((v.get("dns") or {}).get("dynamic_zone_var") or {}).get("A") or []
            if any(str(r.get("name") or "").lower() == addr["name"] for r in zone):
                raise ValidationError(f"the settings already name {addr['name']} in this site's zone (dns:): remove "
                                      "that record first, or choose another name")
        changes = [{"do": "add", "what": "address", "site": plan["site"], "subnet": sub["name"], "key": addr["ip"],
                    "fields": addr}]
        return changes, addr, f"{addr['ip']} kind={addr['kind']} name={addr['name']} mac={addr['mac']}", warnings
    return edit_plan(v, actor, site, "IPAM_ADDRESS_ADD", change, secrets, container, source, caller=caller)
