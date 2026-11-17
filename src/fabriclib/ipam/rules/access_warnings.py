from fabriclib.ipam.rules.constants import ANY, SERVICES


def access_warnings(table, nets):
    """Purpose: what an access table allows that is likely a mistake, said and taken (manual 1.10.4.48.10): a VLAN
             given DHCP but not DNS (its clients are handed fabric's DNS, which will not answer them), a VLAN with a
             subnet allowed nothing, and outside addresses allowed a service (decision 2.1.10.62).
    Inputs:  table — access_table's shape; nets — rule_networks' result for the site.
    Returns: list of str.
    Fails:   never.
    Feeds:   set_access, show_access, access_view."""
    out = []
    for ref, cidrs in nets["vlans"].items():
        row = table.get(ref) or {}
        if not cidrs:
            continue
        if row.get("dhcp") == "allow" and row.get("dns") != "allow":
            out.append(f"VLAN {ref} gets DHCP from fabric but not DNS: its clients are handed fabric's DNS, which "
                       "will not answer them")
        if not any(a == "allow" for a in row.values()):
            out.append(f"VLAN {ref} reaches none of fabric's services: every request from it goes unanswered")
    opened = [s for s in SERVICES if (table.get(ANY) or {}).get(s) == "allow"]
    if opened:
        out.append(f"outside: {', '.join(opened)} open to every address, outside ones too")
    return out
