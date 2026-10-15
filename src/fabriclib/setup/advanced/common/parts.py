"""The optional parts in setup's menu (manual 1.1.9, 1.2.9.11.3): part -> (its title, the setting that turns it on)."""

PARTS = {"kea": ("DHCP with Kea", "install_kea"), "freeradius": ("802.1X with FreeRADIUS", "install_freeradius"),
         "fluentbit": ("Log forwarding (Fluent Bit)", "install_fluentbit"),
         "resolver": ("DNS filter (the BIND resolver)", "dns_filter")}


def part_on(v, part):
    """Purpose: whether an optional part is on in these settings (1.1.9).
    Inputs:  v — settings; part — a key of PARTS.
    Returns: bool (the DNS filter: dns_filter is bind, its default).
    Fails:   KeyError for an unknown part (a coding error).
    Feeds:   setup/advanced/ask_part, setup/advanced/menu_items."""
    key = PARTS[part][1]
    if key == "dns_filter":
        return str(v.get("dns_filter") or "bind").lower() == "bind"
    return bool(v.get(key))
