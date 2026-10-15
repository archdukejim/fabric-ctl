from fabriclib.common.ask import ask_yes_no
from fabriclib.setup.advanced.ask_dhcp_settings import ask_dhcp_settings
from fabriclib.setup.advanced.ask_log_target import ask_log_target
from fabriclib.setup.advanced.common.parts import PARTS, part_on


def ask_part(ctx, part, networks=None):
    """Purpose: the menu's item for one optional part (manual 1.2.9.11.3, 1.1.9): on or off, [Y/n] with its current
             value the default. Turned on it asks what it needs (DHCP its interface, subnet, pool and router when it has
             no settings yet; log forwarding its destination when it has none); turned off it needs nothing, and a part
             left off is not installed at all.
    Inputs:  ctx — SetupContext: vars (install_kea, install_freeradius, install_fluentbit, dns_filter, dhcp,
             log_forwarding; changed); part — "kea", "freeradius", "fluentbit" or "resolver"; networks — passed to
             ask_dhcp_settings (tests). Interactive.
    Returns: None; the part's setting changed. What turning one on needs, refused, leaves it off (said).
    Fails:   EOFError from input().
    Feeds:   setup/advanced/setup_menu."""
    title, key = PARTS[part]
    now = part_on(ctx.vars, part)
    on = ask_yes_no(f"setup.part.{part}", f"{title}: on", now)
    if on and not now:
        if part == "kea" and not (ctx.vars.get("dhcp") or {}).get("subnets") and not ask_dhcp_settings(ctx, networks):
            return
        lf = ctx.vars.get("log_forwarding") or {}
        if part == "fluentbit" and not (lf.get("syslog") or lf.get("elastic")) and not ask_log_target(ctx):
            print("    no destination: log forwarding stays off")
            return
    if key == "dns_filter":
        ctx.vars["dns_filter"] = "bind" if on else "none"
    else:
        ctx.vars[key] = on
