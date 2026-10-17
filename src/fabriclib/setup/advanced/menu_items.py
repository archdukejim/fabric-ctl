import os

from fabriclib.consent.groups import GROUPS
from fabriclib.consent.initial_host_choices import TOGGLED
from fabriclib.samba.suggested_ad_domain import suggested_ad_domain
from fabriclib.samba.suggested_dc_name import suggested_dc_name
from fabriclib.setup.advanced.ask_ca_lifetime import ask_ca_lifetime
from fabriclib.setup.advanced.ask_first_admin_item import ask_first_admin_item
from fabriclib.setup.advanced.ask_host_change import ask_host_change
from fabriclib.setup.advanced.ask_memory import ask_memory
from fabriclib.setup.advanced.ask_network import ask_network
from fabriclib.setup.advanced.ask_part import ask_part
from fabriclib.setup.advanced.common.parts import PARTS, part_on
from fabriclib.setup.ask_ad_domain import ask_ad_domain
from fabriclib.setup.ask_dc_name import ask_dc_name
from fabriclib.setup.common.ask_setting import ask_setting
from fabriclib.setup.common.ca_exists import ca_exists
from fabriclib.setup.common.first_admin_needed import first_admin_needed
from fabriclib.setup.common.network_problem import network_problem
from fabriclib.setup.common.valid_setting import valid_setting

NEEDS = "(needs an answer)"


def _origin(ctx, key, text):
    """Purpose: a value as the menu shows it, marked "(found)" or "(default)" when setup filled it in, not the person.
    Inputs:  ctx — SetupContext (origins); key — the setting; text — its value as shown.
    Returns: str.
    Fails:   never.
    Feeds:   menu_items."""
    return f"{text} ({ctx.origins[key]})" if key in ctx.origins else text


def _setting_item(ctx, key):
    """Purpose: the ask callable of a one-setting required item (guided mode's question, setup.vars.<key>).
    Inputs:  ctx — SetupContext; key — domain, hostname or friendly_name.
    Returns: a function of no arguments that asks it and drops its found/default mark.
    Fails:   never (the callable: EOFError).
    Feeds:   menu_items."""
    def run():
        ctx.vars[key] = ask_setting(key, ctx.vars.get(key))
        ctx.origins.pop(key, None)
    return run


def _ad_item(ctx):
    """Purpose: the ask callable of the AD domain item: guided mode's question (setup.ad_domain), refused once the
             domain exists or when a join's invitation fixed it (it is permanent, 2.1.6.11).
    Inputs:  ctx — SetupContext (vars, deploy_base, join_invitation).
    Returns: a function of no arguments.
    Fails:   never (the callable: EOFError).
    Feeds:   menu_items."""
    def run():
        if os.path.exists(os.path.join(ctx.deploy_base, "samba", "data", ".fabric-provisioned")) or (
                ctx.join_invitation and ctx.vars.get("ad_domain")):
            print("    refused: the AD domain is permanent, and this one is set (the domain exists, or the invitation "
                  "names it)")
            return
        ask_ad_domain(ctx)
    return run


def _dc_item(ctx):
    """Purpose: the ask callable of the domain controller's name item: guided mode's question (setup.dc_name),
             refused once the domain exists (a DC cannot be renamed, 2.1.6.45).
    Inputs:  ctx — SetupContext (vars, deploy_base).
    Returns: a function of no arguments.
    Fails:   never (the callable: EOFError).
    Feeds:   menu_items."""
    def run():
        if os.path.exists(os.path.join(ctx.deploy_base, "samba", "data", ".fabric-provisioned")):
            print("    refused: the domain controller's name is permanent, and this one is made")
            return
        ctx.vars.pop("dc_name", None)          # asked again, dc-001 suggested
        ask_dc_name(ctx)
    return run


def menu_items(ctx, networks=None):
    """Purpose: the menu's items in their three parts (manual 1.2.9.11.3), each with its value as shown now.
    Inputs:  ctx — SetupContext: vars, origins, host_choices, admin_password; networks — host_networks() for DHCP's
             questions (None: this host's).
    Returns: list of {"part": "required"|"before"|"host", "title", "value" (str), "missing" (bool: a required item
             without a usable value), "ask" (callable asking it)}, in menu order (numbered from 1).
    Fails:   errors of first_admin_needed (federation.yaml unreadable).
    Feeds:   setup/advanced/setup_menu."""
    v = ctx.vars
    items = []

    def add(part, title, value, ask, missing=False):
        items.append({"part": part, "title": title, "value": value or NEEDS, "missing": missing, "ask": ask})

    for key, title in (("domain", "DNS domain"), ("hostname", "This host's name"),
                       ("friendly_name", "Organisation's name")):
        val = str(v.get(key) or "")
        ok = valid_setting(key, val)
        add("required", title, _origin(ctx, key, val) if ok else "", _setting_item(ctx, key), not ok)
    domain = str(v.get("domain") or "")
    ad = v.get("ad_domain") or ""
    ad_text = ad or (f"{suggested_ad_domain(domain)} (suggested)" if suggested_ad_domain(domain) else "")
    add("required", "Windows (AD) domain", ad_text, _ad_item(ctx), not ad_text)
    dc = v.get("dc_name") or ""
    dc_text = dc or f"{suggested_dc_name()} (suggested)"
    add("required", "Domain controller's name", dc_text, _dc_item(ctx))
    net_ok = all(valid_setting(k, str(v.get(k) or "")) for k in ("host_ip", "lan_cidr", "lan_gateway"))
    problem = network_problem(v) if net_ok else ""
    net_text = (f"{v.get('host_ip')} in {v.get('lan_cidr')}, gw {v.get('lan_gateway')}"
                + (f" ({ctx.origins['host_ip']})" if "host_ip" in ctx.origins else "")
                + (f" (does not fit: {len(items) + 1} to change)" if problem else "")) if net_ok else ""
    add("required", "Network", net_text, lambda: ask_network(ctx), not net_ok or bool(problem))
    user = str(v.get("webui_admin_user") or "")
    user_ok, needed = valid_setting("webui_admin_user", user), first_admin_needed(ctx)
    pw_missing = needed and not ctx.admin_password
    admin_text = (_origin(ctx, "webui_admin_user", user) if user_ok else NEEDS) + (
        (", password" + (f" {NEEDS}" if pw_missing else "")) if needed else "")
    add("required", "First admin", admin_text, lambda: ask_first_admin_item(ctx), not user_ok or pw_missing)

    years = round(int(v.get("cert_root_ca_days") or 3650) / 365)
    add("before", "CA root lifetime", "fixed: the CA exists" if ca_exists(ctx)
        else f"{years} years (fixed once the CA is made)", lambda: ask_ca_lifetime(ctx))
    for part in PARTS:
        on = part_on(v, part)
        detail = ""
        if part == "kea" and on:
            detail = ", ".join(s.get("subnet", "?") for s in (v.get("dhcp") or {}).get("subnets") or [])
        if part == "fluentbit" and on:
            lf = v.get("log_forwarding") or {}
            detail = ", ".join(d for d in ((lf.get("syslog") or {}).get("host"), (lf.get("elastic") or {}).get("url"))
                               if d)
        add("before", PARTS[part][0], ("on" + (f" ({detail})" if detail else "")) if on else "off",
            lambda p=part: ask_part(ctx, p, networks))
    add("before", "Memory fabric may use", f"{v.get('host_ram_capacity')} GB (the split is in the plan)",
        lambda: ask_memory(ctx))

    for group in TOGGLED:
        on = ctx.host_choices.get(group, True)
        value = ("out (fabric's rules only)" if on else "kept beside fabric's") if group == "own_rules" \
            else ("yes" if on else "no (declined)")
        add("host", GROUPS[group]["title"], value, lambda g=group: ask_host_change(ctx, g))
    if v.get("use_host_dns", True) is False:
        ctx.origins["resolver_item"] = "shown"
    if "resolver_item" in ctx.origins:
        add("host", GROUPS["resolver"]["title"] + " (port 53)",
            "fabric's (port 53 freed)" if v.get("use_host_dns", True) is False else "the host's own (kept)",
            lambda: ask_host_change(ctx, "resolver"))
    add("host", GROUPS["member"]["title"], "yes" if v.get("host_join_domain", True) is not False else "no",
        lambda: ask_host_change(ctx, "member"))
    return items
