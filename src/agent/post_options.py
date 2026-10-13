from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.options.add_plan_class import add_plan_class
from fabriclib.ipam.options.clear_netboot import clear_netboot
from fabriclib.ipam.options.define_plan_option import define_plan_option
from fabriclib.ipam.options.remove_plan_class import remove_plan_class
from fabriclib.ipam.options.remove_plan_option import remove_plan_option
from fabriclib.ipam.options.set_netboot import set_netboot
from fabriclib.ipam.options.set_option_editor import set_option_editor
from fabriclib.ipam.options.set_plan_option import set_plan_option
from fabriclib.ipam.options.undefine_plan_option import undefine_plan_option
from fabriclib.security.refresh_firewall import refresh_firewall
from fabriclib.system.apply_changes import apply_changes


def _action(data, allowed):
    """Purpose: the body's action, one of those the route takes.
    Inputs:  data — the request body; allowed — tuple of str.
    Returns: str.
    Fails:   ValidationError naming the allowed actions (-> 400).
    Feeds:   post_options."""
    action = read_text(data, "action")
    if action not in allowed:
        raise ValidationError(f"action: {' or '.join(allowed)}")
    return action


def _change(org, kind, data, actor):
    """Purpose: one change of the options page, routed to its fabriclib function; the organisation's only through the
             /org routes (dhcp:org-options), a site's never there.
    Inputs:  org — bool: the route is an /org one; kind — "options", "classes" or "option-defs"; data — the request
             body; actor — the verified user.
    Returns: (what, edit_options' result).
    Fails:   ValidationError (-> 400): an organisation change on a site route or the other way round; what the function
             refuses.
    Feeds:   post_options."""
    v = load_vars()
    site = read_text(data, "site")
    if kind == "options":
        scope = read_text(data, "scope")
        is_org = scope == "org" or (scope == "class" and data.get("org") is True)
        if is_org != org:
            raise ValidationError("the organisation's options are changed at /v1/ipam/options/org, a site's at "
                                  "/v1/ipam/options")
        if _action(data, ("set", "remove")) == "set":
            return "option", set_plan_option(v, actor, scope, read_text(data, "target"), read_text(data, "option"),
                                             read_text(data, "data"), site, data.get("org") is True,
                                             True if data.get("always_send") is True else None, source="web")
        return "option", remove_plan_option(v, actor, scope, read_text(data, "target"), read_text(data, "option"),
                                            site, data.get("org") is True, source="web")
    scope = "org" if org else "site"
    if kind == "classes":
        if _action(data, ("add", "remove")) == "add":
            return "class", add_plan_class(v, actor, scope, read_text(data, "name"), read_text(data, "test"),
                                           read_text(data, "next_server"), read_text(data, "server_hostname"),
                                           read_text(data, "boot_file"), site, source="web")
        return "class", remove_plan_class(v, actor, scope, read_text(data, "name"), site, source="web")
    if _action(data, ("define", "undefine")) == "define":
        return "definition", define_plan_option(v, actor, scope, read_text(data, "name"), read_text(data, "code"),
                                                read_text(data, "type"), data.get("array") is True,
                                                read_text(data, "record_types"), read_text(data, "space") or None,
                                                site, source="web")
    return "definition", undefine_plan_option(v, actor, scope, read_text(data, "name"),
                                              read_text(data, "space") or None, site, source="web")


def post_options(route, actor, data):
    """Purpose: the options page's changes (decision 2.1.10.23, manual 1.10.4.24.6): POST /v1/ipam/options,
             /v1/ipam/classes, /v1/ipam/option-defs (a site's: dhcp:write) and their /org forms (the organisation's:
             dhcp:org-options), /v1/ipam/netboot (dhcp:write), /v1/ipam/option-editors (dhcp:org-options, the top
             only). A change to this site's plan or to the organisation's is applied here at once and the firewall
             brought in line; another site's takes it within 30 s (its plan poll).
    Inputs:  route — segments after /v1/; actor — the verified user; data — the body (see 1.10.4.24.6).
    Returns: {"what", "result", "warnings", "site", "applied" (bool, or None for another site's change), "output"}.
    Fails:   ValidationError from the readers and fabriclib (-> 400); RouteNotFound for another route.
    Feeds:   agent/post_route.py."""
    sub = route[1:]
    if sub == ["option-editors"]:
        out = set_option_editor(load_vars(), actor, read_text(data, "site"),
                                _action(data, ("add", "remove")) == "add", source="web")
        return {"what": "editors", "result": out, "warnings": [], "site": "", "applied": None, "output": ""}
    if sub == ["netboot"]:
        v = load_vars()
        site, target = read_text(data, "site"), read_text(data, "target")
        if _action(data, ("on", "off")) == "on":
            preset = {k: read_text(data, k) for k in ("server", "bios", "uefi", "arm64", "ipxe", "http")}
            what, out = "netboot", set_netboot(v, actor, target, preset, site, source="web")
        else:
            what, out = "netboot", clear_netboot(v, actor, target, site, source="web")
    elif len(sub) in (1, 2) and sub[0] in ("options", "classes", "option-defs") and sub[1:] in ([], ["org"]):
        what, out = _change(sub[1:] == ["org"], sub[0], data, actor)
    else:
        raise RouteNotFound()
    if out["site"] != load_vars().get("site_name"):
        return {"what": what, "result": out["result"], "warnings": out["warnings"], "site": out["site"],
                "applied": None, "output": "written to that site's plan: its Kea takes it within 30 s"}
    ok, output = apply_changes(actor, source="web")
    if ok:
        ok, more = refresh_firewall()
        output += "\n" + more
    return {"what": what, "result": out["result"], "warnings": out["warnings"], "site": out["site"], "applied": ok,
            "output": output[-2000:]}
