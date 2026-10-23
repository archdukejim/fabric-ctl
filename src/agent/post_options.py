from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.common.apply_plan_change import apply_plan_change
from fabriclib.ipam.options.add_plan_class import add_plan_class
from fabriclib.ipam.options.clear_netboot import clear_netboot
from fabriclib.ipam.options.define_plan_option import define_plan_option
from fabriclib.ipam.options.remove_plan_class import remove_plan_class
from fabriclib.ipam.options.remove_plan_option import remove_plan_option
from fabriclib.ipam.options.set_netboot import set_netboot
from fabriclib.ipam.options.set_plan_option import set_plan_option
from fabriclib.ipam.options.undefine_plan_option import undefine_plan_option

SET_SCOPES = ("domain", "site")        # the scope of a class or a definition: the domain's set or the site's


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


def _set_scope(data):
    """Purpose: a class's or a definition's set: the body's scope, "site" when absent.
    Inputs:  data — the request body.
    Returns: "domain" or "site".
    Fails:   ValidationError (-> 400) for another scope.
    Feeds:   _change."""
    scope = read_text(data, "scope") or "site"
    if scope not in SET_SCOPES:
        raise ValidationError("scope: domain or site")
    return scope


def _change(v, kind, data, actor, caller):
    """Purpose: one change of the options page, routed to its fabriclib function.
    Inputs:  v — fabric vars; kind — "options", "classes", "option-defs" or "netboot"; data — the request body;
             actor — the verified user; caller — the signed-in person (None: a root peer).
    Returns: (what, edit_options' result).
    Fails:   ValidationError (-> 400): a bad action or scope; what the function refuses (the grant's networks
             options right at the site, or at `all` for the domain's set, first).
    Feeds:   post_options."""
    site, web = read_text(data, "site"), {"source": "web", "caller": caller}
    if kind == "options":
        scope, target, option = read_text(data, "scope"), read_text(data, "target"), read_text(data, "option")
        domain_class = data.get("domain") is True
        if _action(data, ("set", "remove")) == "set":
            return "option", set_plan_option(v, actor, scope, target, option, read_text(data, "data"), site,
                                             domain_class, True if data.get("always_send") is True else None, **web)
        return "option", remove_plan_option(v, actor, scope, target, option, site, domain_class, **web)
    if kind == "classes":
        scope = _set_scope(data)
        if _action(data, ("add", "remove")) == "add":
            return "class", add_plan_class(v, actor, scope, read_text(data, "name"), read_text(data, "test"),
                                           read_text(data, "next_server"), read_text(data, "server_hostname"),
                                           read_text(data, "boot_file"), site, **web)
        return "class", remove_plan_class(v, actor, scope, read_text(data, "name"), site, **web)
    if kind == "option-defs":
        scope = _set_scope(data)
        if _action(data, ("define", "undefine")) == "define":
            return "definition", define_plan_option(v, actor, scope, read_text(data, "name"), read_text(data, "code"),
                                                    read_text(data, "type"), data.get("array") is True,
                                                    read_text(data, "record_types"),
                                                    read_text(data, "space") or None, site, **web)
        return "definition", undefine_plan_option(v, actor, scope, read_text(data, "name"),
                                                  read_text(data, "space") or None, site, **web)
    target = read_text(data, "target")
    if _action(data, ("on", "off")) == "on":
        preset = {k: read_text(data, k) for k in ("server", "bios", "uefi", "arm64", "ipxe", "http")}
        return "netboot", set_netboot(v, actor, target, preset, site, **web)
    return "netboot", clear_netboot(v, actor, target, site, **web)


def post_options(route, actor, data, caller=None):
    """Purpose: the options page's changes (decision 2.1.10.23, manual 1.10.4.24.6, 1.10.4.35): POST
             /v1/ipam/options, /v1/ipam/classes, /v1/ipam/option-defs and /v1/ipam/netboot. The domain's set is
             `scope` domain on the same routes (0.8's `/org` routes and `option-editors` are not ported): who may
             change it is the grant's networks options right at every site, checked by each function first. A change
             is applied here at once with the firewall in line when it is this site's plan or the domain's set
             (apply_plan_change); another site's takes it within 30 s (its plan poll).
    Inputs:  route — segments after /v1/ (["ipam", <kind>]); actor — the verified user; data — the body: action, site,
             and per kind: scope (domain, site, subnet, class, address), target, option, data, always_send, domain (a
             class of the domain's set) for options; scope (domain or site), name, test, next_server,
             server_hostname, boot_file for classes; scope, name, code, type, array, record_types, space for
             definitions; target, server, bios, uefi, arm64, ipxe, http for netboot; caller — the signed-in person
             (None: a root peer).
    Returns: {"what" ("option", "class", "definition", "netboot"), and apply_plan_change's result}.
    Fails:   ValidationError from the readers and fabriclib (-> 400); RouteNotFound for another route.
    Feeds:   agent/post_route.py."""
    if len(route) != 2 or route[1] not in ("options", "classes", "option-defs", "netboot"):
        raise RouteNotFound()
    v = load_vars()
    what, out = _change(v, route[1], data, actor, caller)
    return {"what": what, **apply_plan_change(v, actor, out)}
