from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.add_filter_rule import add_filter_rule
from fabriclib.dns_filter.remove_filter_group import remove_filter_group
from fabriclib.dns_filter.remove_filter_list import remove_filter_list
from fabriclib.dns_filter.remove_filter_rule import remove_filter_rule
from fabriclib.dns_filter.set_filter_group import set_filter_group
from fabriclib.dns_filter.set_filter_list import set_filter_list
from fabriclib.dns_filter.set_filter_lists import set_filter_lists
from fabriclib.dns_filter.set_filter_upstreams import set_filter_upstreams
from fabriclib.dns_filter.set_safe_search import set_safe_search

# the DNS filter's settings changes (manual 1.12.3.8): each a route after /v1/dns-filter/
CHANGES = ("lists", "lists/set", "lists/ticks", "lists/delete", "rules", "rules/delete", "upstreams", "groups",
           "groups/delete", "safe-search")


def _on(text):
    """Purpose: a checkbox's value as a bool.
    Inputs:  text — "on", "true", "1", "off", "false", "0" or "".
    Returns: bool.
    Fails:   ValidationError for anything else.
    Feeds:   change_dns_filter."""
    t = str(text or "").strip().lower()
    if t in ("on", "true", "1", "yes"):
        return True
    if t in ("off", "false", "0", "no", ""):
        return False
    raise ValidationError(f"enabled is on or off, not {text!r}")


def change_dns_filter(route, actor, data, dry=False):
    """Purpose: one DNS filter settings change saved in vars.yaml, nothing applied (manual 1.12.3.8, 1.12.3.17): a
             direct call applies it afterwards (post_dns_filter); a change held for the tab's Apply is checked
             with dry when it is held, and run at Apply, which applies the filter once for all of them.
    Inputs:  route — segments after /v1/ (a CHANGES route under dns-filter); actor — who asks (audit); data — the
             JSON body: lists {name, url} (add, ticked); lists/set {url, enabled, name}; lists/ticks {tick, untick:
             [{url, name}]} (the lists form's Apply); lists/delete {url}; rules and rules/delete {kind, name, group};
             upstreams {upstreams}; groups {name, clients}; groups/delete {name}; safe-search {group, on, youtube}.
             A missing or empty group is everyone. dry — True: only checked, nothing saved or audited.
    Returns: what fabriclib's function returns for the change.
    Fails:   ValidationError for what fabriclib refuses (nothing saved), or a field that is not text; RouteNotFound
             for another route.
    Feeds:   agent/post_dns_filter, agent/pending_filter (the check at hold and Apply), agent/post_pending (the run)."""
    what, group = "/".join(route[1:]), read_text(data, "group")
    if route[:1] != ["dns-filter"] or what not in CHANGES:
        raise RouteNotFound()
    if what == "lists":
        return set_filter_list(actor, read_text(data, "url"), True, read_text(data, "name"), "web", dry=dry)
    if what == "lists/set":
        return set_filter_list(actor, read_text(data, "url"), _on(read_text(data, "enabled")), read_text(data, "name"),
                               "web", dry=dry)
    if what == "lists/ticks":
        return set_filter_lists(actor, data.get("tick", []), data.get("untick", []), "web", dry=dry)
    if what == "lists/delete":
        return remove_filter_list(actor, read_text(data, "url"), "web", dry=dry)
    if what == "rules":
        return add_filter_rule(actor, read_text(data, "kind"), read_text(data, "name"), "web", group, dry=dry)
    if what == "rules/delete":
        return remove_filter_rule(actor, read_text(data, "kind"), read_text(data, "name"), "web", group, dry=dry)
    if what == "upstreams":
        return set_filter_upstreams(actor, read_text(data, "upstreams"), "web", dry=dry)
    if what == "groups":
        return set_filter_group(actor, read_text(data, "name"), read_text(data, "clients"), "web", dry=dry)
    if what == "groups/delete":
        return remove_filter_group(actor, read_text(data, "name"), "web", dry=dry)
    return set_safe_search(actor, group, read_text(data, "on"), read_text(data, "youtube") or "strict", "web",
                           dry=dry)
