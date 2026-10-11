from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns_filter.add_filter_rule import add_filter_rule
from fabriclib.dns_filter.apply_dns_filter import apply_dns_filter
from fabriclib.dns_filter.common.adguard_desired import adguard_desired
from fabriclib.dns_filter.read_query_log import read_query_log
from fabriclib.dns_filter.remove_filter_group import remove_filter_group
from fabriclib.dns_filter.remove_filter_list import remove_filter_list
from fabriclib.dns_filter.remove_filter_rule import remove_filter_rule
from fabriclib.dns_filter.set_filter_group import set_filter_group
from fabriclib.dns_filter.set_filter_list import set_filter_list
from fabriclib.dns_filter.set_filter_upstreams import set_filter_upstreams
from fabriclib.dns_filter.set_safe_search import set_safe_search
from fabriclib.dns_filter.start_list_fetch import start_list_fetch


def _on(text):
    """Purpose: a checkbox's value as a bool.
    Inputs:  text — "on", "true", "1", "off", "false", "0" or "".
    Returns: bool.
    Fails:   ValidationError for anything else.
    Feeds:   post_dns_filter."""
    t = str(text or "").strip().lower()
    if t in ("on", "true", "1", "yes"):
        return True
    if t in ("off", "false", "0", "no", ""):
        return False
    raise ValidationError(f"enabled is on or off, not {text!r}")


def post_dns_filter(route, actor, data):
    """Purpose: answer POST /v1/dns-filter/... (manual 1.12.3.5, 1.12.3.8): the DNS filter's settings changed from the
             web console, each saved and then made where it lives in seconds (apply_dns_filter: the resolver reloaded,
             AdGuard Home through its API; no full apply), and the query-log search.
    Inputs:  route — segments after /v1/ (already authorized: dns:filter, querylog dns:querylog); actor — who asks
             (audit); data — the JSON body: lists {name, url} (add, ticked); lists/set {url, enabled, name} (tick or
             untick); lists/delete {url}; rules and rules/delete {kind (allow | block), name, group}; upstreams
             {upstreams: "<address> <name>, …"}; groups {name, clients}; groups/delete {name}; safe-search {group, on,
             youtube}; fetch {}; querylog {client, name, blocked, limit}. A missing or empty group is everyone.
    Returns: a change: {"result": what it saved, "applied": bool (made at once), "waiting": why not (or None),
             "fetching": True when the lists job was started (a list ticked with no copy yet)}; fetch: {"fetching":
             True}; querylog: read_query_log's result.
    Fails:   ValidationError (-> 400) for what fabriclib refuses (and nothing is saved); RouteNotFound (-> 404).
    Feeds:   agent/post_route."""
    if route == ["dns-filter", "querylog"]:            # a search: its terms in the body (a GET's query is ignored)
        return read_query_log(load_vars(), client=read_text(data, "client"), name=read_text(data, "name"),
                              blocked_only=bool(data.get("blocked")), limit=data.get("limit", 200))
    if route == ["dns-filter", "fetch"]:
        return {"fetching": start_list_fetch()}
    group = read_text(data, "group")
    if route == ["dns-filter", "lists"]:
        result = set_filter_list(actor, read_text(data, "url"), True, read_text(data, "name"), "web")
    elif route == ["dns-filter", "lists", "set"]:
        result = set_filter_list(actor, read_text(data, "url"), _on(read_text(data, "enabled")),
                                 read_text(data, "name"), "web")
    elif route == ["dns-filter", "lists", "delete"]:
        result = remove_filter_list(actor, read_text(data, "url"), "web")
    elif route == ["dns-filter", "rules"]:
        result = add_filter_rule(actor, read_text(data, "kind"), read_text(data, "name"), "web", group)
    elif route == ["dns-filter", "rules", "delete"]:
        result = remove_filter_rule(actor, read_text(data, "kind"), read_text(data, "name"), "web", group)
    elif route == ["dns-filter", "upstreams"]:
        result = set_filter_upstreams(actor, read_text(data, "upstreams"), "web")
    elif route == ["dns-filter", "groups"]:
        result = set_filter_group(actor, read_text(data, "name"), read_text(data, "clients"), "web")
    elif route == ["dns-filter", "groups", "delete"]:
        result = remove_filter_group(actor, read_text(data, "name"), "web")
    elif route == ["dns-filter", "safe-search"]:
        result = set_safe_search(actor, group, read_text(data, "on"), read_text(data, "youtube") or "strict", "web")
    else:
        raise RouteNotFound()
    done = apply_dns_filter(actor, "web")
    # a list ticked before the lists job has its copy: the job (it has the internet; fabric-agent has not) fetches it
    # and adds it to AdGuard (refresh_lists)
    fetch = False
    if route[:2] == ["dns-filter", "lists"] and route[2:] != ["delete"] and result.get("enabled"):
        fetch = not any(f["source"] == result["url"] for f in adguard_desired(load_vars())["filters"])
    return {"result": result, "applied": not done["waiting"], "waiting": done["waiting"],
            "fetching": start_list_fetch() if fetch else False}
