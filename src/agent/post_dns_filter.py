from agent.apply_filter_now import apply_filter_now
from agent.change_dns_filter import change_dns_filter
from agent.read_text import read_text
from fabriclib.common.load_vars import load_vars
from fabriclib.dns_filter.read_query_log import read_query_log
from fabriclib.dns_filter.start_list_fetch import start_list_fetch


def post_dns_filter(route, actor, data):
    """Purpose: answer POST /v1/dns-filter/... (manual 1.12.3.5, 1.12.3.8): a DNS filter settings change called
             directly, saved and then made where it lives in seconds (apply_filter_now: the resolver reloaded,
             AdGuard Home through its API; no full apply), and the query-log search. The console holds its changes
             for the tab's Apply instead (POST /v1/pending/hold, 1.12.3.17), which runs them through
             change_dns_filter and applies once.
    Inputs:  route — segments after /v1/ (already authorized: dns:filter, querylog dns:querylog); actor — who asks
             (audit); data — the JSON body: a change's (change_dns_filter); fetch {}; querylog {client, name,
             blocked, limit, own (true: fabric's own queries too, 2.1.12.12)}.
    Returns: a change: {"result": what it saved, "applied": bool (made at once), "waiting": why not (or None),
             "fetching": True when the lists job was started (a list ticked with no copy yet); a job that cannot
             start leaves the change saved, "waiting" naming why}; fetch: {"fetching": True}; querylog:
             read_query_log's result.
    Fails:   ValidationError (-> 400) for what fabriclib refuses (and nothing is saved); RouteNotFound (-> 404).
    Feeds:   agent/post_route."""
    if route == ["dns-filter", "querylog"]:            # a search: its terms in the body (a GET's query is ignored)
        return read_query_log(load_vars(), client=read_text(data, "client"), name=read_text(data, "name"),
                              blocked_only=bool(data.get("blocked")), limit=data.get("limit", 200),
                              own=data.get("own", False))       # a JSON boolean; read_query_log refuses others
    if route == ["dns-filter", "fetch"]:
        return {"fetching": start_list_fetch()}
    result = change_dns_filter(route, actor, data)
    if route[2:] == ["ticks"]:                         # the lists ticked: a first copy may be needed
        ticked = [str(i.get("url") or "").strip() for i in data.get("tick") or [] if isinstance(i, dict)]
    else:
        ticked = [result["url"]] if route[1:2] == ["lists"] and result.get("enabled") else []
    done = apply_filter_now(actor, ticked)
    return {"result": result, "applied": not done["waiting"], "waiting": done["waiting"], "fetching": done["fetching"]}
