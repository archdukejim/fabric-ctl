import json
import os

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.list_zone import list_zone
from fabriclib.dns_filter.common.resolver_paths import resolver_paths
from fabriclib.dns_filter.common.safe_search import safe_search_summary
from fabriclib.dns_filter.dns_filter_stats import dns_filter_stats
from fabriclib.system.memory_limit_mb import memory_limit_mb


def _read(path, default):
    """Purpose: a JSON file the lists job or the apply keeps, or a default when it is not there (yet).
    Inputs:  path — str; default — what to return then.
    Returns: the parsed JSON, or default.
    Fails:   OSError reading it other than its absence.
    Feeds:   filter_overview."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def _lists(items, state, left_out, view):
    """Purpose: one view's lists as the console shows them: each with its state, and whether the memory guard left it
             out.
    Inputs:  items — [{name, url}]; state — the lists' state; left_out — placement.json's left_out; view — "everyone"
             or a group's name.
    Returns: list of {name, url, zone, last_fetch, last_success, rules, skipped, memory_mb, error, left_out}.
    Fails:   never.
    Feeds:   filter_overview."""
    out = []
    for item in items or []:
        zone = list_zone(item["url"])
        st = state.get(zone, {})
        out.append({"name": item.get("name") or item["url"], "url": item["url"], "zone": zone,
                    **{k: st.get(k) for k in ("last_fetch", "last_success", "rules", "skipped", "memory_mb", "error")},
                    "left_out": any(x["view"] == view and x["zone"] == zone for x in left_out)})
    return out


def filter_overview(v):
    """Purpose: the DNS filter for the web console (manual 1.12.2.13–1.12.2.15; `dns:filter`): its settings that people
             manage, each list's state, the client groups, safe search with the sites it covers, and the statistics
             (no client addresses, 2.1.12.4).
    Inputs:  v — rendered vars (dns_filter, install_resolver, dns_filter_lists, dns_filter_allow, dns_filter_block,
             dns_filter_upstreams, dns_filter_safe_search, dns_filter_youtube, dns_filter_groups,
             memory_plan (the resolver's limit), deploy_base_dir).
    Returns: {"on": bool, "lists": [{name, url, zone, last_fetch, last_success, rules, skipped, memory_mb, error,
             left_out}], "allow", "block", "upstreams", "memory_limit", "memory": the last apply's estimate
             {estimate_mb, limit_mb, left_out} or None, "safe_search": {"on", "youtube"} (everyone's), "groups":
             [{name, clients, safe_search, youtube, lists (as above), allow, block}], "safe_search_sites":
             safe_search_summary(), "stats": dns_filter_stats' result, or {"off": reason} (the query log off, or
             Postgres refusing: its message), "catalogue": {"fetched", "lists": AdGuard's catalogue as the lists job
             kept it, without the lists already on everyone}}.
    Fails:   never for the statistics (a refusal is reported in stats.off); OSError reading the state files other than
             their absence.
    Feeds:   agent/get_route (GET /v1/dns-filter)."""
    sites = safe_search_summary()
    if not v.get("install_resolver"):
        return {"on": False, "lists": [], "allow": [], "block": [], "upstreams": [], "memory_limit": None,
                "memory": None, "safe_search": {"on": False, "youtube": "strict"}, "groups": [],
                "safe_search_sites": sites, "stats": {"off": "the BIND resolver is off"},
                "catalogue": {"fetched": None, "lists": []}}
    paths = resolver_paths(v)
    state = _read(paths["state"], {})
    memory = _read(os.path.join(paths["lists"], "placement.json"), None)
    left_out = (memory or {}).get("left_out") or []
    lists = _lists(v.get("dns_filter_lists"), state, left_out, "everyone")
    groups = [{"name": g.get("name"), "clients": g.get("clients") or [], "safe_search": bool(g.get("safe_search")),
               "youtube": g.get("youtube") or "strict",
               "lists": _lists(g.get("lists"), state, left_out, g.get("name")),
               "allow": g.get("allow") or [], "block": g.get("block") or []}
              for g in v.get("dns_filter_groups") or [] if isinstance(g, dict)]
    try:
        stats = dns_filter_stats(v)
    except ValidationError as e:
        stats = {"off": str(e)}
    catalogue = _read(os.path.join(paths["lists"], "catalogue.json"), {"fetched": None, "lists": []})
    used = {i["url"] for i in lists}
    catalogue["lists"] = [c for c in catalogue["lists"] if c["url"] not in used]
    return {"on": True, "lists": lists, "allow": v.get("dns_filter_allow") or [],
            "block": v.get("dns_filter_block") or [], "upstreams": v.get("dns_filter_upstreams") or [],
            "memory_limit": f"{memory_limit_mb(v, 'resolver')}m", "memory": memory,
            "safe_search": {"on": bool(v.get("dns_filter_safe_search")), "youtube": v.get("dns_filter_youtube")
                            or "strict"},
            "groups": groups, "safe_search_sites": sites, "stats": stats, "catalogue": catalogue}
