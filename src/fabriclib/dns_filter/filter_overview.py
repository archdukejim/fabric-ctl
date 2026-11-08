from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.list_memory import list_memory
from fabriclib.dns_filter.common.lists_version import lists_version
from fabriclib.dns_filter.common.safe_search import safe_search_summary
from fabriclib.dns_filter.dns_filter_stats import dns_filter_stats
from fabriclib.dns_filter.filter_lists import filter_lists

CATEGORIES = ("General", "Security", "Regional", "Other")


def filter_overview(v):
    """Purpose: the DNS filter for the web console (manual 1.12.2.13–1.12.2.15, 1.12.3.5; `dns:filter`): every list as
             a checkbox with its copy's state and memory, the rules, the client groups, safe search with the sites it
             covers, the upstreams and the statistics (no client addresses, 2.1.12.4).
    Inputs:  v — rendered vars (install_resolver, dns_filter, dns_filter_lists, dns_filter_allow, dns_filter_block,
             dns_filter_upstreams, dns_filter_safe_search, dns_filter_youtube, dns_filter_groups, adguard_mem_limit,
             deploy_base_dir).
    Returns: {"on": bool, "lists": filter_lists' rows, "lists_version": their lists_version (the page sends it back
             with its Apply, 1.12.3.17), "categories": the categories in order, "catalogue_fetched": when the
             catalogue was read (epoch) or None, "memory": list_memory's result for the ticked lists, "allow",
             "block", "upstreams", "safe_search": {"on", "youtube"} (everyone's), "groups": [{name, clients,
             safe_search, youtube, allow, block}], "safe_search_sites": safe_search_summary(), "stats":
             dns_filter_stats' result, or {"off": reason}}.
    Fails:   never for the statistics (a refusal is reported in stats.off); OSError reading the state files other than
             their absence.
    Feeds:   agent/get_route (GET /v1/dns-filter)."""
    sites = safe_search_summary()
    if not v.get("install_resolver"):
        return {"on": False, "lists": [], "lists_version": "", "categories": [], "catalogue_fetched": None,
                "memory": None, "allow": [],
                "block": [], "upstreams": [], "safe_search": {"on": False, "youtube": "strict"}, "groups": [],
                "safe_search_sites": sites, "stats": {"off": "the DNS filter is off"}}
    read = filter_lists(v)
    lists = read["lists"]
    groups = [{"name": g.get("name"), "clients": g.get("clients") or [], "safe_search": bool(g.get("safe_search")),
               "youtube": g.get("youtube") or "strict", "allow": g.get("allow") or [], "block": g.get("block") or []}
              for g in v.get("dns_filter_groups") or [] if isinstance(g, dict)]
    try:
        stats = dns_filter_stats(v)
    except ValidationError as e:
        stats = {"off": str(e)}
    categories = [c for c in (*CATEGORIES, "Added by URL") if any(r["category"] == c for r in lists)]
    return {"on": True, "lists": lists, "lists_version": lists_version(lists), "categories": categories,
            "catalogue_fetched": read["catalogue_fetched"],
            "memory": list_memory(v), "allow": v.get("dns_filter_allow") or [],
            "block": v.get("dns_filter_block") or [], "upstreams": v.get("dns_filter_upstreams") or [],
            "safe_search": {"on": bool(v.get("dns_filter_safe_search")),
                            "youtube": v.get("dns_filter_youtube") or "strict"},
            "groups": groups, "safe_search_sites": sites, "stats": stats}
