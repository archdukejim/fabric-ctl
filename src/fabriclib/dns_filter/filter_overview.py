import json

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id
from fabriclib.dns_filter.common.list_memory import list_memory
from fabriclib.dns_filter.common.safe_search import safe_search_summary
from fabriclib.dns_filter.dns_filter_stats import dns_filter_stats

CATEGORIES = ("General", "Security", "Regional", "Other")


def _read(path, default):
    """Purpose: a JSON file the lists job keeps, or a default when it is not there (yet).
    Inputs:  path — str; default — what to return then.
    Returns: the parsed JSON, or default.
    Fails:   OSError reading it other than its absence.
    Feeds:   filter_overview."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def _lists(v, catalogue, state):
    """Purpose: every list the console shows as a checkbox (manual 1.12.3.5): AdGuard's catalogue, then the site's
             lists added by URL, each with whether it is on the site and ticked and its copy's state.
    Inputs:  v — vars (dns_filter_lists); catalogue — catalogue.json's lists; state — the lists' state.
    Returns: list of {id, name, url, description, homepage, category (a CATEGORIES entry or "Added by URL"), on_site,
             enabled, last_fetch, last_success, rules, memory_mb, error}.
    Fails:   never.
    Feeds:   filter_overview."""
    site = {str(i.get("url") or "").strip(): i for i in v.get("dns_filter_lists") or [] if isinstance(i, dict)}
    rows, seen = [], set()
    for c in catalogue:
        seen.add(c["url"])
        rows.append({**c, "category": c.get("group") or "Other"})
    for url, item in site.items():
        if url not in seen:
            rows.append({"name": item.get("name") or url, "url": url, "description": "", "homepage": "",
                         "category": "Added by URL"})
    for r in rows:
        on = site.get(r["url"])
        st = state.get(list_id(r["url"])) or {}
        r.update({"id": list_id(r["url"]), "on_site": on is not None,
                  "enabled": on is not None and on.get("enabled", True) is not False,
                  **{k: st.get(k) for k in ("last_fetch", "last_success", "rules", "memory_mb", "error")}})
        r.pop("group", None)
        if on is not None:
            r["name"] = on.get("name") or r["name"]
    return rows


def filter_overview(v):
    """Purpose: the DNS filter for the web console (manual 1.12.2.13–1.12.2.15, 1.12.3.5; `dns:filter`): every list as
             a checkbox with its copy's state and memory, the rules, the client groups, safe search with the sites it
             covers, the upstreams and the statistics (no client addresses, 2.1.12.4).
    Inputs:  v — rendered vars (install_resolver, dns_filter, dns_filter_lists, dns_filter_allow, dns_filter_block,
             dns_filter_upstreams, dns_filter_safe_search, dns_filter_youtube, dns_filter_groups, adguard_mem_limit,
             deploy_base_dir).
    Returns: {"on": bool, "lists": _lists' rows, "categories": the categories in order, "catalogue_fetched": when the
             catalogue was read (epoch) or None, "memory": list_memory's result for the ticked lists, "allow",
             "block", "upstreams", "safe_search": {"on", "youtube"} (everyone's), "groups": [{name, clients,
             safe_search, youtube, allow, block}], "safe_search_sites": safe_search_summary(), "stats":
             dns_filter_stats' result, or {"off": reason}}.
    Fails:   never for the statistics (a refusal is reported in stats.off); OSError reading the state files other than
             their absence.
    Feeds:   agent/get_route (GET /v1/dns-filter)."""
    sites = safe_search_summary()
    if not v.get("install_resolver"):
        return {"on": False, "lists": [], "categories": [], "catalogue_fetched": None, "memory": None, "allow": [],
                "block": [], "upstreams": [], "safe_search": {"on": False, "youtube": "strict"}, "groups": [],
                "safe_search_sites": sites, "stats": {"off": "the DNS filter is off"}}
    paths = adguard_paths(v)
    catalogue = _read(paths["catalogue"], {"fetched": None, "lists": []})
    lists = _lists(v, catalogue.get("lists") or [], _read(paths["state"], {}))
    groups = [{"name": g.get("name"), "clients": g.get("clients") or [], "safe_search": bool(g.get("safe_search")),
               "youtube": g.get("youtube") or "strict", "allow": g.get("allow") or [], "block": g.get("block") or []}
              for g in v.get("dns_filter_groups") or [] if isinstance(g, dict)]
    try:
        stats = dns_filter_stats(v)
    except ValidationError as e:
        stats = {"off": str(e)}
    categories = [c for c in (*CATEGORIES, "Added by URL") if any(r["category"] == c for r in lists)]
    return {"on": True, "lists": lists, "categories": categories, "catalogue_fetched": catalogue.get("fetched"),
            "memory": list_memory(v), "allow": v.get("dns_filter_allow") or [],
            "block": v.get("dns_filter_block") or [], "upstreams": v.get("dns_filter_upstreams") or [],
            "safe_search": {"on": bool(v.get("dns_filter_safe_search")),
                            "youtube": v.get("dns_filter_youtube") or "strict"},
            "groups": groups, "safe_search_sites": sites, "stats": stats}
