import json

from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id


def _read(path, default):
    """Purpose: a JSON file the lists job keeps, or a default when it is not there (yet).
    Inputs:  path — str; default — what to return then.
    Returns: the parsed JSON, or default.
    Fails:   OSError reading it other than its absence.
    Feeds:   filter_lists."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def filter_lists(v):
    """Purpose: every list the console shows as a checkbox (manual 1.12.3.5): AdGuard's catalogue, then the site's
             lists added by URL, each with whether it is on the site and ticked and its copy's state.
    Inputs:  v — vars (dns_filter_lists, deploy_base_dir).
    Returns: {"lists": [{id, name, url, description, homepage, category (the catalogue's group, "Other" without one,
             or "Added by URL"), on_site, enabled, last_fetch, last_success, rules, memory_mb, error}],
             "catalogue_fetched": when the catalogue was read (epoch) or None}.
    Fails:   OSError reading the lists job's files other than their absence.
    Feeds:   dns_filter/filter_overview, dns_filter/set_filter_lists (a catalogue list's name), agent/pending_filter
             (the ticks of an Apply)."""
    paths = adguard_paths(v)
    catalogue = _read(paths["catalogue"], {"fetched": None, "lists": []})
    state = _read(paths["state"], {})
    site = {str(i.get("url") or "").strip(): i for i in v.get("dns_filter_lists") or [] if isinstance(i, dict)}
    rows, seen = [], set()
    for c in catalogue.get("lists") or []:
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
    return {"lists": rows, "catalogue_fetched": catalogue.get("fetched")}
