from fabriclib.dns_filter.common.adguard_api import adguard_api
from fabriclib.dns_filter.common.adguard_desired import adguard_desired

CLIENT = {"tags": [], "upstreams": [], "use_global_settings": True, "filtering_enabled": True,
          "parental_enabled": False, "safebrowsing_enabled": False, "safe_search": {"enabled": False},
          "use_global_blocked_services": True, "blocked_services": [], "ignore_querylog": False,
          "ignore_statistics": False}


def _filters(v, password, want, have, changes):
    """Purpose: make AdGuard's lists match: add the missing, change a name or its tick, remove the rest, and load the
             ticked lists it has never read (on its first start it reads a list given as a file only at its first
             update, about 5 s later: 2.3.1.18).
    Inputs:  v, password — for adguard_api; want — adguard_desired's filters; have — AdGuard's filters
             (/control/filtering/status); changes — list, appended to.
    Returns: None.
    Fails:   ValidationError from adguard_api.
    Feeds:   sync_adguard."""
    current = {f["url"]: f for f in have or []}
    unread = False
    for f in want:
        cur = current.pop(f["url"], None)
        unread = unread or (cur is not None and f["enabled"] and not cur.get("last_updated"))
        if cur is None:
            # adding compiles the list at once (under a second for most: 2.3.1.18)
            adguard_api(v, password, "POST", "/control/filtering/add_url",
                        {"name": f["name"], "url": f["url"], "whitelist": False}, timeout=300)
            cur = {"name": f["name"], "url": f["url"], "enabled": True}
            changes.append(f"list added: {f['name']}")
        if cur.get("name") != f["name"] or bool(cur.get("enabled")) != f["enabled"]:
            adguard_api(v, password, "POST", "/control/filtering/set_url",
                        {"url": f["url"], "whitelist": False,
                         "data": {"name": f["name"], "url": f["url"], "enabled": f["enabled"]}}, timeout=300)
            changes.append(f"list {'on' if f['enabled'] else 'off'}: {f['name']}")
    for url, f in current.items():
        adguard_api(v, password, "POST", "/control/filtering/remove_url", {"url": url, "whitelist": False})
        changes.append(f"list removed: {f.get('name') or url}")
    if unread:
        adguard_api(v, password, "POST", "/control/filtering/refresh", {"whitelist": False}, timeout=600)
        changes.append("lists read")


def _clients(v, password, want, changes):
    """Purpose: make AdGuard's clients the groups: each known by its ClientID, its name (1.12.3.6).
    Inputs:  v, password — for adguard_api; want — the groups' names; changes — list, appended to.
    Returns: None.
    Fails:   ValidationError from adguard_api.
    Feeds:   sync_adguard."""
    have = {c["name"]: c for c in (adguard_api(v, password, "GET", "/control/clients") or {}).get("clients") or []}
    for name in want:
        if name in have and have[name].get("ids") == [name]:
            have.pop(name)
            continue
        if name in have:
            adguard_api(v, password, "POST", "/control/clients/update",
                        {"name": name, "data": {**CLIENT, "name": name, "ids": [name]}})
            have.pop(name)
        else:
            adguard_api(v, password, "POST", "/control/clients/add", {**CLIENT, "name": name, "ids": [name]})
        changes.append(f"group: {name}")
    for name in have:
        adguard_api(v, password, "POST", "/control/clients/delete", {"name": name})
        changes.append(f"group removed: {name}")


def sync_adguard(v, password):
    """Purpose: make the running AdGuard Home match the vars through its API (manual 1.12.3.4, 1.12.3.8): its lists
             (a list's copy read as a file, ticked or not), its rules (the owner's and the groups' allows), its
             clients (the groups) and its upstreams. Nothing restarts; what already matches is not touched.
    Inputs:  v — checked vars; password — adguard_api_password.
    Returns: list of str, the changes made ([] when it matched).
    Fails:   ValidationError from adguard_api (AdGuard not answering, or refusing a change: the first refusal stops the
             sync; what was made before it stays, and the next sync or apply carries on).
    Feeds:   dns_filter/deploy_adguard (every apply), dns_filter/apply_dns_filter (a console change),
             dns_filter/refresh_lists (after the lists job)."""
    want = adguard_desired(v)
    changes = []
    status = adguard_api(v, password, "GET", "/control/filtering/status") or {}
    _filters(v, password, want["filters"], status.get("filters"), changes)
    if list(status.get("user_rules") or []) != want["user_rules"]:
        adguard_api(v, password, "POST", "/control/filtering/set_rules", {"rules": want["user_rules"]})
        changes.append("rules")
    _clients(v, password, want["groups"], changes)
    dns = adguard_api(v, password, "GET", "/control/dns_info") or {}
    if (list(dns.get("upstream_dns") or []) != want["upstreams"]
            or list(dns.get("bootstrap_dns") or []) != want["bootstrap"]):
        adguard_api(v, password, "POST", "/control/dns_config",
                    {"upstream_dns": want["upstreams"], "bootstrap_dns": want["bootstrap"]})
        changes.append("upstreams")
    return changes
