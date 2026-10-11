from fabriclib.common.errors import ValidationError

EVERYONE = {"allow": "dns_filter_allow", "block": "dns_filter_block",
            "safe_search": "dns_filter_safe_search", "youtube": "dns_filter_youtube"}
GROUP = {k: k for k in EVERYONE}


def filter_target(data, group):
    """Purpose: where a DNS filter change goes (manual 1.12.2.15): everyone's settings, or one client group's entry.
    Inputs:  data — the vars being changed (a copy: the target is changed in place); group — "" (or "everyone") for
             everyone, else a group's name.
    Returns: (the dict to change, {"allow", "block", "safe_search", "youtube": its key for each}, the label
             for messages and the audit: "everyone" or "group <name>").
    Fails:   ValidationError when no group has that name.
    Feeds:   dns_filter/add_filter_rule, remove_filter_rule, set_safe_search."""
    group = str(group or "").strip().lower()
    if group in ("", "everyone"):
        return data, EVERYONE, "everyone"
    for g in data.get("dns_filter_groups") or []:
        if isinstance(g, dict) and str(g.get("name") or "").strip().lower() == group:
            return g, GROUP, f"group {group}"
    raise ValidationError(f"no client group is called {group}")
