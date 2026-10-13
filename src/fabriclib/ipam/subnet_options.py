from fabriclib.ipam.common.option_codes import CODES, NAMES, PROVIDED

# the levels an option can come from, least specific first (manual 1.10.4.6.1: the most specific wins, as in Kea)
LEVELS = ("fabric", "organisation", "site", "settings", "vlan", "subnet")


def _key(o):
    """Purpose: what makes two options the same: its name, or the name its code stands for.
    Inputs:  o — an option ({name | code, data, …}).
    Returns: str, the standard name or "code <n>".
    Fails:   never.
    Feeds:   subnet_options."""
    if o.get("name"):
        return str(o["name"]).lower()
    code = o.get("code")
    return NAMES.get(code, f"code {code}")


def subnet_options(levels):
    """Purpose: the options a subnet (or a reservation in it) ends up with and where each came from (manual
             1.10.4.6.1, 1.10.4.9): every level's options, each shown with its standard name and code, the one a more
             specific level replaces marked as overridden, and fabric's own carrying "provided by fabric" (1.10.4.6.2).
             Any level whose list is empty or absent shows nothing, so a level another part of fabric adds later (the
             organisation's and the site's options) appears as soon as its data does.
    Inputs:  levels — {level: list of options} for the LEVELS (and "reservation" last for a reservation's view);
             an option is {name | code, data, …}.
    Returns: list of {"name", "code" (int or None), "data", "source" (the level), "provided" (bool: fabric's own),
             "overridden" (the more specific level that replaces it, or "")}, least specific first.
    Fails:   never.
    Feeds:   networks_view."""
    order = [lv for lv in (*LEVELS, "reservation") if levels.get(lv)]
    rows = []
    for i, level in enumerate(order):
        for o in levels[level]:
            key = _key(o)
            later = next((lv for lv in order[i + 1:] if any(_key(x) == key for x in levels[lv])), "")
            code = o.get("code") if o.get("code") is not None else CODES.get(key)
            rows.append({"name": key if not key.startswith("code ") else "", "code": code,
                         "data": str(o.get("data") or ""), "source": level,
                         "provided": level == "fabric" and key in PROVIDED, "overridden": later})
    return rows
