import json

from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id
from fabriclib.dns_filter.common.mem_mb import mem_mb

PEAK = 2.5          # compiling the lists briefly takes this many times their steady size (2.1 on the Pi, 2.6 on amd64)


def list_memory(v, lists=None):
    """Purpose: the memory rule of manual 1.12.3.9: the ticked lists' estimated size (rules × 0.14 KB each, from the
             lists job's state) and whether their peak while AdGuard compiles them (× PEAK) stays within
             adguard_mem_limit.
    Inputs:  v — fabric vars (dns_filter_lists, adguard_mem_limit, deploy_base_dir); lists — the lists to count
             (default: dns_filter_lists), each {url, enabled}.
    Returns: {"estimate_mb": the ticked lists' steady size, "peak_mb": × PEAK, "limit_mb": the limit or None, "fits":
             bool, "unknown": [names of ticked lists with no copy yet, not counted]}.
    Fails:   never (no state yet counts nothing).
    Feeds:   dns_filter/set_filter_list (a list ticked), dns_filter/filter_overview, show_filter_status."""
    try:
        with open(adguard_paths(v)["state"]) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    total, unknown = 0.0, []
    for item in v.get("dns_filter_lists") if lists is None else lists:
        if item.get("enabled", True) is False:
            continue
        mb = (state.get(list_id(item["url"])) or {}).get("memory_mb")
        if mb is None:
            unknown.append(item.get("name") or item["url"])
        else:
            total += float(mb)
    limit = mem_mb(v.get("adguard_mem_limit"))
    return {"estimate_mb": round(total, 1), "peak_mb": round(total * PEAK, 1),
            "limit_mb": round(limit, 1) if limit else None, "fits": limit is None or total * PEAK <= limit,
            "unknown": unknown}
