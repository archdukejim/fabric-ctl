import json
import time

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.adguard_api import adguard_api
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id
from fabriclib.dns_filter.common.list_memory import list_memory
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc
from fabriclib.system.memory_limit_mb import memory_limit_mb


def _age(ts):
    """Purpose: how long ago a time was, for people.
    Inputs:  ts — seconds since the epoch, or None.
    Returns: "never", "12 min ago", "5 h ago" or "3 days ago".
    Fails:   never.
    Feeds:   show_filter_status."""
    if not ts:
        return "never"
    s = max(0, int(time.time() - ts))
    return f"{s // 60} min ago" if s < 7200 else f"{s // 3600} h ago" if s < 172800 else f"{s // 86400} days ago"


def show_filter_status(v, password=None):
    """Purpose: `fabricctl dns-filter status` (manual 1.12.2.10, 1.12.3): whether the resolver and AdGuard Home answer,
             and each of the site's lists: ticked or not, its copy (fetched, last good copy, rules, estimated memory,
             last error) and AdGuard's own rule count; the memory rule's total.
    Inputs:  v — rendered vars (install_resolver, dns_filter, dns_filter_lists, memory_plan, adguard_mem_limit,
             deploy_base_dir, ip_adguard); password — adguard_api_password (None: AdGuard is not asked).
    Returns: exit status: 0 when both answer and every ticked list has a good copy; 1 otherwise (each problem
             printed).
    Fails:   never raises (a missing or unreadable state file reads as no list fetched yet).
    Feeds:   dns_filter/run_dns_filter_command."""
    if not v.get("install_resolver"):
        print(f"the DNS filter is off (dns_filter: {v.get('dns_filter')})")
        return 0
    r = resolver_rndc(["status"], timeout=15)
    ok = bool(r and r.returncode == 0)
    print(f"resolver: {'running' if ok else 'NOT answering'}   memory limit {memory_limit_mb(v, 'resolver')}m")
    counts = {}
    if password is not None:
        try:
            status = adguard_api(v, password, "GET", "/control/filtering/status") or {}
            counts = {f.get("url"): f.get("rules_count") for f in status.get("filters") or []}
            print(f"AdGuard Home: running   memory limit {memory_limit_mb(v, 'adguard')}m")
        except ValidationError as e:
            print(f"AdGuard Home: NOT answering ({e}): internet names fail closed (SERVFAIL) until it does")
            ok = False
    try:
        with open(adguard_paths(v)["state"]) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    for item in v.get("dns_filter_lists") or []:
        lid = list_id(item["url"])
        st = state.get(lid, {})
        on = item.get("enabled", True) is not False
        name = f"[{'x' if on else ' '}] {item.get('name') or item['url']}"
        if not st.get("last_success"):
            print(f"  {name}: no good copy yet — {st.get('error') or 'not fetched'}")
            ok = ok and not on
            continue
        loaded = counts.get(f"/lists/{lid}.txt")
        line = (f"  {name}: {st.get('rules', 0)} rules, ~{st.get('memory_mb')} MiB"
                + (f", {loaded} in AdGuard" if loaded is not None else "")
                + f"; fetched {_age(st.get('last_fetch'))}, good copy {_age(st.get('last_success'))}")
        print(line + (f"\n    last error: {st['error']}" if st.get("error") else ""))
    if not v.get("dns_filter_lists"):
        print("  no lists (dns_filter_lists: [])")
    m = list_memory(v)
    print(f"ticked lists: ~{m['estimate_mb']:.0f} MiB, ~{m['peak_mb']:.0f} MiB while AdGuard reads them"
          + (f", limit {m['limit_mb']:.0f} MiB" + ("" if m["fits"] else " — PAST THE LIMIT: untick a list")
             if m["limit_mb"] else ""))
    return 0 if ok else 1
