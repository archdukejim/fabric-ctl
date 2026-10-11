import json
import time

from fabriclib.dns_filter.common.list_zone import list_zone
from fabriclib.dns_filter.common.resolver_paths import resolver_paths
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


def show_filter_status(v):
    """Purpose: `fabricctl dns-filter status` (manual 1.12.2.10): whether the resolver answers, and each list's state —
             last fetched, last good copy, rules converted and skipped, its estimated memory, the last error.
    Inputs:  v — rendered vars (dns_filter, dns_filter_lists, memory_plan, deploy_base_dir).
    Returns: exit status: 0 when the resolver runs and every list has a good copy; 1 otherwise (each problem printed).
    Fails:   never raises (a missing or unreadable state file reads as no list fetched yet).
    Feeds:   dns_filter/run_dns_filter_command."""
    if not v.get("install_resolver"):
        print(f"the BIND resolver is off (dns_filter: {v.get('dns_filter')})")
        return 0
    r = resolver_rndc(["status"], timeout=15)
    running = bool(r and r.returncode == 0)
    print(f"resolver: {'running' if running else 'NOT answering'}   memory limit {memory_limit_mb(v, 'resolver')}m")
    try:
        with open(resolver_paths(v)["state"]) as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    ok = running
    total = 0.0
    for item in v.get("dns_filter_lists") or []:
        st = state.get(list_zone(item["url"]), {})
        name = item.get("name") or item["url"]
        if not st.get("last_success"):
            print(f"  {name}: no good copy yet — {st.get('error') or 'not fetched'}")
            ok = False
            continue
        total += st.get("memory_mb") or 0
        line = (f"  {name}: {st.get('rules', 0)} rules, {st.get('skipped', 0)} skipped, ~{st.get('memory_mb')} MiB;"
                f" fetched {_age(st.get('last_fetch'))}, good copy {_age(st.get('last_success'))}")
        print(line + (f"\n    last error: {st['error']}" if st.get("error") else ""))
    if not v.get("dns_filter_lists"):
        print("  no lists (dns_filter_lists: [])")
    else:
        print(f"lists in memory: ~{round(total)} MiB")
    return 0 if ok else 1
