import copy
import json

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.list_id import list_id
from fabriclib.dns_filter.common.list_memory import PEAK, list_memory

MAX_TICKS = 500          # lists one Apply may tick and untick (the catalogue holds about 90)


def _entries(items, what):
    """Purpose: the lists an Apply ticks or unticks, as sent: each {url, name}.
    Inputs:  items — the body's list; what — "tick" or "untick" (for the refusal).
    Returns: [(url, name)], in order, each URL once.
    Fails:   ValidationError for anything but a list of objects with a text url (and an optional text name).
    Feeds:   set_filter_lists."""
    if not isinstance(items, list) or len(items) > MAX_TICKS:
        raise ValidationError(f"{what}: a list of at most {MAX_TICKS} lists, each {{url, name}}")
    out, seen = [], set()
    for item in items:
        url = item.get("url") if isinstance(item, dict) else None
        name = item.get("name", "") if isinstance(item, dict) else None
        if not isinstance(url, str) or not url.strip() or not isinstance(name, str):
            raise ValidationError(f"{what}: each list is {{url, name}}, both text")
        if url.strip() not in seen:
            seen.add(url.strip())
            out.append((url.strip(), name.strip()))
    return out


def _estimates(v):
    """Purpose: each list's estimated memory, from the lists job's state (as list_memory reads it).
    Inputs:  v — vars (deploy_base_dir).
    Returns: {list id: MiB}.
    Fails:   never (no state yet: none).
    Feeds:   set_filter_lists (the refusal names each new list's share)."""
    try:
        with open(adguard_paths(v)["state"]) as f:
            state = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: s.get("memory_mb") for k, s in state.items() if isinstance(s, dict) and s.get("memory_mb") is not None}


def set_filter_lists(actor, tick, untick, source="web", dry=False):
    """Purpose: the lists form's Apply (manual 1.12.3.17): every tick and untick of it at once, in one save of
             vars.yaml. A list ticked that the site does not have yet (one of AdGuard's catalogue) is added; one
             unticked stays, with its copy. The memory rule (1.12.3.9) is checked for the whole set: when the ticked
             lists would not fit, nothing is saved and the refusal names the lists this Apply ticks and by how much
             the set is over. Made in AdGuard by apply_dns_filter.
    Inputs:  actor — who asks (audit); tick, untick — [{url, name}] (the name is used for a list new to the site; an
             existing list keeps its own); source — "web" or "cli"; dry — True: only checked, nothing saved or
             audited (held for the tab's Apply).
    Returns: {"ticked": [names], "unticked": [names], "added": [names], "memory": list_memory's result}.
    Fails:   ValidationError: tick or untick not a list of {url, name}, a URL in both, a name over 200 characters, a
             list unticked that the site does not have, a URL not http(s) (check_filter_settings), the memory rule
             (the lists, the estimate, the gap and how to make room); nothing is saved then. OSError or yaml errors
             from the vars file and the audit log.
    Feeds:   agent/change_dns_filter (POST /v1/dns-filter/lists/ticks)."""
    tick, untick = _entries(tick, "tick"), _entries(untick, "untick")
    both = {u for u, _ in tick} & {u for u, _ in untick}
    if both:
        raise ValidationError(f"a list is ticked and unticked at once: {sorted(both)[0]}")
    if any(len(n) > 200 for _, n in tick):
        raise ValidationError("a list's name is at most 200 characters")
    with vars_lock():
        data = copy.deepcopy(load_vars())
        lists = [dict(i) for i in data.get("dns_filter_lists") or [] if isinstance(i, dict)]
        by_url = {str(i.get("url") or "").strip(): i for i in lists}
        ticked, unticked, added = [], [], []
        for url, name in untick:
            if url not in by_url:
                raise ValidationError(f"the site has no list with the url {url}")
            if by_url[url].get("enabled", True) is not False:
                unticked.append(by_url[url].get("name") or url)
            by_url[url]["enabled"] = False
        for url, name in tick:
            current = by_url.get(url)
            if current is None:
                current = {"name": name or url, "url": url, "enabled": True}
                lists.append(current)
                by_url[url] = current
                added.append(current["name"])
            elif current.get("enabled", True) is not False:
                continue                     # already ticked: nothing changes
            current["enabled"] = True
            ticked.append(current["name"])
        data["dns_filter_lists"] = lists
        check_filter_settings(data)
        memory = list_memory(data, lists)
        if not memory["fits"]:
            est = _estimates(data)
            new = [f"{by_url[u]['name']} (~{est[list_id(u)]:.0f} MiB)" if list_id(u) in est else by_url[u]["name"]
                   for u, _ in tick if by_url[u]["name"] in ticked]
            gap = memory["peak_mb"] - memory["limit_mb"]
            raise ValidationError(
                f"the ticked lists do not fit: {', '.join(new) or 'the lists ticked'} would take the set to about "
                f"{memory['estimate_mb']:.0f} MiB, {memory['peak_mb']:.0f} MiB while AdGuard Home compiles them, "
                f"{gap:.0f} MiB past its limit of {memory['limit_mb']:.0f} MiB (its share of fabric's memory budget, "
                f"{memory['limit_mb'] / PEAK:.0f} MiB); untick about {gap / PEAK:.0f} MiB of lists, or give fabric "
                f"more memory (host_ram_capacity, memory_floors.adguard; manual 1.2.4.3). Nothing was changed")
        if not dry:
            save_vars(data)
    if not dry and (ticked or unticked):
        write_audit(actor, "DNS_FILTER_LISTS", f"ticked: {', '.join(ticked) or '-'}; unticked: "
                    f"{', '.join(unticked) or '-'}" + (f"; added: {', '.join(added)}" if added else ""), source)
    return {"ticked": ticked, "unticked": unticked, "added": added, "memory": memory}
