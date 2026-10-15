import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.dns_filter.common.list_id import list_id
from fabriclib.dns_filter.common.list_memory import PEAK, list_memory


def set_filter_list(actor, url, enabled=True, name="", source="cli"):
    """Purpose: tick or untick one of the site's lists (manual 1.12.3.5), or add one (from the catalogue or by URL):
             saved in vars.yaml. A list unticked stays, with its copy. Ticking is refused when the ticked lists'
             peak would pass AdGuard Home's memory limit (1.12.3.9). Made in AdGuard by apply_dns_filter.
    Inputs:  actor — who asks (audit); url — the list's URL; enabled — True to tick (or add), False to untick; name —
             its name for a new list (the URL when empty; an existing list keeps its name); source — "cli" or "web".
    Returns: {"name", "url", "id", "enabled", "added": True for a new list, "memory": list_memory's result}.
    Fails:   ValidationError: not http(s) (check_filter_settings), a name over 200 characters, unticking a list the
             site does not have, the memory rule (with the estimate and the limit); nothing is saved then. OSError
             or yaml errors from the vars file and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/lists, /v1/dns-filter/lists/set)."""
    url, name = str(url or "").strip(), str(name or "").strip()
    if len(name) > 200:
        raise ValidationError("a list's name is at most 200 characters")
    with vars_lock():
        data = copy.deepcopy(load_vars())
        lists = [dict(i) for i in data.get("dns_filter_lists") or [] if isinstance(i, dict)]
        current = next((i for i in lists if str(i.get("url") or "").strip() == url), None)
        added = current is None
        if added and not enabled:
            raise ValidationError(f"the site has no list with the url {url}")
        if added:
            current = {"name": name or url, "url": url, "enabled": True}
            lists.append(current)
        current["enabled"] = bool(enabled)
        data["dns_filter_lists"] = lists
        check_filter_settings(data)
        memory = list_memory(data, lists)
        if enabled and not memory["fits"]:
            raise ValidationError(
                f"{current['name']} does not fit: the ticked lists would take about {memory['estimate_mb']:.0f} MiB, "
                f"past AdGuard Home's share of fabric's memory budget ({memory['limit_mb'] / PEAK:.0f} MiB; "
                f"{memory['limit_mb']:.0f} MiB while it compiles them); untick a list first, or give fabric more "
                f"memory (host_ram_capacity, memory_floors.adguard; manual 1.2.4.3)")
        save_vars(data)
    write_audit(actor, "DNS_FILTER_LIST_" + ("ADD" if added else "ON" if enabled else "OFF"),
                f"{current['name']} {url}", source)
    return {"name": current["name"], "url": url, "id": list_id(url), "enabled": bool(enabled), "added": added,
            "memory": memory}
