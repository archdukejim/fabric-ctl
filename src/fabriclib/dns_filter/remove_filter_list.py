import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit


def remove_filter_list(actor, url, source="cli"):
    """Purpose: take a list off the site (manual 1.12.3.5): saved in vars.yaml; AdGuard drops it at the next sync
             (apply_dns_filter). Its copy stays while it is in AdGuard's catalogue (so it can be ticked again at once).
    Inputs:  actor — who asks (audit); url — the list's url, as listed; source — "cli" or "web".
    Returns: {"name", "url"} of the list removed.
    Fails:   ValidationError when the site has no list with that url; OSError or yaml errors from the vars file and
             the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/lists/delete)."""
    url = str(url or "").strip()
    with vars_lock():
        data = copy.deepcopy(load_vars())
        lists = list(data.get("dns_filter_lists") or [])
        gone = next((i for i in lists if isinstance(i, dict) and str(i.get("url") or "").strip() == url), None)
        if gone is None:
            raise ValidationError(f"the site has no list with the url {url}")
        data["dns_filter_lists"] = [i for i in lists if i is not gone]
        save_vars(data)
    write_audit(actor, "DNS_FILTER_LIST_REMOVE", f"{gone.get('name')} {url}", source)
    return {"name": gone.get("name") or url, "url": url}
