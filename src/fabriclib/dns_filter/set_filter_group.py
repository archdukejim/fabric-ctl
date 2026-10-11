import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.check_filter_settings import check_filter_settings


def set_filter_group(actor, name, clients, source="cli"):
    """Purpose: add a client group to the DNS filter, or change an existing group's clients (manual 1.12.2.15). A new
             group starts with safe search off and nothing of its own: it is answered as everyone until something
             is added. Saved in vars.yaml; applied by the next apply.
    Inputs:  actor — who asks (audit); name — the group's name; clients — its addresses and subnets: a list, or one
             string separated by commas, spaces or new lines; source — "cli" or "web".
    Returns: {"name" (normalised), "clients" (normalised), "added": True for a new group}.
    Fails:   ValidationError from check_filter_settings (a bad or reserved name, no clients, an address that is not
             one, outside the networks answered, inside fabric's own, in another group); nothing is saved then.
             OSError or yaml errors from the vars file and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/groups)."""
    if isinstance(clients, str):
        clients = clients.replace(",", " ").split()
    if not isinstance(clients, list):
        raise ValidationError("clients: addresses and subnets")
    key = str(name or "").strip().lower()
    with vars_lock():
        data = copy.deepcopy(load_vars())
        groups = data.get("dns_filter_groups") if isinstance(data.get("dns_filter_groups"), list) else []
        data["dns_filter_groups"] = groups
        current = next((g for g in groups if str(g.get("name") or "").strip().lower() == key), None)
        added = current is None
        if added:
            groups.append({"name": key, "clients": clients, "safe_search": False, "youtube": "strict", "allow": [],
                           "block": []})
        else:
            current["clients"] = clients
        check_filter_settings(data)
        save_vars(data)
    group = next(g for g in data["dns_filter_groups"] if g["name"] == key)
    write_audit(actor, "DNS_FILTER_GROUP_" + ("ADD" if added else "CLIENTS"), f"{key}: {' '.join(group['clients'])}",
                source)
    return {"name": key, "clients": group["clients"], "added": added}
