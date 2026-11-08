import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit


def remove_filter_group(actor, name, source="cli", dry=False):
    """Purpose: remove a client group from the DNS filter (manual 1.12.2.15): its clients are answered as everyone
             again; the next apply drops its view, its rules zone and its own lists' copies.
    Inputs:  actor — who asks (audit); name — the group's name; source — "cli" or "web".
             dry — True: only checked, nothing saved or audited (a change held for the DNS filter tab's
             Apply, 1.12.3.17).
    Returns: {"name", "clients"} of the group removed.
    Fails:   ValidationError when no group has that name; OSError or yaml errors from the vars file and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/groups/delete)."""
    key = str(name or "").strip().lower()
    with vars_lock():
        data = copy.deepcopy(load_vars())
        groups = [g for g in data.get("dns_filter_groups") or [] if isinstance(g, dict)]
        gone = next((g for g in groups if str(g.get("name") or "").strip().lower() == key), None)
        if gone is None:
            raise ValidationError(f"no client group is called {key}")
        data["dns_filter_groups"] = [g for g in groups if g is not gone]
        if not dry:
            save_vars(data)
    if not dry:
        write_audit(actor, "DNS_FILTER_GROUP_REMOVE", key, source)
    return {"name": key, "clients": list(gone.get("clients") or [])}
