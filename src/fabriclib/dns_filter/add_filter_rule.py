import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.dns_filter.common.filter_target import filter_target

KINDS = ("allow", "block")


def add_filter_rule(actor, kind, name, source="cli", group="", dry=False):
    """Purpose: allow a name past every list, or block it whatever the lists say — the name and every name below it —
             for everyone or one client group (manual 1.12.2.7, 1.12.2.14, 1.12.2.15). A name in the other rule
             moves: allowing a blocked name unblocks it. Saved in vars.yaml; applied by the next apply.
    Inputs:  actor — who asks (audit); kind — "allow" or "block"; name — a DNS name; source — "cli" or "web"; group —
             "" for everyone, else a group's name.
             dry — True: only checked, nothing saved or audited (a change held for the DNS filter tab's Apply, 1.12.3.17).
    Returns: {"kind", "name" (normalised), "moved" (True when it left the other rule), "group" ("" or the name)}.
    Fails:   ValidationError for another kind, an unknown group, or from check_filter_settings (not a name, inside
             fabric's own domains, a group allow above them); nothing is saved then. OSError or yaml errors from the
             vars file and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/rules)."""
    if kind not in KINDS:
        raise ValidationError("kind: allow or block")
    other = "block" if kind == "allow" else "allow"
    name = str(name or "").strip().rstrip(".").lower()
    with vars_lock():
        data = copy.deepcopy(load_vars())
        target, keys, label = filter_target(data, group)
        moved = name in (target.get(keys[other]) or [])
        target[keys[kind]] = [*(target.get(keys[kind]) or []), name]
        target[keys[other]] = [n for n in target.get(keys[other]) or [] if n != name]
        check_filter_settings(data)                           # normalises the rules in data
        if not dry:
            save_vars(data)
    if not dry:
        write_audit(actor, f"DNS_FILTER_{kind.upper()}", f"{name} ({label})" + (" (moved)" if moved else ""), source)
    return {"kind": kind, "name": name, "moved": moved, "group": "" if label == "everyone" else label[6:]}
