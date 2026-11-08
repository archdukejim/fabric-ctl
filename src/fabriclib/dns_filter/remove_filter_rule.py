import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.add_filter_rule import KINDS
from fabriclib.dns_filter.common.filter_target import filter_target


def remove_filter_rule(actor, kind, name, source="cli", group="", dry=False):
    """Purpose: take a name out of the DNS filter's allows or blocks, everyone's or a client group's (manual
             1.12.2.14, 1.12.2.15). Saved in vars.yaml; applied by the next apply.
    Inputs:  actor — who asks (audit); kind — "allow" or "block"; name — as listed; source — "cli" or "web"; group —
             "" for everyone, else a group's name.
             dry — True: only checked, nothing saved or audited (a change held for the DNS filter tab's Apply, 1.12.3.17).
    Returns: {"kind", "name", "group"}.
    Fails:   ValidationError for another kind, an unknown group or a name not in that rule; OSError or yaml errors
             from the vars file and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/rules/delete)."""
    if kind not in KINDS:
        raise ValidationError("kind: allow or block")
    name = str(name or "").strip().rstrip(".").lower()
    with vars_lock():
        data = copy.deepcopy(load_vars())
        target, keys, label = filter_target(data, group)
        names = list(target.get(keys[kind]) or [])
        if name not in names:
            raise ValidationError(f"{name} is not {'allowed' if kind == 'allow' else 'blocked'} by a rule of {label}")
        target[keys[kind]] = [n for n in names if n != name]
        if not dry:
            save_vars(data)
    if not dry:
        write_audit(actor, f"DNS_FILTER_UN{kind.upper()}", f"{name} ({label})", source)
    return {"kind": kind, "name": name, "group": "" if label == "everyone" else label[6:]}
