import json

from fabriclib.common.errors import ValidationError
from fabriclib.settings.check_wizard_value import check_wizard_value
from fabriclib.settings.constants import WIZARD_KEYS
from fabriclib.settings.read_settings import read_settings
from fabriclib.system.host_ram_gb import host_ram_gb
from fabriclib.system.plan_memory import SERVICES, plan_memory

# the settings that change which parts run, or how much memory they share: the plan shows the memory plan then
_SIZING = ("dns_filter", "install_fluentbit", "host_ram_capacity")


def _same(a, b):
    """Purpose: whether two settings' values are the same (maps compared by content, not key order).
    Inputs:  a, b — JSON-able values.
    Returns: bool.
    Fails:   never for JSON-able values.
    Feeds:   plan_settings."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _show(value):
    """Purpose: one value as one line of text for the plan.
    Inputs:  value — a setting's value.
    Returns: str: "on"/"off" for a bool, "—" for nothing, JSON for a map or list, else the value.
    Fails:   never for JSON-able values.
    Feeds:   plan_settings."""
    if isinstance(value, bool):
        return "on" if value else "off"
    if value in (None, {}, []):
        return "—"
    return json.dumps(value) if isinstance(value, (dict, list)) else str(value)


def _limits(v):
    """Purpose: the memory plan's limit per service, or None when the settings do not fit (today's may not).
    Inputs:  v — settings.
    Returns: {service: MB per container} or None.
    Fails:   never.
    Feeds:   plan_settings."""
    try:
        return plan_memory(v)["limits"]
    except ValidationError:
        return None


def plan_settings(v, given, ignored=(), source="web", have_gb=None):
    """Purpose: the plan for a change of the wizard's settings (manual 1.8.5.5), from the wizard, a settings file in
             the console or `fabricctl settings import`; nothing changes. Each value is checked as setup checks it
             (check_wizard_value); then together: log forwarding on needs a destination, and the parts that
             run must fit the memory (plan_memory).
             One invalid value refuses the whole change.
    Inputs:  v — the settings as saved (vars.yaml); given — {wizard key: value}, any subset (other keys are a caller's
             error); ignored — [{"key", "reason"}] a file's ignored keys, carried into the plan; source — "web",
             "file" or "cli" (audited as where it came from); have_gb — the host's GB (None: measured).
    Returns: {"source", "given", "ignored", "base": today's wizard settings (read_settings), "settings": the whole set
             after the change, "changes": [{"key", "old", "new"}] (texts, the wizard's order), "keys": the changed keys,
             "parts": [{"service", "change": started|stopped}], "memory": None or {"budget_mb", "rows":
             [{"service", "before", "after"}]} (when a part or the memory changes)}.
    Fails:   ValidationError naming the key and why (nothing changes); KeyError for a key that is not the wizard's.
    Feeds:   agent/post_settings (POST /v1/settings/plan; a stale plan made again at Apply),
             settings/run_settings_command (`fabricctl settings import`)."""
    have_gb = host_ram_gb() if have_gb is None else have_gb
    base = read_settings(v, have_gb)
    new = dict(base)
    for key in WIZARD_KEYS:
        if key in given:
            new[key] = check_wizard_value(key, given[key], v, have_gb)
    if new["install_fluentbit"] and not any(new["log_forwarding"].get(p) for p in ("syslog", "elastic")):
        raise ValidationError("install_fluentbit: log forwarding needs somewhere to send the logs (log_forwarding: "
                              "a syslog server or an Elasticsearch URL)")
    sized = {**v, **{k: new[k] for k in _SIZING}}
    try:
        after = plan_memory(sized)["limits"]
    except ValidationError as e:
        raise ValidationError(f"host_ram_capacity: {e}") from None
    changed = [k for k in WIZARD_KEYS if not _same(base[k], new[k])]
    memory, parts = None, []
    if any(k in changed for k in _SIZING):
        before = _limits({**v, "host_ram_capacity": base["host_ram_capacity"]}) or {}
        parts = ([{"service": SERVICES[s][3], "change": "started"} for s in after if s not in before]
                 + [{"service": SERVICES[s][3], "change": "stopped"} for s in before if s not in after])
        memory = {"budget_mb": plan_memory(sized)["budget_mb"],
                  "rows": [{"service": SERVICES[s][3], "before": before.get(s), "after": after.get(s)}
                           for s in SERVICES if s in before or s in after]}
    return {"source": source, "given": given, "ignored": list(ignored), "base": base, "settings": new,
            "changes": [{"key": k, "old": _show(base[k]), "new": _show(new[k])} for k in changed],
            "keys": changed, "parts": parts, "memory": memory}
