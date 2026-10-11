from fabriclib.consent.groups import GROUPS
from fabriclib.consent.load_consent import load_consent

# the recommended host changes the menu turns on and off (manual 1.2.9.11.3); domain membership is its setting's item
# (host_join_domain) and the resolver its choice's (use_host_dns)
TOGGLED = [g for g, meta in GROUPS.items() if meta["level"] == "recommended" and g != "member"]


def initial_host_choices(config_dir, approve=None, decline=None):
    """Purpose: whether each recommended host change starts on or off in setup's menu and plan (decision 2.1.2.18): on
             unless declined before (consent.yaml) or by --decline; --approve turns one back on; a change whose needed
             one is off is off too (the firewall needs ports, the host's own rules need the firewall).
    Inputs:  config_dir — the install's config folder; approve, decline — the --approve / --decline values (lists of
             comma-separated group names; "all" approves all).
    Returns: {group: bool} for every group in TOGGLED.
    Fails:   OSError / yaml errors from load_consent.
    Feeds:   setup/run_setup (ctx.host_choices)."""
    def names(values):
        return {n.strip() for item in (values or []) for n in str(item).split(",") if n.strip()}
    approved, declined = names(approve), names(decline)
    recorded = load_consent(config_dir) or {}
    out = {}
    for group in TOGGLED:
        on = (recorded.get(group) or {}).get("answer") != "no"
        if group in approved or "all" in approved:
            on = True
        if group in declined:
            on = False
        needs = GROUPS[group].get("needs")
        out[group] = on and (needs not in out or out[needs])
    return out
