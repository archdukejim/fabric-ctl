import hashlib
import json


def _hash(value):
    """Purpose: a stable digest of a JSON-able value.
    Inputs:  value — anything json.dumps takes.
    Returns: str, hex SHA-256 of its sorted JSON.
    Fails:   TypeError for a value JSON cannot hold.
    Feeds:   plan_digest."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def plan_digest(rendered):
    """Purpose: what the plan poll compares between runs (decision 2.1.10.24, manual 1.10.4.26): a digest of what Kea is
             rendered from, one of what DNS is rendered from, and the served subnets (the firewall's part).
    Inputs:  rendered — plan_to_dhcp's result (subnets, records, options, option_defs, client_classes).
    Returns: {"kea": hex, "dns": hex, "subnets": sorted list of the served networks}.
    Fails:   never for plan_to_dhcp's result.
    Feeds:   poll_plan, load_address_plan (the DNS digest an apply renders)."""
    kea = {k: rendered.get(k) or [] for k in ("subnets", "options", "option_defs", "client_classes")}
    subnets = sorted(s["subnet"] for s in rendered.get("subnets") or [])
    dns = {"records": sorted((r["name"], r["ip"]) for r in rendered.get("records") or []), "subnets": subnets}
    return {"kea": _hash(kea), "dns": _hash(dns), "subnets": subnets}
