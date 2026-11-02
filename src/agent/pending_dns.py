def _zone(key):
    """Purpose: A zone key as people read it: the site's zone for dynamic_zone_var, else its name.
    Inputs:  key — str.
    Returns: str.
    Fails:   never.
    Feeds:   describe_dns."""
    return "the site's zone" if key == "dynamic_zone_var" else key


def describe_dns(route, body):
    """Purpose: A DNS change in a sentence ("Add A record www to home.lan", "Remove TSIG key npm").
    Inputs:  route — segments after /v1/ (zones/..., tsig/<name>/delete); body — the change's body.
    Returns: str.
    Fails:   never.
    Feeds:   agent/pending_thing.describe_change."""
    if route[0] == "tsig":
        return f"Remove TSIG key {route[1]}"
    if len(route) == 1:
        return f"Add zone {body.get('name', '')}".strip()
    zone, rtype, name = _zone(route[1]), body.get("type", ""), body.get("name", "")
    if route[2:] == ["delete"]:
        return f"Remove zone {zone} with its records"
    if route[2:] == ["records"]:
        return f"Add {rtype} record {name} to {zone}"
    if route[3:] == ["delete"]:
        return f"Delete {rtype} record {name} from {zone}"
    if body.get("link") == "on":
        return f"Link {name} from the landing page"
    return f"Stop linking {name} from the landing page"
