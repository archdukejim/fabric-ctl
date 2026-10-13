from fabriclib.federation.common.load_registry import load_registry


def visible_sites(v):
    """Purpose: the sites this install's console and agent show and edit in the address manager (manual 1.10.4.9,
             1.10.4.21, decision 2.1.10.27): its own site first, then the sites that joined below it (its federation
             registry, 2.1.9.19), so the top sees every house and a house only itself. AD's access rules still decide
             every write (1.10.4.13.3).
    Inputs:  v — fabric vars (site_name).
    Returns: list of {"name", "own" (bool)}, the own site first, the others by name.
    Fails:   yaml/OSError from load_registry for a malformed registry.
    Feeds:   common/site_scope, networks_overview."""
    own = v.get("site_name") or ""
    below = sorted(n for n in (load_registry().get("sites") or {}) if n and n != own)
    return [{"name": own, "own": True}] + [{"name": n, "own": False} for n in below]
