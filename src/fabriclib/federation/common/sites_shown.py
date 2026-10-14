from fabriclib.federation.common.load_registry import load_registry
from fabriclib.ipam.visible_sites import visible_sites


def sites_shown(v, registry=None):
    """Purpose: which sites' address plans this install shows (2.1.9.22, manual 1.9.8.20): the top (no upstream) every
             site; any other site itself and the sites below it, as the Networks tab (visible_sites) — never a
             sibling's or a parent's.
    Inputs:  v — fabric vars (site_name); registry — load_registry()'s dict (default: read it).
    Returns: None for every site (the top), else list of str site names.
    Fails:   yaml/OSError from load_registry for a malformed registry.
    Feeds:   federation_overview, show_networks, ipam/run_ipam_command (find)."""
    registry = registry if registry is not None else load_registry()
    if not registry.get("upstream"):
        return None
    return [s["name"] for s in visible_sites(v)]
