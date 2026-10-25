import os

from fabriclib.common.paths import FEDERATION_FILE
from fabriclib.federation.common.load_registry import load_registry


def is_root_site(registry_path=FEDERATION_FILE):
    """Purpose: whether this install is the root site (standalone, or the top of a federation): it holds the
             domain-wide parts (the root policy, fabric's fixed groups) and creates the first admin.
    Inputs:  registry_path — the federation registry (default this install's config/federation.yaml).
    Returns: True when this install has no upstream site.
    Fails:   yaml/OSError from load_registry for a malformed registry.
    Feeds:   samba/converge_domain, keycloak/configure_keycloak, setup/create_admin, setup/start_services."""
    if not os.path.exists(registry_path):
        return True
    return not load_registry(registry_path).get("upstream")
