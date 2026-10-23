import json
import os

from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.clear_stale_dhcp_names import clear_stale_dhcp_names
from fabriclib.dhcp.common.hand_set_path import hand_set_path
from fabriclib.secrets.load_secrets import load_secrets


def clean_dhcp_names(v, actor, source):
    """Purpose: `fabricctl dhcp clean-names [--scheduled]`, the hourly fabric-dhcp-names timer's run (decision
             2.1.10.22): DHCP names left behind for addresses set by hand deleted, from the addresses the last apply
             kept; the cleanup alone, not an apply.
    Inputs:  v — the rendered vars (SetupContext.load_state().vars); actor, source — the audit's ("timer" or "cli").
    Returns: {"off": why} with Kea or its DNS registration off; else {"removed": clear_stale_dhcp_names()}.
    Fails:   ValidationError: no apply has kept the addresses yet, or one from clear_stale_dhcp_names (BIND refused);
             ValidationError from load_secrets (OpenBao locked); OSError, ValueError reading the kept file.
    Feeds:   dhcp/run_dhcp_command."""
    if not v.get("install_kea"):
        return {"off": "DHCP is off (install_kea: false): nothing to clean"}
    if not (v.get("dhcp") or {}).get("ddns", True):
        return {"off": "DHCP registers no names (dhcp.ddns: false): nothing to clean"}
    path = hand_set_path(v)
    if not os.path.exists(path):
        raise ValidationError(f"no apply has kept the addresses set by hand yet ({path}): run `sudo fabricctl --apply`")
    with open(path) as f:
        addresses = json.load(f).get("addresses") or []
    secret = load_secrets().get("kea_ddns_secret", "")
    return {"removed": clear_stale_dhcp_names(v, addresses, secret, actor, source)}
