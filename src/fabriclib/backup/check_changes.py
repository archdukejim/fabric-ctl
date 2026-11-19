import ipaddress

from fabriclib.common.errors import ValidationError

CHANGEABLE = ("host_ip", "lan_cidr", "lan_gateway")


def check_changes(changes, manifest):
    """Purpose: the settings a whole restore may change (manual 1.3.7.7), checked against the bundle's own before
             anything is unpacked.
    Inputs:  changes — {key: value}; manifest — the bundle's (host_ip, lan_cidr, lan_gateway as it was made).
    Returns: {key: (old, new)} of what changes.
    Fails:   ValidationError: a key that cannot change (the domain, the DC's name, the host's name: renamed after the
             restore, 4.2.4.3), an address that is not one, a gateway or address outside the subnet, the host on the
             gateway's address.
    Feeds:   restore_bundle, run_reinstall_command (checked before anything is stopped)."""
    bad = sorted(set(changes) - set(CHANGEABLE))
    if bad:
        raise ValidationError(f"a restore changes only {', '.join(CHANGEABLE)}; not {', '.join(bad)}"
                              + (" (rename the host after the restore: manual 4.2.4.3)" if "hostname" in bad else ""))
    new = {k: changes.get(k, manifest.get(k)) for k in CHANGEABLE}
    try:
        net = ipaddress.ip_network(new["lan_cidr"], strict=False)
        host, gateway = ipaddress.ip_address(new["host_ip"]), ipaddress.ip_address(new["lan_gateway"])
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"the new network is not valid: {exc}") from None
    if host not in net or gateway not in net:
        raise ValidationError(f"{host} and its gateway {gateway} must both be in {net}")
    if host == gateway:
        raise ValidationError(f"the host's address {host} is the gateway's")
    return {k: (manifest.get(k), new[k]) for k in CHANGEABLE if str(manifest.get(k)) != str(new[k])}
