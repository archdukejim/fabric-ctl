import ipaddress

from fabriclib.common.errors import ValidationError

CHANGEABLE = ("host_ip", "lan_cidr", "lan_gateway", "dns_server")
NETWORK = ("host_ip", "lan_cidr", "lan_gateway")


def check_changes(changes, manifest):
    """Purpose: the settings a whole restore or a reinstall may change (manual 1.3.7.7), checked against the bundle's
             own (or the install's) before anything is unpacked or stopped.
    Inputs:  changes — {key: value}; manifest — the bundle's, or vars.yaml for a reinstall (host_ip, lan_cidr,
             lan_gateway, dns_server as they were; linked: whether the install had linked sites).
    Returns: {key: (old, new)} of what changes.
    Fails:   ValidationError: a key that cannot change (the domain, the DC's name, the host's name: renamed after the
             restore, 4.2.4.3), an address that is not one, a gateway or address outside the subnet, the host on the
             gateway's address, an upstream DNS server that is not an address, a new address or subnet for an install
             with linked sites (decision 2.1.1.77: they keep its old address).
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
    if "dns_server" in changes:
        try:
            ipaddress.ip_address(changes["dns_server"])
        except ValueError:
            raise ValidationError(f"dns_server {changes['dns_server']!r} is not an address") from None
    changed = {k: (manifest.get(k), new[k]) for k in CHANGEABLE if str(manifest.get(k)) != str(new[k])}
    if manifest.get("linked") and set(changed) & set(NETWORK):
        raise ValidationError("this install has linked sites: they keep its old address, so it is not moved to a new "
                              "one (decision 2.1.1.77); unlink them first (`fabricctl federation status`)")
    return changed
