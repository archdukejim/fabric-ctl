import ipaddress

from fabriclib.common.console import info
from fabriclib.common.errors import ValidationError
from fabriclib.ipam.subnet_collision import subnet_collision

CHANGEABLE = ("host_ip", "lan_cidr", "lan_gateway", "dns_server")
NETWORK = ("host_ip", "lan_cidr", "lan_gateway")


def check_changes(changes, manifest):
    """Purpose: the settings a whole restore or a reinstall may change (manual 1.3.7.7), checked against the bundle's
             own (or the install's) before anything is unpacked or stopped.
    Inputs:  changes — {key: value}; manifest — the bundle's, or vars.yaml for a reinstall (host_ip, lan_cidr,
             lan_gateway, dns_server as they were; linked: whether the install had linked sites; fabric_subnet and
             plan_subnets, kept_plan_subnets's list, for the collision checks, 2.1.1.107).
    Returns: {key: (old, new)} of what changes.
    Fails:   ValidationError: a key that cannot change (the domain, the DC's name, the host's name: renamed after the
             restore, 4.2.4.3), an address that is not one, a gateway or address outside the subnet, the host on the
             gateway's address, an upstream DNS server that is not an address, a new address or subnet for an install
             with linked sites (decision 2.1.1.77: they keep its old address), a new subnet overlapping fabric's
             container network or another subnet of the address plan (subnet_collision, 2.1.1.107).
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
    if "lan_cidr" in changed:
        if manifest.get("fabric_subnet") is None and manifest.get("plan_subnets") is None:
            info("the bundle does not carry fabric's container network or the address plan's subnets (made by fabric "
                 "0.10.1): the new subnet is checked against them when setup writes it")
        found = subnet_collision(net, manifest.get("fabric_subnet"), manifest.get("plan_subnets"),
                                 moving=manifest.get("lan_cidr"))
        if found:
            raise ValidationError(f"the new subnet collides: {found}. Choose another subnet for the host's LAN")
    if manifest.get("linked") and set(changed) & set(NETWORK):
        raise ValidationError("this install has linked sites: they keep its old address, so it is not moved to a new "
                              "one (decision 2.1.1.77); unlink them first (`fabricctl federation status`)")
    return changed
