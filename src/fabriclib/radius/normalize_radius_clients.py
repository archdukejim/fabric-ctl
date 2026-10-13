import ipaddress
import re

from fabriclib.common.errors import ValidationError
from fabriclib.radius.nas.nas_profile import nas_profile
from fabriclib.radius.nas.profiles import DEFAULT_TRANSPORT, DEFAULT_VENDOR, TRANSPORTS

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")
# A secret a switch's CLI takes without quoting: printable ASCII without spaces,
# quotes, backslashes or `$` (FreeRADIUS expands ${...} inside quoted strings).
SECRET_RE = re.compile(r"^[A-Za-z0-9!#%&()*+,./:;<=>?@\[\]^_{|}~-]{16,128}$")


def normalize_radius_clients(clients):
    """Purpose: Check radius_clients, the switches and access points that may ask FreeRADIUS.
    Inputs:  clients — list of {name, address, message_authenticator (default true), vendor (unifi | cisco | generic,
             default generic), transport (udp | radsec, default udp), secret (optional: one a switch already has)},
             or None.
    Returns: (clients, {name: secret}): entries {"name" (lower case), "address" (a single IP or a network),
             "message_authenticator" (bool), "vendor", "transport"}, and the secrets taken out of them, to be kept in
             fabric's secrets.
    Fails:   ValidationError: an entry that is not a dict, a bad name, a name listed twice, an address that is not an IP
             or network (host bits must be zero), 0/0, overlapping clients, a bad secret, an unknown vendor
             (nas_profile), a transport other than udp or radsec, or radsec for a vendor whose profile does not offer
             it (manual 1.11.1.3).
    Feeds:   deploy/merge_radius_clients (apply), add_radius_client; SECRET_RE is reused by rotate_radius_secret;
             tests/freeradius/run.py,
             tests/render.py.
    Notes:   SECRET_RE keeps a secret typeable on a switch CLI without quoting and free of `$` (FreeRADIUS expands
             ${...} inside quoted strings).
    """
    out, embedded, seen_names, seen_nets = [], {}, set(), []
    for c in clients or []:
        if not isinstance(c, dict):
            raise ValidationError("radius_clients: each entry is {name, address}")
        name = str(c.get("name", "")).strip().lower()
        if not NAME_RE.match(name):
            raise ValidationError(f"radius_clients: {name!r} is not a name (a-z, 0-9, -; up to 32)")
        if name in seen_names:
            raise ValidationError(f"radius_clients: {name} is listed twice")
        try:
            net = ipaddress.ip_network(str(c.get("address", "")).strip(), strict=True)
        except ValueError:
            raise ValidationError(f"radius_clients: {name}: address must be an IP address or network "
                                  f"(e.g. 192.168.4.2 or 192.168.10.0/24)")
        if net.prefixlen == 0:
            raise ValidationError(f"radius_clients: {name}: 'any address' is not a RADIUS client")
        for other, onet in seen_nets:
            if net.version == onet.version and net.overlaps(onet):
                raise ValidationError(f"radius_clients: {name} and {other} overlap")
        try:
            profile = nas_profile(c.get("vendor") or DEFAULT_VENDOR)
        except ValidationError as exc:
            raise ValidationError(f"radius_clients: {name}: {exc}")
        transport = str(c.get("transport") or DEFAULT_TRANSPORT).strip().lower()
        if transport not in TRANSPORTS:
            raise ValidationError(f"radius_clients: {name}: transport must be one of " + ", ".join(TRANSPORTS))
        if transport == "radsec" and not profile["radsec"]:
            raise ValidationError(f"radius_clients: {name}: RadSec is not offered for vendor {profile['vendor']} "
                                  f"(Cisco only for now: manual 1.11.1.2)")
        entry = {"name": name, "address": str(net.network_address) if net.num_addresses == 1 else str(net),
                 "message_authenticator": bool(c.get("message_authenticator", True)),
                 "vendor": profile["vendor"], "transport": transport}
        secret = c.get("secret")
        if secret:
            if not SECRET_RE.match(str(secret)):
                raise ValidationError(f"radius_clients: {name}: the secret must be 16-128 printable characters, "
                                      f"without spaces or quotes")
            embedded[name] = str(secret)
        seen_names.add(name)
        seen_nets.append((name, net))
        out.append(entry)
    return out, embedded
