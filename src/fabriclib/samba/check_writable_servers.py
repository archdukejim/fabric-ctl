import ipaddress
import re

from fabriclib.common.errors import ValidationError

MAX_SERVERS = 8
_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_NAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")


def check_writable_servers(value):
    """Purpose: the setting `ad_writable_servers` (decision 2.1.6.57, manual 1.6.11.13.1): the writable DCs a read-only
             DC's site writes at, in the order to try, checked at apply before anything is rendered.
    Inputs:  value — the setting as rendered (None, or a list).
    Returns: list of str, each trimmed (empty: `ad_join_server` is used, samba/writable_server).
    Fails:   ValidationError naming the setting: not a list; an entry that is not a DNS name or an IP address; a
             repeat; more than MAX_SERVERS.
    Feeds:   deploy/check_samba_settings."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError(f"ad_writable_servers must be a list of DC names or addresses (got {value!r})")
    out = []
    for entry in value:
        name = entry.strip() if isinstance(entry, str) else ""
        ok = bool(_NAME.match(name))
        if not ok and name:
            try:
                ipaddress.ip_address(name)
                ok = True
            except ValueError:
                ok = False
        if not ok:
            raise ValidationError(f"ad_writable_servers: {entry!r} is not a DNS name or an IP address")
        if name.lower() in [o.lower() for o in out]:
            raise ValidationError(f"ad_writable_servers: {name} is listed twice")
        out.append(name)
    if len(out) > MAX_SERVERS:
        raise ValidationError(f"ad_writable_servers: at most {MAX_SERVERS} writable DCs (got {len(out)})")
    return out
