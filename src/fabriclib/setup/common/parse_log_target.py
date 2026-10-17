import ipaddress
from urllib.parse import urlsplit

from fabriclib.common.errors import ValidationError
from fabriclib.setup.common.valid_setting import HOST_RE


def _host_ok(host):
    """Purpose: whether a destination's host is a DNS name or an IP address.
    Inputs:  host — str.
    Returns: bool.
    Fails:   never.
    Feeds:   parse_log_target."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_RE.match(host or ""))


def parse_log_target(answer):
    """Purpose: where log forwarding sends the logs, from one line of text (manual 2.1.15.1, the `log_forwarding`
             setting): a syslog server (`host` or `host:port`, TLS, 6514 by default) or an Elasticsearch / OpenSearch
             URL (`https://…`).
    Inputs:  answer — str, already stripped; not empty.
    Returns: {"elastic": {"url": answer}} or {"syslog": {"host": host, "port": int}}.
    Fails:   ValidationError saying why: a URL that is not https or names no host; a host that is no name or address,
             or a port outside 1-65535.
    Feeds:   setup/advanced/ask_log_target (asked again on a refusal), settings/settings_from_form (the wizard's
             log forwarding, manual 1.8.5)."""
    if "://" in answer:
        url = urlsplit(answer)
        if url.scheme == "https" and _host_ok(url.hostname or ""):
            return {"elastic": {"url": answer}}
        raise ValidationError(f"{answer!r}: an Elasticsearch URL starts https:// (verified TLS) and names its host")
    host, _, port = answer.rpartition(":") if answer.count(":") == 1 else (answer, "", "")
    if _host_ok(host) and (not port or (port.isdigit() and 1 <= int(port) <= 65535)):
        return {"syslog": {"host": host, "port": int(port or 6514)}}
    raise ValidationError(f"{answer!r}: a host name or address, optionally :port (1-65535)")
