import ipaddress
from urllib.parse import urlsplit

from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.setup.common.valid_setting import HOST_RE


def _host_ok(host):
    """Purpose: whether a destination's host is a DNS name or an IP address.
    Inputs:  host — str.
    Returns: bool.
    Fails:   never.
    Feeds:   ask_log_target."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_RE.match(host or ""))


def ask_log_target(ctx):
    """Purpose: where log forwarding sends the logs, asked when it is turned on with none set (manual 2.1.15.1, the
             `log_forwarding` setting): a syslog server (`host` or `host:port`, TLS, 6514 by default) or an
             Elasticsearch / OpenSearch URL (`https://…`, its password set later: `fabricctl logs set-password elastic`).
    Inputs:  ctx — SetupContext: vars (log_forwarding; changed). Interactive.
    Returns: True with ctx.vars["log_forwarding"] holding the destination; False when Enter was given (nothing set:
             the item stays off). A host that is no name or address, a port outside 1-65535 or a URL that is not https
             is refused, saying why, and asked again.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/ask_part (log forwarding turned on)."""
    while True:
        answer = ask("setup.logs.target", "    Send the logs to: a syslog server (host or host:port, TLS) or an "
                     "Elasticsearch URL (https://…); Enter for none: ")
        if not answer:
            return False
        if "://" in answer:
            url = urlsplit(answer)
            if url.scheme == "https" and _host_ok(url.hostname or ""):
                ctx.vars["log_forwarding"] = {"elastic": {"url": answer}}
                return True
            print(f"    {YELLOW}{answer!r}: an Elasticsearch URL starts https:// (verified TLS) and names its host{NC}")
            continue
        host, _, port = answer.rpartition(":") if answer.count(":") == 1 else (answer, "", "")
        if _host_ok(host) and (not port or (port.isdigit() and 1 <= int(port) <= 65535)):
            ctx.vars["log_forwarding"] = {"syslog": {"host": host, "port": int(port or 6514)}}
            return True
        print(f"    {YELLOW}{answer!r}: a host name or address, optionally :port (1-65535){NC}")
