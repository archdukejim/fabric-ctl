from fabriclib.common.ask import ask
from fabriclib.common.console import NC, YELLOW
from fabriclib.common.errors import ValidationError
from fabriclib.setup.common.parse_log_target import parse_log_target


def ask_log_target(ctx):
    """Purpose: where log forwarding sends the logs, asked when it is turned on with none set (manual 2.1.15.1, the
             `log_forwarding` setting): a syslog server (`host` or `host:port`, TLS, 6514 by default) or an
             Elasticsearch / OpenSearch URL (`https://…`, its password set later:
             `fabricctl logs set-password elastic`).
    Inputs:  ctx — SetupContext: vars (log_forwarding; changed). Interactive.
    Returns: True with ctx.vars["log_forwarding"] holding the destination; False when Enter was given (nothing set:
             the item stays off). A host that is no name or address, a port outside 1-65535 or a URL that is not https
             is refused, saying why (parse_log_target), and asked again.
    Fails:   EOFError from input().
    Feeds:   setup/advanced/ask_part (log forwarding turned on)."""
    while True:
        answer = ask("setup.logs.target", "    Send the logs to: a syslog server (host or host:port, TLS) or an "
                     "Elasticsearch URL (https://…); Enter for none: ")
        if not answer:
            return False
        try:
            ctx.vars["log_forwarding"] = parse_log_target(answer)
            return True
        except ValidationError as e:
            print(f"    {YELLOW}{e}{NC}")
