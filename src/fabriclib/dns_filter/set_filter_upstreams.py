from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dns_filter.check_filter_settings import check_filter_settings


def set_filter_upstreams(actor, text, source="cli"):
    """Purpose: where AdGuard Home sends internet lookups (manual 1.12.3.2, 1.12.3.8): DNS-over-TLS upstreams, at least
             one, each an address with the name on its certificate (AdGuard reaches the address and verifies the
             certificate for it; the name is shown). Saved in vars.yaml; made in AdGuard by apply_dns_filter.
    Inputs:  actor — who asks (audit); text — "<address> <certificate name>" pairs separated by commas or new lines
             (e.g. "9.9.9.9 dns.quad9.net, 149.112.112.112 dns.quad9.net"); source — "cli" or "web".
    Returns: the upstreams saved, [{address, name}].
    Fails:   ValidationError for an empty text, a pair without its name, or from check_filter_settings (none given,
             not an address, not a name); OSError or yaml errors from the vars file and the audit log.
    Feeds:   agent/post_dns_filter (POST /v1/dns-filter/upstreams)."""
    text = str(text or "").strip()
    if not text:
        raise ValidationError("upstreams: at least one \"<address> <certificate name>\" pair")
    ups = []
    for part in text.replace("\n", ",").split(","):
        pair = part.split()
        if not pair:
            continue
        if len(pair) != 2:
            raise ValidationError(f"{part.strip()!r}: an address and the name on its certificate, e.g. "
                                  "9.9.9.9 dns.quad9.net")
        ups.append({"address": pair[0], "name": pair[1].lower()})
    with vars_lock():
        data = load_vars()
        check_filter_settings({**data, "dns_filter_upstreams": ups})
        data["dns_filter_upstreams"] = ups
        save_vars(data)
    write_audit(actor, "DNS_FILTER_UPSTREAMS", ", ".join(f"{u['address']} {u['name']}" for u in ups), source)
    return ups
