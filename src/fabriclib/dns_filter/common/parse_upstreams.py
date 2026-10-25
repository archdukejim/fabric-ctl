from fabriclib.common.errors import ValidationError


def parse_upstreams(text):
    """Purpose: the DNS filter's upstreams from text (manual 1.12.3.8): "<address> <certificate name>" pairs separated
             by commas or new lines, e.g. "9.9.9.9 dns.quad9.net, 149.112.112.112 dns.quad9.net". Only the form is
             checked here; check_filter_settings checks the address and the name.
    Inputs:  text — str (None counts as empty).
    Returns: [{"address", "name" (lower case)}], in the order given.
    Fails:   ValidationError for an empty text, or a pair without its name.
    Feeds:   dns_filter/set_filter_upstreams (the DNS filter tab, POST /v1/dns-filter/upstreams),
             settings/settings_from_form (the wizard's upstreams, manual 1.8.5)."""
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
    return ups
