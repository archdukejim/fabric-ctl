CLASSES = {"IN", "CH", "HS"}


def _one_line(tokens):
    """Purpose: a record's rdata on one line, with the parentheses that let BIND continue it over several lines taken
             out (BIND writes a long DHCID as `DHCID ( AAEB… <newline> …= )`, 2.3.10.11.16).
    Inputs:  tokens — the rdata's tokens, from every line of the record.
    Returns: str, the tokens joined by single spaces, no "(" or ")".
    Fails:   never.
    Feeds:   zone_records."""
    return " ".join(" ".join(tokens).replace("(", " ").replace(")", " ").split())


def zone_records(text, zone, types):
    """Purpose: the records of the given types in a zone file, owners made absolute.
    Inputs:  text — a zone file as fabric renders it or BIND writes it ($ORIGIN, relative owners, an owner left out
             to repeat the last, TTL and class optional, comments, a record continued over lines in `( … )`); zone —
             its name; types — set of upper-case record types to return (e.g. {"PTR", "DHCID"}).
    Returns: list of (owner FQDN with trailing dot, lower-case; type; rdata on one line, without the parentheses a
             continued record had: 2.3.10.11.16 found a two-line DHCID kept as its first line only, which BIND
             then refused, "unbalanced parentheses").
    Fails:   never: lines it cannot read are skipped.
    Feeds:   dns/merge_dynamic_records (Kea's PTR and DHCID in a reverse zone), dhcp/stale_dhcp_names (Kea's names
             in dhcp.<domain>)."""
    origin, owner, out, depth, pending = zone.rstrip(".") + ".", None, [], 0, None
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        if not line.strip():
            continue
        if depth:                                    # inside ( ... ): the SOA, or a wanted record continued
            depth += line.count("(") - line.count(")")
            if pending:
                pending[2].extend(line.split())
                if depth <= 0:
                    out.append((pending[0], pending[1], _one_line(pending[2])))
                    pending, depth = None, 0
            continue
        if line.startswith("$ORIGIN"):
            origin = line.split()[1].rstrip(".") + "."
            continue
        if line.startswith("$"):
            continue
        tokens = line.split()
        if not raw[:1].isspace():
            owner = tokens.pop(0)
            owner = origin if owner == "@" else owner if owner.endswith(".") else f"{owner}.{origin}"
        while tokens and (tokens[0].isdigit() or tokens[0].upper() in CLASSES):
            tokens.pop(0)
        depth = line.count("(") - line.count(")")
        if owner and len(tokens) >= 2 and tokens[0].upper() in types:
            if depth > 0:
                pending = [owner.lower(), tokens[0].upper(), tokens[1:]]
            else:
                out.append((owner.lower(), tokens[0].upper(), _one_line(tokens[1:])))
                depth = 0
    return out
