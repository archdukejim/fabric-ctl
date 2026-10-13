CLASSES = {"IN", "CH", "HS"}


def zone_records(text, zone, types):
    """Purpose: the records of the given types in a zone file, owners made absolute.
    Inputs:  text — a zone file as fabric renders it or BIND writes it ($ORIGIN, relative owners, an owner left out
             to repeat the last, TTL and class optional, comments); zone — its name; types — set of upper-case
             record types to return (e.g. {"PTR", "DHCID"}).
    Returns: list of (owner FQDN with trailing dot, lower-case; type; rdata as written).
    Fails:   never: lines it cannot read are skipped.
    Feeds:   dns/merge_dynamic_records (Kea's PTR and DHCID in a reverse zone), dhcp/stale_dhcp_names (Kea's names
             in dhcp.<domain>)."""
    origin, owner, out, depth = zone.rstrip(".") + ".", None, [], 0
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        if not line.strip():
            continue
        if depth:                                    # inside ( ... ), e.g. the SOA
            depth += line.count("(") - line.count(")")
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
            out.append((owner.lower(), tokens[0].upper(), " ".join(tokens[1:])))
    return out
