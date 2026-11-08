import ipaddress

from fabriclib.common.errors import ValidationError

LOOPBACK = ("127.0.0.0/8", "::1/128")


def own_clients(v):
    """Purpose: fabric's own clients of the resolver (manual 1.12.3.16, decision 2.1.12.12): the networks whose queries
             the query log hides by default and the statistics count apart.
    Inputs:  v — rendered vars: fabric_subnet (default 10.255.0.0/24: the containers, and the host's gateway address
             from which the DC, in the host's network, reaches the resolver), host_ip (may be missing).
    Returns: list of ip_network: fabric_subnet, host_ip as a single address when it is one, 127.0.0.0/8 and ::1.
             The SQL takes them as one inet[] literal ("{a,b,...}", from these checked values) bound as a psql
             variable, never pasted into the SQL.
    Fails:   ValidationError when fabric_subnet is not a network.
    Feeds:   dns_filter/read_query_log, dns_filter/dns_filter_stats, dns_filter/ingest_dns_log."""
    try:
        nets = [ipaddress.ip_network(str(v.get("fabric_subnet") or "10.255.0.0/24"), strict=False)]
    except ValueError:
        raise ValidationError(f"fabric_subnet is not a network (got {v.get('fabric_subnet')!r})") from None
    try:
        nets.append(ipaddress.ip_network(str(v.get("host_ip") or "").strip()))
    except ValueError:
        pass                                       # no host_ip (or not an address): nothing of the host's to add
    return nets + [ipaddress.ip_network(n) for n in LOOPBACK]

