import ipaddress
import json

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.rule_names import NAME_RE
from fabriclib.dns_filter.common.list_zone import list_zone
from fabriclib.dns_filter.common.own_clients import own_clients
from fabriclib.dns_filter.common.read_dnslog import read_dnslog

MAX_LIMIT = 500

SEARCH = """SELECT coalesce(json_agg(t), '[]') FROM (
  SELECT to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS at, host(client) AS client, view, name,
         qtype, action, zone, blocked
  FROM queries
  WHERE (:'client' = '' OR client <<= NULLIF(:'client', '')::inet)
    AND (:'name' = '' OR name = :'name' OR right(name, length(:'name') + 1) = '.' || :'name')
    AND (NOT :blocked OR blocked)
    AND (:own OR NOT (client <<= ANY (:'own_nets'::inet[])))
  ORDER BY at DESC LIMIT :limit) t;
"""


def read_query_log(v, client="", name="", blocked_only=False, limit=200, own=False):
    """Purpose: search the DNS query log, newest first (manual 1.12.2.13; admins only, 2.1.12.4) as the fabric-dns-log
             timer last read the resolver's log (one query, no ingest: 2.1.12.10), filtered by client, by name (the
             name and every name below it) and to blocked queries. fabric's own queries (own_clients: its containers,
             the host, loopback) are left out unless own is True or the client searched for lies within one of
             fabric's own networks (manual 1.12.3.16, decision 2.1.12.12).
    Inputs:  v — rendered vars (dns_filter_lists for list names, fabric_subnet and host_ip for fabric's own, and what
             read_dnslog reads); client — "" or an address or network (e.g. 192.168.1.20 or 192.168.1.0/24); name —
             "" or a DNS name; blocked_only — bool; limit — 1..500, default 200; own — bool (True or False only),
             fabric's own queries too.
    Returns: {"off": reason} when the query log is off or not made yet; else {"as_of": when the timer last read the
             log (epoch) or None, "entries": [{at (UTC, ISO), client, view, name, qtype, action, zone, list (the
             list's name when a list's zone matched), blocked}], "own": whether fabric's own queries are in it,
             "own_networks": [fabric's own networks, str]}.
    Fails:   ValidationError for a client that is not an address or network, a name that is not one, a limit out of
             range, own that is not True or False, a fabric_subnet that is not a network, or from Postgres.
    Feeds:   agent/post_route (POST /v1/dns-filter/querylog), dns_filter/run_dns_filter_command (`fabricctl
             dns-filter log`); tests/resolver/querylog.py."""
    if not isinstance(own, bool):
        raise ValidationError(f"own (fabric's own queries too) is true or false, not {own!r}")
    nets = own_clients(v)
    client, name = str(client or "").strip(), str(name or "").strip().rstrip(".").lower()
    if client:
        try:
            net = ipaddress.ip_network(client, strict=False)
        except ValueError:
            raise ValidationError(f"{client!r} is not an address or a network") from None
        client = str(net)
        # asking for one of fabric's own addresses is asking to see it (2.1.12.12); a wider search is not
        own = own or any(net.version == n.version and net.subnet_of(n) for n in nets)
    if name and not NAME_RE.match(name):
        raise ValidationError(f"{name!r} is not a DNS name")
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise ValidationError("limit must be a number") from None
    if not 1 <= limit <= MAX_LIMIT:
        raise ValidationError(f"limit must be 1 to {MAX_LIMIT}")
    r = read_dnslog(v, SEARCH, {"client": client, "name": name, "blocked": "true" if blocked_only else "false",
                                "own": "true" if own else "false",
                                "own_nets": "{" + ",".join(str(n) for n in nets) + "}", "limit": str(limit)})
    if "off" in r:
        return {"off": r["off"]}
    names = {list_zone(i["url"]): i.get("name") or i["url"] for i in v.get("dns_filter_lists") or []}
    entries = json.loads(r["out"].strip() or "[]")
    for e in entries:
        e["list"] = names.get(e.get("zone") or "")
    return {"as_of": r["as_of"], "entries": entries, "own": own, "own_networks": [str(n) for n in nets]}
