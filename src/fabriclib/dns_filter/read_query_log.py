import ipaddress
import json

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.rule_names import NAME_RE
from fabriclib.dns_filter.common.list_zone import list_zone
from fabriclib.dns_filter.common.read_dnslog import read_dnslog

MAX_LIMIT = 500

SEARCH = """SELECT coalesce(json_agg(t), '[]') FROM (
  SELECT to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS at, host(client) AS client, view, name,
         qtype, action, zone, blocked
  FROM queries
  WHERE (:'client' = '' OR client <<= NULLIF(:'client', '')::inet)
    AND (:'name' = '' OR name = :'name' OR right(name, length(:'name') + 1) = '.' || :'name')
    AND (NOT :blocked OR blocked)
  ORDER BY at DESC LIMIT :limit) t;
"""


def read_query_log(v, client="", name="", blocked_only=False, limit=200):
    """Purpose: search the DNS query log, newest first (manual 1.12.2.13; admins only, 2.1.12.4) as the fabric-dns-log
             timer last read the resolver's log (one query, no ingest: 2.1.12.10), filtered by client, by name (the
             name and every name below it) and to blocked queries.
    Inputs:  v — rendered vars (dns_filter_lists for list names, and what read_dnslog reads); client — "" or an
             address or network (e.g. 192.168.1.20 or 192.168.1.0/24); name — "" or a DNS name; blocked_only — bool;
             limit — 1..500, default 200.
    Returns: {"off": reason} when the query log is off or not made yet; else {"as_of": when the timer last read the
             log (epoch) or None, "entries": [{at (UTC, ISO), client, view, name, qtype, action, zone, list (the
             list's name when a list's zone matched), blocked}]}.
    Fails:   ValidationError for a client that is not an address or network, a name that is not one, a limit out of
             range, or from Postgres.
    Feeds:   agent/post_route (POST /v1/dns-filter/querylog), dns_filter/run_dns_filter_command (`fabricctl
             dns-filter log`); tests/resolver/querylog.py."""
    client, name = str(client or "").strip(), str(name or "").strip().rstrip(".").lower()
    if client:
        try:
            client = str(ipaddress.ip_network(client, strict=False))
        except ValueError:
            raise ValidationError(f"{client!r} is not an address or a network") from None
    if name and not NAME_RE.match(name):
        raise ValidationError(f"{name!r} is not a DNS name")
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise ValidationError("limit must be a number") from None
    if not 1 <= limit <= MAX_LIMIT:
        raise ValidationError(f"limit must be 1 to {MAX_LIMIT}")
    r = read_dnslog(v, SEARCH, {"client": client, "name": name, "blocked": "true" if blocked_only else "false",
                                "limit": str(limit)})
    if "off" in r:
        return {"off": r["off"]}
    names = {list_zone(i["url"]): i.get("name") or i["url"] for i in v.get("dns_filter_lists") or []}
    entries = json.loads(r["out"].strip() or "[]")
    for e in entries:
        e["list"] = names.get(e.get("zone") or "")
    return {"as_of": r["as_of"], "entries": entries}
