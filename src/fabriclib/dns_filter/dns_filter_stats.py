import json

from fabriclib.dns_filter.common.list_zone import list_zone
from fabriclib.dns_filter.common.read_dnslog import read_dnslog

STATS = """SELECT json_build_object(
  'hours', (SELECT coalesce(json_agg(json_build_object(
              'hour', to_char(hour AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24":00Z"'), 'queries', queries,
              'blocked', blocked) ORDER BY hour), '[]')
            FROM stats_hourly WHERE zone = '' AND hour >= date_trunc('hour', now()) - interval '23 hours'),
  'week', (SELECT json_build_object('queries', coalesce(sum(queries), 0), 'blocked', coalesce(sum(blocked), 0))
           FROM stats_hourly WHERE zone = '' AND hour >= now() - interval '7 days'),
  'zones', (SELECT coalesce(json_agg(json_build_object('zone', zone, 'queries', q, 'blocked', b) ORDER BY b DESC),
                            '[]')
            FROM (SELECT zone, sum(queries) AS q, sum(blocked) AS b FROM stats_hourly
                  WHERE zone <> '' AND hour >= now() - interval '7 days' GROUP BY zone) z),
  'top_blocked', (SELECT coalesce(json_agg(json_build_object('name', name, 'zone', zone, 'count', c)), '[]')
                  FROM (SELECT name, zone, sum(count) AS c FROM stats_blocked
                        WHERE day >= (now() AT TIME ZONE 'UTC')::date - 7 GROUP BY name, zone
                        ORDER BY c DESC LIMIT 20) t));
"""


def dns_filter_stats(v):
    """Purpose: the DNS filter's statistics (manual 1.12.2.13; no client addresses, 2.1.12.4) as the fabric-dns-log
             timer last read the resolver's log (one query, no ingest: 2.1.12.10): the last 24 hours by hour, the
             last 7 days' totals, queries and blocks per zone (each list, the owner's rules, fabric's own names), and
             the 20 most blocked names of the last 7 days.
    Inputs:  v — rendered vars (dns_filter_lists for list names, and what read_dnslog reads).
    Returns: {"off": reason} when the query log is off or not made yet; else {"as_of": when the timer last read
             the log (epoch) or None, "hours": [{hour, queries, blocked}], "week": {queries, blocked}, "zones":
             [{zone, list (its name, or None), queries, blocked}], "top_blocked": [{name, zone, list, count}]}.
    Fails:   ValidationError from Postgres.
    Feeds:   agent/get_route (GET /v1/dns-filter), dns_filter/run_dns_filter_command (`fabricctl dns-filter stats`);
             tests/resolver/querylog.py."""
    r = read_dnslog(v, STATS)
    if "off" in r:
        return {"off": r["off"]}
    stats = {**json.loads(r["out"].strip()), "as_of": r["as_of"]}
    names = {list_zone(i["url"]): i.get("name") or i["url"] for i in v.get("dns_filter_lists") or []}
    for row in stats["zones"] + stats["top_blocked"]:
        row["list"] = names.get(row["zone"])
    return stats
