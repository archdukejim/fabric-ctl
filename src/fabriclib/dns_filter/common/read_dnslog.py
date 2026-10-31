import os

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.dnslog_psql import dnslog_psql
from fabriclib.dns_filter.common.query_log_off import query_log_off
from fabriclib.dns_filter.common.resolver_paths import resolver_paths

NOT_YET = "not read yet: fabric-dns-log reads the resolver's log every 5 minutes"


def read_dnslog(v, sql, variables=None):
    """Purpose: one read of the DNS query log as the fabric-dns-log timer last left it (manual 1.12.2.13, 2.1.12.10):
             one psql, never an ingest, so a view of the console's tab waits for nothing but this query.
    Inputs:  v — rendered vars (install_resolver, install_keycloak, deploy_base_dir); sql — a read (str); variables —
             psql variables for it, as dnslog_psql takes them.
    Returns: {"off": reason} when the query log is off, or not made yet (before the timer's first run); else {"out":
             psql's output, "as_of": when the timer last read the resolver's log (epoch seconds; ingest.json's time),
             or None}.
    Fails:   ValidationError from dnslog_psql (Postgres not running or refusing).
    Feeds:   dns_filter/dns_filter_stats, dns_filter/read_query_log."""
    off = query_log_off(v)
    if off:
        return {"off": off}
    try:
        out = dnslog_psql(sql, variables)
    except ValidationError as e:
        if "does not exist" in str(e):        # the role or the database: the timer's first run makes them
            return {"off": NOT_YET}
        raise
    try:
        as_of = os.path.getmtime(os.path.join(resolver_paths(v)["root"], "ingest.json"))
    except OSError:
        as_of = None
    return {"out": out, "as_of": as_of}
