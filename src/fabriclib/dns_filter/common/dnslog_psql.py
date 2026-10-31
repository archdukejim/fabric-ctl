import subprocess

from fabriclib.common.errors import ValidationError

CONTAINER = "postgres"
ADMIN = "fabric_admin"           # Postgres's own admin (setup/ensure_db_rotation): creates the role and database
ROLE = "fabric_dnslog"           # owns the dnslog database; nothing else may connect to it
DB = "dnslog"


def dnslog_psql(sql, variables=None, as_admin=False, db=DB, timeout=300):
    """Purpose: run SQL for the DNS query log (manual 1.12.2.13) with psql in fabric's Postgres container, over its
             local socket, the SQL on stdin (COPY data may follow it there); tuples only, unaligned.
    Inputs:  sql — str; variables — {name: value} bound as psql variables (`:'name'` in the SQL quotes them as
             literals; values are checked by the callers and are never secrets); as_admin — True to connect as
             fabric_admin (creating the role and database), else as fabric_dnslog; db — the database, default
             dnslog; timeout — seconds.
    Returns: psql's output (str).
    Fails:   ValidationError when psql fails (the last line of its error) or Postgres is not running; OSError without
             docker; subprocess.TimeoutExpired.
    Feeds:   dns_filter/ensure_dnslog_db, dns_filter/ingest_dns_log, dns_filter/common/read_dnslog (the reads of
             dns_filter/read_query_log and dns_filter/dns_filter_stats)."""
    args = ["docker", "exec", "-i", CONTAINER, "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
            "-U", ADMIN if as_admin else ROLE, "-d", db]
    for name, value in (variables or {}).items():
        args += ["-v", f"{name}={value}"]
    r = subprocess.run(args, input=sql, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        lines = (r.stderr or r.stdout).strip().splitlines()
        detail = next((ln for ln in lines if "ERROR" in ln or "FATAL" in ln or "Error" in ln),
                      lines[-1] if lines else "psql failed")
        raise ValidationError(f"the DNS query log (Postgres): {detail.strip()}")
    return r.stdout
