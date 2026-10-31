import datetime
import fcntl
import json
import os
import re
import urllib.parse

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns_filter.common.adguard_api import adguard_api
from fabriclib.dns_filter.common.adguard_password import adguard_password
from fabriclib.dns_filter.common.dnslog_psql import dnslog_psql
from fabriclib.dns_filter.common.query_log_off import query_log_off
from fabriclib.dns_filter.common.resolver_paths import resolver_paths
from fabriclib.dns_filter.ensure_dnslog_db import ensure_dnslog_db

CLIENT = r"client @\S+ ([0-9a-fA-F:.]+)#(\d+) \((\S+)\): view (\S+):"
QUERY = re.compile(r"^(\S+ \S+) " + CLIENT + r" query: (\S+) IN (\S+) ")
RESPONSE = re.compile(r"^(\S+ \S+) " + CLIENT + r" response: (\S+) IN (\S+) (\S+) ")
RPZ = re.compile(r"^(\S+ \S+) " + CLIENT + r" rpz \S+ (\S+) rewrite (\S+)/(\S+)/IN via (\S+)")
ZONE = re.compile(r"((?:[0-9a-f]{12}\.list|[a-z0-9-]+)\.rpz)$")
MAX_BATCH = 64 * 1024 * 1024           # read at most this much per file and run (the rest the next run)
MAX_ASK = 5000                         # names asked of AdGuard per run at most (the rest stay unmarked)

PURGE = """
DELETE FROM queries WHERE at < now() - interval '7 days';
DELETE FROM stats_hourly WHERE hour < now() - interval '90 days';
DELETE FROM stats_blocked WHERE day < (now() AT TIME ZONE 'UTC')::date - 90;
"""


def _new_lines(folder, name, seen):
    """Purpose: the complete lines added to a resolver log since the last run, a rotated file finished first.
    Inputs:  folder — the log folder; name — "query.log" or "rpz.log"; seen — {"inode", "offset"} from the last run,
             or None.
    Returns: (lines: list of str, place: {"inode", "offset"} after them, or None when the file is not there).
    Fails:   OSError reading the files.
    Feeds:   ingest_dns_log.
    Notes:   BIND renames a full log to <name>.0 (versions 2): a file with the last run's inode there is read on from
             the last offset first. A file shorter than the offset was truncated: read from its start."""
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        return [], None
    cur = os.stat(path)
    data = b""
    offset = 0
    if seen:
        rotated = path + ".0"
        if seen["inode"] == cur.st_ino:
            offset = seen["offset"] if seen["offset"] <= cur.st_size else 0
        elif os.path.exists(rotated) and os.stat(rotated).st_ino == seen["inode"]:
            with open(rotated, "rb") as f:
                f.seek(seen["offset"])
                data += f.read(MAX_BATCH)
    with open(path, "rb") as f:
        f.seek(offset)
        chunk = f.read(MAX_BATCH)
    end = chunk.rfind(b"\n") + 1                 # a line still being written waits for the next run
    data += chunk[:end]
    return data.decode("utf-8", errors="replace").splitlines(), {"inode": cur.st_ino, "offset": offset + end}


def _time(text):
    """Purpose: a BIND log time (the container's clock, UTC) as ISO 8601.
    Inputs:  text — e.g. "09-Oct-2026 11:49:42.575".
    Returns: str "2026-10-09T11:49:42.575+00:00", or None when it does not parse.
    Fails:   never.
    Feeds:   _rows."""
    try:
        return datetime.datetime.strptime(text, "%d-%b-%Y %H:%M:%S.%f").replace(
            tzinfo=datetime.timezone.utc).isoformat(timespec="milliseconds")
    except ValueError:
        return None


def _field(value):
    """Purpose: a value as a COPY text field (backslash, tab and newline escaped).
    Inputs:  value — str.
    Returns: str.
    Fails:   never.
    Feeds:   _rows."""
    return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def _adguard_blocks(v, responses, rewritten):
    """Purpose: which NXDOMAIN answers AdGuard Home gave for a list (manual 1.12.3.7): an NXDOMAIN with no rewrite of
             the resolver's own came from AdGuard or from the internet; AdGuard is asked (check_host) once per name
             and group, and a name it filters is marked blocked by its list. A genuine NXDOMAIN stays unblocked.
    Inputs:  v — rendered vars (ip_adguard, deploy_base_dir); responses — _responses' tuples; rewritten — set of
             (client, port, name) the RPZ log names.
    Returns: (rows: COPY rows (at, client, port, name, zone) of the queries to mark, error: why AdGuard could not be
             asked, or None).
    Fails:   never (AdGuard not answering is the error returned).
    Feeds:   ingest_dns_log."""
    pending = {}
    for at, client, port, view, name, _, rcode in responses:
        if rcode == "NXDOMAIN" and (client, port, name) not in rewritten:
            pending.setdefault((name, view), []).append((at, client, port))
    if not pending:
        return [], None
    try:
        password = adguard_password(v)
        status = adguard_api(v, password, "GET", "/control/filtering/status") or {}
        ids = {f.get("id"): f.get("url") or "" for f in status.get("filters") or []}
        rows = []
        for (name, view), hits in list(pending.items())[:MAX_ASK]:
            query = {"name": name} if view == "everyone" else {"name": name, "client": view}
            r = adguard_api(v, password, "GET", "/control/filtering/check_host?" + urllib.parse.urlencode(query)) or {}
            if not str(r.get("reason") or "").startswith("FilteredBlack"):
                continue
            url = next((ids.get(x.get("filter_list_id")) for x in r.get("rules") or [] if x.get("filter_list_id")),
                       "") or ""
            zone = os.path.basename(url)[:-4] + ".list.rpz" if url.startswith("/lists/") else "adguard"
            rows += ["\t".join(_field(x) for x in (at, client, port, name, zone)) for at, client, port in hits]
        return rows, None
    except (ValidationError, KeyError) as e:
        return [], str(e)


def _responses(lines):
    """Purpose: the resolver's answers in its query log (`responselog`, manual 1.12.3.7).
    Inputs:  lines — query.log's lines.
    Returns: list of (at, client, port, view, name, qtype, rcode).
    Fails:   never.
    Feeds:   ingest_dns_log."""
    out = []
    for line in lines:
        m = RESPONSE.match(line)
        at = _time(m.group(1)) if m else None
        if at:
            client, port, _, view, name, qtype, rcode = m.group(2, 3, 4, 5, 6, 7, 8)
            out.append((at, client, port, view, name.rstrip(".").lower(), qtype, rcode))
    return out


def _rows(lines, pattern, rpz):
    """Purpose: the lines of one log as COPY rows: queries (time, client, port, view, name, type) or rewrites (the
             same and the action and the zone).
    Inputs:  lines — list of str; pattern — QUERY or RPZ; rpz — True for rpz.log's lines.
    Returns: (rows: list of str, skipped: int — lines that are not a query, a response or a rewrite).
    Fails:   never.
    Feeds:   ingest_dns_log."""
    rows, skipped = [], 0
    for line in lines:
        m = pattern.match(line)
        at = _time(m.group(1)) if m else None
        if not at:
            skipped += 0 if RESPONSE.match(line) else 1
            continue
        if rpz:
            client, port, _, view, action, name, qtype, via = m.group(2, 3, 4, 5, 6, 7, 8, 9)
            z = ZONE.search(via.rstrip("."))
            row = [at, client, port, view, name.rstrip(".").lower(), qtype, action, z.group(1) if z else via]
        else:
            client, port, _, view, name, qtype = m.group(2, 3, 4, 5, 6, 7)
            row = [at, client, port, view, name.rstrip(".").lower(), qtype]
        rows.append("\t".join(_field(x) for x in row))
    return rows, skipped


def ingest_dns_log(v):
    """Purpose: read the resolver's new query and RPZ log lines into the query log (manual 1.12.2.13, 1.12.3.7,
             decision 2.1.12.5): queries in, each rewrite of the resolver's marked on its query, each NXDOMAIN that
             AdGuard Home gave for a list marked blocked by that list, the touched hours' and days' statistics
             recomputed, then rows past their time purged (2.1.12.4: 7 days; statistics 90 days). One run at a time;
             the timer's alone since 2.1.12.10 (the console's reads never ingest): ingest.json's time is when it last
             ran, which the tab shows.
    Inputs:  v — rendered vars (install_resolver, install_keycloak, deploy_base_dir, ip_adguard).
    Returns: {"off": reason} when the resolver or Postgres is not on; else {"queries": rows added, "rewrites": rewrite
             lines read, "adguard": answers marked blocked by a list, "adguard_error": why AdGuard could not be asked
             (those answers stay unmarked) or None, "skipped": lines that were none of these, "created": True when
             the database was made now}.
    Fails:   ValidationError from dnslog_psql (Postgres not running or refusing; the place in the files is kept, so
             the next run reads the same lines again, and its time); OSError reading the logs or writing the place.
    Feeds:   dns_filter/run_dns_filter_command (`fabricctl dns-filter ingest`, the fabric-dns-log timer),
             tests/resolver/querylog.py."""
    off = query_log_off(v)
    if off:
        return {"off": off}
    paths = resolver_paths(v)
    place_file = os.path.join(paths["root"], "ingest.json")
    with open(os.path.join(paths["root"], "ingest.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(place_file) as f:
                place = json.load(f)
        except (OSError, ValueError):
            place = {}
        created = ensure_dnslog_db()
        q_lines, q_place = _new_lines(paths["log"], "query.log", place.get("query.log"))
        r_lines, r_place = _new_lines(paths["log"], "rpz.log", place.get("rpz.log"))
        queries, q_skip = _rows(q_lines, QUERY, False)
        rewrites, r_skip = _rows(r_lines, RPZ, True)
        rewritten = set()
        for line in r_lines:
            m = RPZ.match(line)
            if m:
                rewritten.add((m.group(2), m.group(3), m.group(7).rstrip(".").lower()))
        blocks, ag_error = _adguard_blocks(v, _responses(q_lines), rewritten)
        sql = ["BEGIN;"]
        if queries or rewrites or blocks:
            sql += ["CREATE TEMP TABLE q_in (at timestamptz, client inet, port int, view text, name text, qtype text)"
                    " ON COMMIT DROP;",
                    "COPY q_in FROM STDIN;", *queries, "\\.",
                    "INSERT INTO queries (at, client, port, view, name, qtype) SELECT * FROM q_in;",
                    "CREATE TEMP TABLE r_in (at timestamptz, client inet, port int, view text, name text, qtype text,"
                    " action text, zone text) ON COMMIT DROP;",
                    "COPY r_in FROM STDIN;", *rewrites, "\\.",
                    """UPDATE queries q SET action = r.action, zone = r.zone, blocked = (r.action = 'NXDOMAIN')
                       FROM r_in r WHERE q.client = r.client AND q.port = r.port AND q.name = r.name
                       AND q.at BETWEEN r.at - interval '2 seconds' AND r.at + interval '2 seconds';""",
                    # AdGuard's blocks, each with the list that blocked it (1.12.3.7)
                    "CREATE TEMP TABLE a_in (at timestamptz, client inet, port int, name text, zone text)"
                    " ON COMMIT DROP;",
                    "COPY a_in FROM STDIN;", *blocks, "\\.",
                    """UPDATE queries q SET action = 'NXDOMAIN', zone = a.zone, blocked = true
                       FROM a_in a WHERE q.client = a.client AND q.port = a.port AND q.name = a.name
                       AND q.zone IS NULL
                       AND q.at BETWEEN a.at - interval '5 seconds' AND a.at + interval '1 second';""",
                    """CREATE TEMP TABLE touched ON COMMIT DROP AS SELECT DISTINCT date_trunc('hour', at) AS hour
                       FROM (SELECT at FROM q_in UNION ALL SELECT at FROM r_in UNION ALL SELECT at FROM a_in) t;""",
                    "DELETE FROM stats_hourly WHERE hour IN (SELECT hour FROM touched);",
                    """INSERT INTO stats_hourly SELECT date_trunc('hour', at), '', count(*),
                       count(*) FILTER (WHERE blocked) FROM queries WHERE at >= (SELECT min(hour) FROM touched)
                       AND date_trunc('hour', at) IN (SELECT hour FROM touched) GROUP BY 1;""",
                    """INSERT INTO stats_hourly SELECT date_trunc('hour', at), zone, count(*),
                       count(*) FILTER (WHERE blocked) FROM queries WHERE zone IS NOT NULL
                       AND at >= (SELECT min(hour) FROM touched)
                       AND date_trunc('hour', at) IN (SELECT hour FROM touched) GROUP BY 1, 2;""",
                    """DELETE FROM stats_blocked WHERE day IN
                       (SELECT DISTINCT (hour AT TIME ZONE 'UTC')::date FROM touched);""",
                    """INSERT INTO stats_blocked SELECT (at AT TIME ZONE 'UTC')::date, name, zone, count(*) FROM queries
                       WHERE blocked AND (at AT TIME ZONE 'UTC')::date IN
                       (SELECT DISTINCT (hour AT TIME ZONE 'UTC')::date FROM touched) GROUP BY 1, 2, 3;"""]
        sql += [PURGE, "COMMIT;"]
        dnslog_psql("\n".join(sql) + "\n")
        new = {k: p for k, p in (("query.log", q_place), ("rpz.log", r_place)) if p}
        if new != place or not os.path.exists(place_file):
            write_file_if_changed(place_file, json.dumps(new) + "\n", 0o600)
        else:
            os.utime(place_file)             # read up to now, nothing new: its time is the tab's "as of"
    return {"queries": len(queries), "rewrites": len(rewrites), "adguard": len(blocks), "adguard_error": ag_error,
            "skipped": q_skip + r_skip, "created": created}
