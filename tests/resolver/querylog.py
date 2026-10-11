#!/usr/bin/env python3
"""The DNS filter's query log and statistics (manual 1.12.2.13) with a real Postgres (the pinned image, named as
fabric runs it): ingesting the resolver's log files, rewrites marking their queries, reading on from where it stopped
(a rotated file too), purging at 7 days while statistics stay, searches and statistics, and what must be refused.

    sudo python3 tests/resolver/querylog.py      (needs Docker)
"""
import datetime
import io
import os
import shutil
import subprocess
import sys
import time
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/querylog"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns_filter.common.list_zone import list_zone  # noqa: E402
from fabriclib.dns_filter.dns_filter_stats import dns_filter_stats  # noqa: E402
from fabriclib.dns_filter.ingest_dns_log import ingest_dns_log  # noqa: E402
from fabriclib.dns_filter.read_query_log import read_query_log  # noqa: E402
from fabriclib.dns_filter.run_dns_filter_command import run_dns_filter_command  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

URL = "https://lists.example/test.txt"
ZONE = list_zone(URL)
LOG = f"{W}/resolver/log"
V = {"deploy_base_dir": W, "install_resolver": True, "install_keycloak": True,
     "dns_filter_lists": [{"name": "Test list", "url": URL}]}


def stamp(ago=0):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=ago)
    return t.strftime("%d-%b-%Y %H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def query(client, port, name, ago=0, view="everyone"):
    return (f"{stamp(ago)} client @0x7f00 {client}#{port} ({name}): view {view}: query: {name} IN A +E(0)K "
            f"(10.255.0.33)\n")


def rewrite(client, port, name, action, via, ago=0, view="everyone"):
    return (f"{stamp(ago)} client @0x7f00 {client}#{port} ({name}): view {view}: rpz QNAME {action} rewrite "
            f"{name}/A/IN via {via}\n")


def append(name, text):
    with open(f"{LOG}/{name}", "a") as f:
        f.write(text)


def dnsf(v, *argv):
    """fabricctl dns-filter …, as the CLI routes it (fabriclib/cli.py): its exit status and output (stdout and
    stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_dns_filter_command(v, list(argv))
    return code, out.getvalue() + err.getvalue()


def psql(sql, user="fabric_dnslog", db="dnslog"):
    return subprocess.run(["docker", "exec", "-i", "postgres", "psql", "-X", "-At", "-U", user, "-d", db],
                          input=sql, capture_output=True, text=True)


# ---- the permission: admins only (2.1.12.4); the statistics for the DNS filter's managers
check("POST /v1/dns-filter/querylog needs dns:querylog; GET /v1/dns-filter needs dns:filter",
      required_permission("POST", ["dns-filter", "querylog"]) == "dns:querylog"
      and required_permission("GET", ["dns-filter"]) == "dns:filter")
check("dns:querylog is in the admin bundle only (not network operators, not auditors)",
      "dns:querylog" in BUNDLES["admin"] and not [b for b, p in BUNDLES.items() if b != "admin" and "dns:querylog" in p])
check("off: without Postgres (install_keycloak false) the query log says so",
      "Postgres" in ingest_dns_log({**V, "install_keycloak": False}).get("off", ""))
NOPG = {**V, "install_keycloak": False}
OFF = "the query log is off: Postgres is not installed (install_keycloak: false)"
outs = {cmd: dnsf(NOPG, cmd) for cmd in ("ingest", "log", "stats")}
# covers: cli:dns-filter.ingest cli:dns-filter.log cli:dns-filter.stats -
check("fabricctl dns-filter ingest, log and stats refused without Postgres: exit 2, saying the query log is off",
      all(code == 2 and OFF in out for code, out in outs.values()), outs)

pg = sh([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "postgres"]).stdout.strip()
try:
    sh("docker rm -f postgres", ok=False)
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(LOG)
    sh(["docker", "run", "-d", "--name", "postgres", "-e", "POSTGRES_USER=fabric_admin", "-e", "POSTGRES_DB=keycloak",
        "-e", "POSTGRES_PASSWORD=test-only-password", pg])
    for _ in range(60):
        if sh("docker exec postgres pg_isready -U fabric_admin -d keycloak", ok=False).returncode == 0:
            break
        time.sleep(1)
    time.sleep(2)

    append("query.log", query("192.168.1.20", 4001, "ads.example", 30) + query("192.168.1.20", 4002, "www.example.org", 29)
           + query("192.168.1.21", 4003, "deep.sub.ads.example", 28) + query("192.168.1.21", 4004, "ok.example", 27)
           + query("192.168.1.22", 4005, "old.example", 8 * 86400) + "a line that is not a query\n")
    append("rpz.log", rewrite("192.168.1.20", 4001, "ads.example", "NXDOMAIN", f"ads.example.{ZONE}", 30)
           + rewrite("192.168.1.21", 4003, "deep.sub.ads.example", "NXDOMAIN", f"*.ads.example.{ZONE}", 28)
           + rewrite("192.168.1.21", 4004, "ok.example", "PASSTHRU", "ok.example.owner.rpz", 27)
           + rewrite("192.168.1.22", 4005, "old.example", "NXDOMAIN", f"old.example.{ZONE}", 8 * 86400))
    r = ingest_dns_log(V)
    check("ingest: the database made, the queries and rewrites read, a stray line counted",
          r.get("created") and r["queries"] == 5 and r["rewrites"] == 4 and r["skipped"] == 1, r)
    other = psql("CREATE ROLE other_role LOGIN;", user="fabric_admin", db="keycloak")
    refused = psql("SELECT 1;", user="other_role")
    check("isolation: another role cannot connect to dnslog (CONNECT revoked from PUBLIC)",
          other.returncode == 0 and refused.returncode != 0 and "permission denied" in refused.stderr, refused.stderr)
    log = read_query_log(V)["entries"]
    check("the log: newest first, 8-day-old rows purged (7 days)",
          [e["name"] for e in log] == ["ok.example", "deep.sub.ads.example", "www.example.org", "ads.example"], log)
    blocked = read_query_log(V, blocked_only=True)["entries"]
    check("a rewrite marks its query: blocked, with the action, the list's zone and its name",
          [(e["name"], e["action"], e["zone"], e["list"], e["blocked"]) for e in blocked]
          == [("deep.sub.ads.example", "NXDOMAIN", ZONE, "Test list", True),
              ("ads.example", "NXDOMAIN", ZONE, "Test list", True)], blocked)
    passed = [e for e in log if e["name"] == "ok.example"][0]
    check("an owner's allow is recorded as PASSTHRU via owner.rpz, not blocked",
          (passed["action"], passed["zone"], passed["blocked"]) == ("PASSTHRU", "owner.rpz", False), passed)
    check("search by client (an address or a network) and by name (it and every name below it)",
          [e["name"] for e in read_query_log(V, client="192.168.1.21")["entries"]] == ["ok.example",
                                                                                       "deep.sub.ads.example"]
          and len(read_query_log(V, client="192.168.1.0/24")["entries"]) == 4
          and [e["name"] for e in read_query_log(V, name="ads.example")["entries"]] == ["deep.sub.ads.example",
                                                                                         "ads.example"]
          and read_query_log(V, name="s.example")["entries"] == [])
    s = dns_filter_stats(V)
    check("statistics: the 7 days' totals and the 24 hours by hour, no client addresses",
          s["week"] == {"queries": 4, "blocked": 2} and sum(h["queries"] for h in s["hours"]) == 4
          and "192.168" not in str(s), s)
    check("statistics: per list (its name) and per rules zone; the most blocked names",
          {(z["list"] or z["zone"], z["blocked"]) for z in s["zones"]} == {("Test list", 2), ("owner.rpz", 0)}
          and {(t["name"], t["count"]) for t in s["top_blocked"]} == {("ads.example", 1), ("deep.sub.ads.example", 1)},
          s)
    kept = psql("SELECT count(*) FROM stats_hourly WHERE zone = '' AND hour < now() - interval '7 days';").stdout.strip()
    check("statistics stay past 7 days (90): the old hour's count kept though its query is gone", kept == "1", kept)

    # fabricctl dns-filter stats | log | ingest, as the CLI routes them (manual 1.12.2.13)
    code, out = dnsf(V, "stats")
    # covers: cli:dns-filter.stats +
    check("fabricctl dns-filter stats: the 7 days' totals and share, per list, the most blocked names, exit 0",
          code == 0 and "last 7 days: 4 queries, 2 blocked (50.0%)" in out and "Test list: 2 blocked" in out
          and "ads.example  (Test list)" in out and "192.168" not in out, out)
    code, out = dnsf(V, "log", "--client", "192.168.1.21")
    code2, out2 = dnsf(V, "log", "--blocked", "--limit", "1")
    rows = out.splitlines()
    # covers: cli:dns-filter.log +
    check("fabricctl dns-filter log: newest first, by client; a block names its action and list; --blocked --limit",
          code == 0 and len(rows) == 2 and "ok.example" in rows[0] and "PASSTHRU via owner.rpz" in rows[0]
          and "deep.sub.ads.example" in rows[1] and "NXDOMAIN via Test list" in rows[1]
          and code2 == 0 and len(out2.splitlines()) == 1 and "deep.sub.ads.example" in out2, (out, out2))
    refusals = {why: dnsf(V, "log", *args) for why, args in (
        ("a limit of 0", ["--limit", "0"]), ("an option without its value", ["--client"]),
        ("an unknown option", ["--since", "1h"]), ("a name that is not one", ["--name", "bad name!"]))}
    # covers: cli:dns-filter.log -
    check("fabricctl dns-filter log refuses a limit of 0, an option without its value, an unknown option and a bad "
          "name: exit 1, saying why", all(code == 1 and out.startswith("refused: ") for code, out in refusals.values())
          and "limit must be 1 to 500" in refusals["a limit of 0"][1]
          and "missing value: --client" in refusals["an option without its value"][1]
          and "unknown option or missing value: --since" in refusals["an unknown option"][1]
          and "is not a DNS name" in refusals["a name that is not one"][1], refusals)
    append("query.log", query("192.168.1.50", 4101, "cli-ingest.example"))
    code, out = dnsf(V, "ingest", "--scheduled")
    # covers: cli:dns-filter.ingest +
    check("fabricctl dns-filter ingest (as its timer runs it): the new line read, exit 0; the log shows it",
          code == 0 and out.strip() == "query log: 1 queries and 0 rewrites read"
          and [e["name"] for e in read_query_log(V, client="192.168.1.50")["entries"]] == ["cli-ingest.example"],
          out)
    code, out = dnsf(V, "stats", "--week")
    check("fabricctl dns-filter stats with an unknown word: refused with the usage", code == 2 and "usage:" in out,
          out)

    # a client group (1.12.2.15): its view's query, the main view's copy from 127.0.0.1 and the main view's rewrite;
    # a rewrite of the group's own rules on its query
    append("query.log", query("192.168.1.40", 7001, "tracker.example", 5, view="kids")
           + query("127.0.0.1", 7101, "tracker.example", 5)
           + query("192.168.1.40", 7002, "kids-only.example", 4, view="kids"))
    append("rpz.log", rewrite("127.0.0.1", 7101, "tracker.example", "NXDOMAIN", f"tracker.example.{ZONE}", 5)
           + rewrite("192.168.1.40", 7002, "kids-only.example", "NXDOMAIN", "kids-only.example.group-kids.rpz", 4,
                     view="kids"))
    ingest_dns_log(V)
    kid = {e["name"]: e for e in read_query_log(V, client="192.168.1.40")["entries"]}
    check("groups: the main view's rewrite is put on the group's query (the real client, its view, the list)",
          set(kid) == {"tracker.example", "kids-only.example"}
          and (kid["tracker.example"]["view"], kid["tracker.example"]["zone"], kid["tracker.example"]["blocked"])
          == ("kids", ZONE, True), kid)
    check("groups: the group's own rule is on its query (group-kids.rpz)",
          (kid["kids-only.example"]["zone"], kid["kids-only.example"]["blocked"]) == ("group-kids.rpz", True), kid)
    check("groups: the chain's own hop (127.0.0.1) is not a client's query",
          read_query_log(V, client="127.0.0.1")["entries"] == [])

    # reading on: only new lines; a rotated file finished first; Postgres down keeps the lines for the next run
    r = ingest_dns_log(V)
    check("ingest again with nothing new: nothing added", r["queries"] == 0 and r["rewrites"] == 0, r)
    append("query.log", query("192.168.1.30", 5001, "before-rotation.example"))
    os.rename(f"{LOG}/query.log", f"{LOG}/query.log.0")
    append("query.log", query("192.168.1.30", 5002, "after-rotation.example"))
    r = ingest_dns_log(V)
    names = [e["name"] for e in read_query_log(V, client="192.168.1.30")["entries"]]
    check("a rotated log is finished from where it stopped, then the new one read from its start",
          r["queries"] == 2 and sorted(names) == ["after-rotation.example", "before-rotation.example"], (r, names))
    sh("docker stop postgres")
    append("query.log", query("192.168.1.31", 6001, "while-down.example"))
    try:
        ingest_dns_log(V)
        check("Postgres down: refused", False, "accepted")
    except ValidationError as e:
        check("Postgres down: refused, saying why", "query log" in str(e), e)
    place = open(f"{W}/resolver/ingest.json").read()
    code, out = dnsf(V, "ingest")
    # covers: cli:dns-filter.ingest -
    check("fabricctl dns-filter ingest with Postgres down: refused (exit 1) saying why; its place in the log kept",
          code == 1 and out.startswith("refused: the DNS query log (Postgres)")
          and open(f"{W}/resolver/ingest.json").read() == place, out)
    sh("docker start postgres")
    for _ in range(60):
        if sh("docker exec postgres pg_isready -U fabric_admin -d keycloak", ok=False).returncode == 0:
            break
        time.sleep(1)
    time.sleep(2)
    check("…and the lines refused then are read by the next run (the place moved only after Postgres took them)",
          ingest_dns_log(V)["queries"] == 1
          and [e["name"] for e in read_query_log(V, client="192.168.1.31")["entries"]] == ["while-down.example"])
    for args, why in ((dict(client="not-an-address"), "a client that is not an address"),
                      (dict(name="bad name!"), "a name that is not one"),
                      (dict(limit=0), "a limit of 0"), (dict(limit=501), "a limit over 500"),
                      (dict(client="1.2.3.4'; DROP TABLE queries; --"), "SQL in a client")):
        try:
            read_query_log(V, **args)
            check(f"refused: {why}", False, "accepted")
        except ValidationError as e:
            check(f"refused: {why}, saying why", bool(str(e)), e)
    check("the queries table is still there after the refusals",
          psql("SELECT count(*) > 0 FROM queries;").stdout.strip() == "t")
finally:
    sh("docker rm -f postgres", ok=False)

print("\nall passed (0 failures)" if not FAILED else f"\n{FAILED} failed")
sys.exit(1 if FAILED else 0)
