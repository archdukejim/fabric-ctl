from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.apply_dns_filter import apply_dns_filter
from fabriclib.dns_filter.common.adguard_password import adguard_password
from fabriclib.dns_filter.dns_filter_stats import dns_filter_stats
from fabriclib.dns_filter.ingest_dns_log import ingest_dns_log
from fabriclib.dns_filter.read_query_log import read_query_log
from fabriclib.dns_filter.refresh_lists import refresh_lists
from fabriclib.dns_filter.show_filter_status import show_filter_status

USAGE = """usage: fabricctl dns-filter lists [--scheduled]  fetch AdGuard's catalogue and a copy of every list now;
                                                AdGuard Home rereads the copies that changed
       fabricctl dns-filter apply               make the DNS filter's settings in vars.yaml where they live
                                                (the resolver reloaded, AdGuard Home through its API)
       fabricctl dns-filter status              the resolver, AdGuard Home, and each list's state
       fabricctl dns-filter log [--client ADDRESS] [--name NAME] [--blocked] [--limit N]
                                                the query log, newest first (a name: it and every name below it)
       fabricctl dns-filter stats               the last 24 hours, the last 7 days, per list, the most blocked names
       fabricctl dns-filter ingest [--scheduled]
                                                read the resolver's new log lines into the query log now"""


def _options(args):
    """Purpose: the options of `fabricctl dns-filter log`.
    Inputs:  args — list of str after "log".
    Returns: {"client", "name", "blocked_only", "limit"} for read_query_log.
    Fails:   ValidationError for an unknown option or one without its value.
    Feeds:   run_dns_filter_command."""
    out = {"client": "", "name": "", "blocked_only": False, "limit": 50}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--blocked":
            out["blocked_only"] = True
            i += 1
        elif a in ("--client", "--name", "--limit") and i + 1 < len(args):
            out[a[2:]] = args[i + 1]
            i += 2
        else:
            raise ValidationError(f"unknown option or missing value: {a}")
    return out


def _print_stats(s):
    """Purpose: the statistics as text.
    Inputs:  s — dns_filter_stats' result.
    Returns: None (prints).
    Fails:   never.
    Feeds:   run_dns_filter_command."""
    week = s["week"]
    share = round(100 * week["blocked"] / week["queries"], 1) if week["queries"] else 0
    print(f"last 7 days: {week['queries']} queries, {week['blocked']} blocked ({share}%)")
    print("last 24 hours (UTC):")
    for h in s["hours"]:
        print(f"  {h['hour'][11:16]}  {h['queries']:>7} queries  {h['blocked']:>6} blocked")
    print("by list and rules (7 days):")
    for z in s["zones"]:
        print(f"  {z['list'] or z['zone']}: {z['blocked']} blocked, {z['queries']} rewritten or passed")
    print("most blocked (7 days):")
    for t in s["top_blocked"]:
        print(f"  {t['count']:>6}  {t['name']}  ({t['list'] or t['zone']})")


def run_dns_filter_command(v, argv):
    """Purpose: `fabricctl dns-filter lists | apply | status | log | stats | ingest` (manual 1.12.2.10, 1.12.2.13,
             1.12.3): the DNS filter's lists, its quick apply and its query log (routing only).
    Inputs:  v — rendered vars of the install; argv — list of str after "dns-filter" (default status). `lists
             --scheduled` is the daily lists timer's run (fabric-dns-lists); `ingest --scheduled` the query log's
             (fabric-dns-log).
    Returns: exit status: 0 success; 1 a list failed, the resolver or AdGuard is not answering, or the query log
             refused (its reason printed); 2 usage, or the resolver or the query log is off.
    Fails:   OSError from update_lists or ingest_dns_log writing their files; ValidationError from adguard_password
             (OpenBao locked) is printed as refused.
    Feeds:   fabriclib/cli.py (`fabricctl dns-filter`)."""
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    try:
        if cmd == "status" and not args:
            try:
                password = adguard_password(v) if v.get("install_resolver") else None
            except (ValidationError, KeyError):
                password = None
            return show_filter_status(v, password)
        if cmd in ("lists", "apply") and not v.get("install_resolver"):
            print(f"the DNS filter is off (dns_filter: {v.get('dns_filter')})")
            return 2
        if cmd == "apply" and not args:
            r = apply_dns_filter("root", "cli")
            res = r["resolver"] or {}
            print("resolver: " + ("reloaded" if res.get("reconfigured") else "unchanged" if not res.get("config")
                                  else "NOT reloaded (is it running?)"))
            print("AdGuard Home: " + (", ".join(r["adguard"]) or "unchanged" if r["adguard"] is not None
                                      else f"waiting: {r['waiting']}"))
            return 1 if r["waiting"] or (res.get("config") and not res.get("reconfigured")) else 0
        if cmd == "lists" and args in ([], ["--scheduled"]):
            result = refresh_lists(v, adguard_password(v))
            for lid, st in result["lists"].items():
                if st.get("error") and st["name"] in result["failed"]:
                    print(f"  {st['name']}: FAILED — {st['error']}")
                elif lid in result["changed"]:
                    print(f"  {st['name']}: new copy, {st.get('rules', 0)} rules")
            print(f"{len(result['lists'])} lists: {len(result['changed'])} new copies, {len(result['failed'])} failed"
                  " (each keeps its last good copy)")
            print(f"AdGuard's catalogue: {result['catalogue']} lists" if result["catalogue"] is not None
                  else "AdGuard's catalogue: could not be fetched (the last copy kept)")
            print(f"AdGuard Home: {', '.join(result['synced']) or 'up to date'}" if result["synced"] is not None
                  else f"AdGuard Home: not reached ({result['error']}); it takes the copies when it answers again")
            return 1 if result["error"] or any(
                st["name"] in result["failed"] for st in result["lists"].values()
                if any(i["url"] == st["url"] for i in v.get("dns_filter_lists") or [])) else 0
        if cmd == "ingest" and args in ([], ["--scheduled"]):
            r = ingest_dns_log(v)
            if "off" in r:
                print(f"the query log is off: {r['off']}")
                return 2
            print(f"query log: {r['queries']} queries and {r['rewrites']} rewrites read, {r['adguard']} blocked by a"
                  " list" + (f", {r['skipped']} other lines" if r["skipped"] else "")
                  + (f"; AdGuard not asked ({r['adguard_error']})" if r["adguard_error"] else ""))
            return 0
        if cmd == "log":
            r = read_query_log(v, **_options(args))
            if "off" in r:
                print(f"the query log is off: {r['off']}")
                return 2
            for e in r["entries"]:
                why = f"  {e['action']} via {e['list'] or e['zone']}" if e.get("action") else ""
                print(f"{e['at']}  {e['client']:<15} {e['view']:<10} {e['qtype']:<6} {e['name']}{why}")
            return 0
        if cmd == "stats" and not args:
            s = dns_filter_stats(v)
            if "off" in s:
                print(f"the query log is off: {s['off']}")
                return 2
            _print_stats(s)
            return 0
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    print(USAGE)
    return 2
