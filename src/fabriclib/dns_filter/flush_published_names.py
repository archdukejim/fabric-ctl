from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc


def _why(res):
    """Purpose: what rndc said when a flush failed.
    Inputs:  res — resolver_rndc()'s result (CompletedProcess or None).
    Returns: str.
    Fails:   never.
    Feeds:   flush_published_names."""
    if res is None:
        return "the resolver did not answer (is bind9-resolver running?)"
    return (res.stderr or res.stdout or f"exit {res.returncode}").strip().splitlines()[-1]


def flush_published_names(v, changed, call=resolver_rndc):
    """Purpose: the filtering resolver made to forget what it cached for the names fabric just published (decision
             2.1.10.46, manual 1.10.4.44): a client that asked for a name before it existed got an NXDOMAIN the
             resolver keeps for up to three hours (the zone's negative TTL; 2.3.10.11.16), and a changed or removed
             name its old answer. `rndc flushname` for each name (every view: the client groups' too), `rndc
             flushtree` for a zone flushed whole; after BIND serves the new records.
    Inputs:  v — the settings (install_resolver); changed — changed_names' result; call — resolver_rndc (tests give
             their own).
    Returns: {"flushed": how many names and zones were flushed, "error": why the rest were not, or None}; nothing is
             asked with the resolver off or nothing changed.
    Fails:   never: a flush that fails is said in "error" (the callers print it); BIND serves the new records
             either way, and the resolver's copy expires on its own.
    Feeds:   deploy/restart_changed (an apply), dns/apply_dns (DNS' own Apply), dns/publish_zone_list (a zone
             added or removed, flushed whole: 2.1.4.9), dns/publish_plan_records (Sync now)."""
    asks = [["flushtree", z] for z in changed.get("trees") or []] + \
        [["flushname", n.rstrip(".")] for n in changed.get("names") or []]
    if not v.get("install_resolver") or not asks:
        return {"flushed": 0, "error": None}
    done = 0
    for args in asks:
        res = call(args, timeout=15)
        if res is None or res.returncode != 0:
            return {"flushed": done, "error": f"the filtering resolver did not forget {args[1]} ({_why(res)}): it "
                                              "answers from its cache until that expires"}
        done += 1
    return {"flushed": done, "error": None}
