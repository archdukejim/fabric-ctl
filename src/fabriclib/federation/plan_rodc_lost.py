from fabriclib.federation.site_below import site_below

RESET_KINDS = ("person", "machine", "service")
SKIPPED = {"dc": "the read-only DC's own account (removed with it)",
           "krbtgt": "the read-only DC's own krbtgt account (removed with it)",
           "protected": "a krbtgt account that is not this DC's (never touched here: see 4.9.1.3)",
           "gone": "no longer in the domain"}


def plan_rodc_lost(v, target, sites, listing=None, record=None):
    """Purpose: what `fabricctl federation rodc-lost <site>` will do, or why it may not (decision 2.1.6.58, manual
             1.9.8.21): first the checks that need nothing from the DC (listing None), then, with the DC's listing,
             every account the site's read-only DC was told the password of, and what is left to do (a record of an
             earlier run that did not finish carries on: its accounts are never reset twice).
    Inputs:  v — fabric vars: site_name, ad_dc_type; target — the site whose read-only DC is lost; sites —
             domain_sites()'s list; listing — the DC's list answer ({"rodcs": [{"name", "dn", "krbtgt", "accounts":
             [{"dn", "name", "kind"}]}]}) or None; record — the incident's record ({"accounts", "reset": [DN],
             "removed": [names], "rodcs": [names], "done_at"}) or None.
    Returns: {"refused": "" or why, "noop": bool (nothing left: no read-only DC and nothing unfinished), "rodcs":
             [names], "accounts": [{"dn", "name", "kind"}] (every one revealed, each once), "reset_left": [{"dn",
             "kind"}], "remove_left": [names], "skipped": [{"dn", "name", "kind", "why"}], "lines": [what it does]}.
    Fails:   never.
    Feeds:   federation/rodc_lost."""
    out = {"refused": "", "noop": False, "rodcs": [], "accounts": [], "reset_left": [], "remove_left": [],
           "skipped": [], "lines": []}
    me, target = v.get("site_name"), str(target or "").strip().lower()
    if target == me:
        out["refused"] = f"{target} is this site: a lost read-only DC is handled from a site above it"
        return out
    if v.get("ad_dc_type") == "rodc":
        out["refused"] = ("this site's domain controller is read-only: a lost read-only DC is handled at a writable "
                          "DC, from a site above the lost DC's site")
        return out
    below, where = site_below(sites, me, target)
    if not where:
        out["refused"] = f"no site {target} in the domain"
        return out
    if not below:
        out["refused"] = (f"site {target} is not below this site ({where}): its lost DC is handled from its parent or "
                          "a site above it")
        return out
    if listing is None:
        return out
    record = record or {}
    open_record = record if record.get("accounts") is not None and not record.get("done_at") else {}
    rodcs = listing.get("rodcs") or []
    seen = {}
    for a in list(open_record.get("accounts") or []) + [a for r in rodcs for a in r.get("accounts") or []]:
        seen.setdefault(a["dn"].lower(), a)
    out["accounts"] = [seen[k] for k in sorted(seen)]
    out["rodcs"] = sorted({r["name"] for r in rodcs} | set(open_record.get("rodcs") or []))
    done = {d.lower() for d in open_record.get("reset") or []}
    removed = {n.lower() for n in open_record.get("removed") or []}
    out["reset_left"] = [{"dn": a["dn"], "kind": a["kind"]} for a in out["accounts"]
                         if a["kind"] in RESET_KINDS and a["dn"].lower() not in done]
    out["remove_left"] = [r["name"] for r in rodcs if r["name"].lower() not in removed]
    out["skipped"] = [{**a, "why": SKIPPED.get(a["kind"], a["kind"])} for a in out["accounts"]
                      if a["kind"] not in RESET_KINDS]
    if not out["reset_left"] and not out["remove_left"]:
        out["noop"] = True
        out["lines"] = [f"site {target} has no read-only DC"
                        + (f" (handled on {record['done_at']})" if record.get("done_at") else "")
                        + ": nothing to do"]
        return out
    count = {k: sum(1 for a in out["reset_left"] if a["kind"] == k) for k in RESET_KINDS}
    if count["person"]:
        out["lines"].append(f"reset {count['person']} person(s)' password to a random one nobody is told, to be "
                            "changed at the next sign-in: each signs in again once an admin of their site gives "
                            "them a one-time password (fabricctl people reset <uid>, or Directory > Reset sign-in)")
    if count["machine"]:
        out["lines"].append(f"rotate {count['machine']} machine account(s)' password: each machine signs in to the "
                            "domain again only once it is joined again (4.9.1.3)")
    if count["service"]:
        out["lines"].append(f"rotate {count['service']} service account(s)' password: fabric's own are set again by "
                            "the site's fabric when it is set up again; any other's owner sets a new one")
    for name in out["remove_left"]:
        out["lines"].append(f"remove the read-only DC {name}: its computer account with its password replication "
                            f"allow list ({target}-rodc-cache), its own krbtgt account (every ticket it issued stops "
                            f"working), its server objects and DNS records; site {target} has no DC until a new one "
                            "joins")
    return out
