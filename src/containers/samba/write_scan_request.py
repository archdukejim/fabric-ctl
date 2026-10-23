import re

import ldb

import paths

ID = re.compile(r"^scan-[0-9]{14}-[0-9a-f]{6}$")
STATES = ("done", "refused", "expired")


def request_dn(samdb, of, subnet, rid):
    """Purpose: where a scan request lives: below its subnet's entry `CN=<site>/<subnet>` in the domain's OU=networks
             (manual 1.10.4.33), every name escaped.
    Inputs:  samdb — SamDB; of — the site that serves the subnet; subnet — the subnet's name; rid — the request's id.
    Returns: ldb.Dn.
    Fails:   ValueError for an id fabric does not make, or no site or subnet named.
    Feeds:   write_scan_request."""
    if not ID.match(str(rid or "")):
        raise ValueError(f"not a scan request's id: {rid!r}")
    if not of or not subnet:
        raise ValueError("a scan request names its site and its subnet")
    return paths.plan_entry_dn(samdb, str(of), str(subnet), below=rid)


def write_scan_request(samdb, lp, site, do, of, subnet, rid, fields=None):
    """Purpose: one change to a scan request (decision 2.1.10.38, manual 1.10.4.36): "add" by any DC's agent for a
             person fabric-agent has checked (the request, pending, naming the signed-in DC's site as the one that
             asked, never a site the caller names); "finish" by the serving site (its state, result and when, after
             its own check of the grants); "remove" by the serving site (a day after it was made). Its owner in AD is
             the account that made it, which the serving site checks.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — the signed-in DC's site (the asking
             one, for "add"); do — "add", "finish" or "remove"; of — the serving site; subnet — the subnet's name;
             rid — the request's id ("scan-<YYYYmmddHHMMSS>-<6 hex>"); fields — add: {"cidr", "actor"}; finish:
             {"state" (done, refused or expired), "result" (text: the JSON, or why), "done_at"}.
    Returns: str, what changed.
    Fails:   ValueError: an unknown change, a state fabric does not write, a bad id, no site or subnet named;
             ldb.LdbError when AD refuses (no such object: the subnet or the request gone; already exists).
    Feeds:   directory_ops (op "write_scan_request")."""
    dn, fields = request_dn(samdb, of, subnet, rid), fields or {}
    if do == "add":
        samdb.add({"dn": dn, "objectClass": "fabricScanRequest", "fabricCidr": str(fields["cidr"]),
                   "fabricScanRequestedBy": site, "fabricScanActor": str(fields.get("actor") or "?"),
                   "fabricScanState": "pending"})
        return f"scan of {fields['cidr']} requested at {of} ({rid})"
    if do == "finish":
        if fields.get("state") not in STATES:
            raise ValueError(f"a scan request is answered {', '.join(STATES)} (got {fields.get('state')!r})")
        msg = ldb.Message(dn)
        for attr, key in (("fabricScanState", "state"), ("fabricScanResult", "result"),
                          ("fabricScanDoneAt", "done_at")):
            value = str(fields.get(key) or "")
            msg[attr] = ldb.MessageElement([value] if value else [], ldb.FLAG_MOD_REPLACE, attr)
        samdb.modify(msg)
        return f"scan request {rid} at {of} {fields['state']}"
    if do == "remove":
        samdb.delete(dn)
        return f"scan request {rid} at {of} removed"
    raise ValueError(f"unknown scan request change: {do!r}")
