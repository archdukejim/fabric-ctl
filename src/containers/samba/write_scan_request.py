import re

import ldb

from paths import site_dn

ID = re.compile(r"^scan-[0-9]{14}-[0-9a-f]{6}$")
STATES = ("done", "refused", "expired")


def _dn(samdb, of, subnet, rid):
    """Purpose: where a request lives: below its subnet's entry in the site's OU=networks (every name escaped).
    Inputs:  samdb — SamDB; of — the site; subnet — the subnet entry's name; rid — the request's id.
    Returns: ldb.Dn.
    Fails:   ValueError: no such site, an id fabric does not make.
    Feeds:   write_scan_request."""
    if not ID.match(str(rid or "")):
        raise ValueError(f"not a scan request's id: {rid!r}")
    try:
        base = f"OU=networks,{site_dn(samdb, of)}"
    except LookupError:
        raise ValueError(f"no such site: {of}")
    parent = ldb.Dn(samdb, f"CN=x,{base}")
    parent.set_component(0, "CN", str(subnet))
    dn = ldb.Dn(samdb, f"CN=x,{parent}")
    dn.set_component(0, "CN", rid)
    return dn


def write_scan_request(samdb, lp, site, do, of, subnet, rid, fields=None):
    """Purpose: one change to a scan request (decision 2.1.10.30, manual 1.10.4.29.3): "add" by a site above (the
             request, pending, naming the signed-in site as the one that asked: never a site the caller names); "finish"
             by the branch (its state, result and when); "remove" by the branch (24 h after it was made). AD decides who
             may: a site above creates through its inherited full control; the branch's own agent is denied creating
             one (ensure_site_acl) and may answer and remove; a sibling has no access at all.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — the signed-in site (the asking one, for
             "add"); do — "add", "finish" or "remove"; of — the branch; subnet — the subnet entry's name; rid — the
             request's id ("scan-<YYYYmmddHHMMSS>-<6 hex>"); fields — add: {"cidr", "actor"}; finish: {"state" (done,
             refused or expired), "result" (text, the JSON or why), "done_at"}.
    Returns: str, what changed.
    Fails:   ValueError: an unknown change, a state fabric does not write, a bad id, no such site; ldb.LdbError when AD
             refuses (insufficient access: a sibling, the branch creating its own; no such object: the subnet or the
             request gone; already exists).
    Feeds:   directory_ops (op "write_scan_request")."""
    dn, fields = _dn(samdb, of, subnet, rid), fields or {}
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
