import calendar
import json
import time

import ldb
from samba.dcerpc import security
from samba.ndr import ndr_unpack

from paths import ancestors, site_dn

ATTRS = ["cn", "fabricCidr", "fabricScanRequestedBy", "fabricScanActor", "fabricScanState", "fabricScanResult",
         "fabricScanDoneAt", "whenCreated", "nTSecurityDescriptor"]


def _one(m, name):
    """Purpose: one attribute of a search result as text.
    Inputs:  m — ldb.Message; name — attribute.
    Returns: str ("" when absent).
    Fails:   never.
    Feeds:   read_scan_requests."""
    return str(m.get(name, idx=0) or "")


def _owner(samdb, m, names):
    """Purpose: who created a request: its security descriptor's owner (the creating account; an agent is no
             administrator, so AD makes it the owner, and nobody below it may change that), by account name.
    Inputs:  samdb — SamDB; m — ldb.Message read with the sd_flags control (the owner only); names — dict, SIDs already
             looked up (filled in).
    Returns: str, the owner's sAMAccountName ("" when the descriptor was not readable or the SID has no account).
    Fails:   ldb.LdbError from the lookup.
    Feeds:   read_scan_requests."""
    raw = m.get("nTSecurityDescriptor", idx=0)
    if raw is None:
        return ""
    sid = str(ndr_unpack(security.descriptor, bytes(raw)).owner_sid)
    if sid not in names:
        res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                           expression=f"(objectSid={ldb.binary_encode(sid)})", attrs=["sAMAccountName"])
        names[sid] = _one(res[0], "sAMAccountName") if len(res) else ""
    return names[sid]


def read_scan_requests(samdb, lp, site, of):
    """Purpose: the scan requests in a site's plan (decision 2.1.10.30, manual 1.10.4.29.3), each with its answer and
             whether a site above the site made it: its owner is the agent of the site it names, and that site is one
             of the site's ancestors in AD (the branch's poll runs only those).
    Inputs:  samdb — SamDB (as the asking site's agent: its read access applies; the owner needs read-control, which
             the site and the sites above it hold); lp — LoadParm (unused); site — str (unused); of — the site whose
             requests are read.
    Returns: list of {"id", "site", "subnet" (the subnet entry's name), "cidr", "requested_by", "actor", "state",
             "result" (the parsed JSON, or {"error": text} for a value that is not JSON, None when unanswered),
             "done_at", "created" (ISO, from whenCreated), "created_at" (epoch seconds), "owner", "from_above" (bool)},
             oldest first.
    Fails:   ValueError "no such site: <of>"; ldb.LdbError from the searches.
    Feeds:   directory_ops (op "read_scan_requests")."""
    try:
        base = f"OU=networks,{site_dn(samdb, of)}"
    except LookupError:
        raise ValueError(f"no such site: {of}")
    above, names, out = ancestors(samdb, of), {}, []
    for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression="(objectClass=fabricScanRequest)",
                          attrs=ATTRS, controls=["sd_flags:1:1"]):
        made = _one(m, "whenCreated")
        epoch = calendar.timegm(time.strptime(made[:14], "%Y%m%d%H%M%S")) if made else 0
        text = _one(m, "fabricScanResult")
        try:
            result = json.loads(text) if text else None
        except ValueError:
            result = {"error": text}
        by, owner = _one(m, "fabricScanRequestedBy"), _owner(samdb, m, names)
        out.append({"id": _one(m, "cn"), "site": of, "subnet": str(m.dn.parent().get_rdn_value()),
                    "cidr": _one(m, "fabricCidr"), "requested_by": by, "actor": _one(m, "fabricScanActor"),
                    "state": _one(m, "fabricScanState") or "pending", "result": result,
                    "done_at": _one(m, "fabricScanDoneAt"),
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)) if epoch else "",
                    "created_at": epoch, "owner": owner,
                    "from_above": bool(by) and by in above and owner.lower() == f"fabric-agent-{by}".lower()})
    return sorted(out, key=lambda r: (r["created_at"], r["id"]))
