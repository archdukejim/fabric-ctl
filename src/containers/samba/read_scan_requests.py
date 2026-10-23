import calendar
import json
import re
import time

import ldb
from samba.dcerpc import security
from samba.ndr import ndr_unpack

import paths

ATTRS = ["cn", "fabricCidr", "fabricScanRequestedBy", "fabricScanActor", "fabricScanState", "fabricScanResult",
         "fabricScanDoneAt", "whenCreated", "nTSecurityDescriptor"]
AGENT = re.compile(r"^fabric-agent-dc-[0-9]{4}$", re.IGNORECASE)     # a fabric DC's agent account (2.1.6.82)


def _one(m, name):
    """Purpose: one attribute of a search result as text.
    Inputs:  m — ldb.Message; name — attribute.
    Returns: str ("" when absent).
    Fails:   never.
    Feeds:   read_scan_requests."""
    return str(m.get(name, idx=0) or "")


def _owner(samdb, m, names):
    """Purpose: who made a request: its security descriptor's owner (the creating account: an agent is no
             administrator, so AD makes it the owner), by account name.
    Inputs:  samdb — SamDB; m — ldb.Message read with the sd_flags control (the owner only); names — dict, SIDs
             already looked up (filled in).
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
    """Purpose: the scan requests below a site's subnets (decision 2.1.10.38, manual 1.10.4.36), each with its answer
             and whether a fabric DC's agent account made it (the serving site's poll then checks the person's grant
             itself, and runs only those).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); of — the site whose
             requests are read.
    Returns: list of {"id", "site", "subnet" (the subnet's name), "cidr", "requested_by", "actor", "state", "result"
             (the parsed JSON, {"error": text} for a value that is not JSON, None when unanswered), "done_at",
             "created" (ISO, from whenCreated), "created_at" (epoch seconds), "owner", "by_agent" (bool)}, oldest
             first.
    Fails:   ValueError when no site is named; ldb.LdbError from the searches.
    Feeds:   directory_ops (op "read_scan_requests")."""
    if not of:
        raise ValueError("whose scan requests: no site named")
    prefix, names, out = f"{of}/".lower(), {}, []
    for m in samdb.search(base=paths.folder_dn(samdb, "networks"), scope=ldb.SCOPE_SUBTREE,
                          expression="(objectClass=fabricScanRequest)", attrs=ATTRS, controls=["sd_flags:1:1"]):
        parent = str(m.dn.parent().get_rdn_value())
        if not parent.lower().startswith(prefix):
            continue
        made = _one(m, "whenCreated")
        epoch = calendar.timegm(time.strptime(made[:14], "%Y%m%d%H%M%S")) if made else 0
        text = _one(m, "fabricScanResult")
        try:
            result = json.loads(text) if text else None
        except ValueError:
            result = {"error": text}
        owner = _owner(samdb, m, names)
        out.append({"id": _one(m, "cn"), "site": of, "subnet": parent.split("/", 1)[1],
                    "cidr": _one(m, "fabricCidr"), "requested_by": _one(m, "fabricScanRequestedBy"),
                    "actor": _one(m, "fabricScanActor"), "state": _one(m, "fabricScanState") or "pending",
                    "result": result, "done_at": _one(m, "fabricScanDoneAt"),
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)) if epoch else "",
                    "created_at": epoch, "owner": owner, "by_agent": bool(AGENT.match(owner))})
    return sorted(out, key=lambda r: (r["created_at"], r["id"]))
