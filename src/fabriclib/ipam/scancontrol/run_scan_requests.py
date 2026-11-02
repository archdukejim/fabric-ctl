import datetime
import re
import time

from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.scan_busy import ScanBusy
from fabriclib.ipam.scan_subnet import scan_subnet
from fabriclib.ipam.scancontrol.bound_result import bound_result
from fabriclib.ipam.scancontrol.limits import KEEP, PER_RUN, RUN_WITHIN
from fabriclib.ipam.scancontrol.read_scan_requests import read_scan_requests
from fabriclib.ipam.scancontrol.write_scan_request import write_scan_request

ROOT = re.compile(r"^root@[A-Za-z0-9-]{1,15}$")      # root at a fabric host: acts for the Enterprise Admin


def _answer(v, secrets, write, container, r, state, text, at):
    """Purpose: write a request's answer back on it in AD.
    Inputs:  v, secrets — as run_scan_requests; write — write_scan_request; container — the DC's container; r — the
             request; state — "done", "refused" or "expired"; text — the result's JSON, or why; at — when (ISO).
    Returns: None.
    Fails:   ValidationError from the write.
    Feeds:   run_scan_requests."""
    write(v, secrets, "finish", r["site"], r["subnet"], r["id"], {"state": state, "result": text, "done_at": at},
          container=container)


def _who_may(v, r, check, container):
    """Purpose: whether the person a request names may scan at this site, by this site's own reading of the grants
             (decision 2.1.10.38): root at a fabric host always; anyone else through check_access's `networks:scan`
             here (a Directory Administrator by tier, or a grant naming this site or `all`).
    Inputs:  v — fabric vars (site_name); r — the request (actor); check — check_access; container — the DC's
             container.
    Returns: None when allowed, else why (str).
    Fails:   never: a refusal of check_access is its answer.
    Feeds:   run_scan_requests."""
    actor = str(r.get("actor") or "")
    if ROOT.match(actor):
        return None
    if not actor or "@" in actor:
        return f"the request names no person this site can check ({actor or 'none'})"
    try:
        check(v, actor, "networks:scan", {"site": v["site_name"]}, container)
    except ValidationError as exc:
        return str(exc)
    return None


def _refuse(v, secrets, write, container, r, why, at, out):
    """Purpose: answer a request "refused" with why, audited, never run.
    Inputs:  as run_scan_requests' parts; why — str; out — the result being built.
    Returns: None.
    Fails:   ValidationError from the write; OSError from the audit log.
    Feeds:   run_scan_requests."""
    _answer(v, secrets, write, container, r, "refused", why, at)
    write_audit(f"{r['actor']}@{r['requested_by']}", "IPAM_SCAN_REQUEST_REFUSED",
                f"site={v['site_name']} subnet={r['cidr']} request={r['id']} owner={r['owner']} why={why}", "request")
    out["refused"].append(r["id"])


def run_scan_requests(v, secrets, container="samba", requests=read_scan_requests, write=write_scan_request,
                      scan=scan_subnet, check=check_access, now=time.time):
    """Purpose: at the serving site, the plan poll's step that answers the scans other sites requested (decision
             2.1.10.38, manual 1.10.4.36): this site's requests read from AD; each older than a day removed; a pending
             one answered "refused" (never run) when its owner in AD is not a fabric DC's agent account or the person
             it names does not hold `networks:scan` here by this site's own reading of the grants (_who_may); one
             pending longer than an hour answered "expired"; then at most PER_RUN run here by scan_subnet (as
             "<person>@<site>", source "request", every limit kept) and the result written back, bounded
             (bound_result). A scan refused only for now (ScanBusy) stays pending; any other refusal is answered
             "refused" with why. Audited: IPAM_SCAN by scan_subnet, IPAM_SCAN_REQUEST_REFUSED for one refused here.
    Inputs:  v — fabric vars (site_name, install_kea, …); secrets — fabric's secrets (ad_agent_password); container —
             the DC's container; requests, write, scan, check, now — read_scan_requests, write_scan_request,
             scan_subnet, check_access and time.time (tests give their own).
    Returns: {"ran" [request ids], "refused" [ids], "expired" [ids], "removed" [ids], "pending" (bool: one still waits,
             so the poll reads them again next run)}.
    Fails:   ValidationError from reading or writing the requests (the DC not answering); OSError from the audit log.
             A failure leaves the requests not yet answered pending, so the next run tries again.
    Feeds:   ipam/poll_plan (each run of fabric-plan-watch)."""
    site = v["site_name"]
    out = {"ran": [], "refused": [], "expired": [], "removed": [], "pending": False}
    at = datetime.datetime.now().isoformat(timespec="seconds")
    for r in requests(v, site, secrets, container):
        age = now() - r["created_at"]
        if age > KEEP:
            write(v, secrets, "remove", site, r["subnet"], r["id"], container=container)
            out["removed"].append(r["id"])
            continue
        if r["state"] != "pending":
            continue
        if not r.get("by_agent"):
            _refuse(v, secrets, write, container, r, f"not made by a fabric DC's agent account (made by "
                    f"{r['owner'] or 'an unknown account'})", at, out)
            continue
        why = _who_may(v, r, check, container)
        if why:
            _refuse(v, secrets, write, container, r, why, at, out)
            continue
        if age > RUN_WITHIN:
            _answer(v, secrets, write, container, r, "expired", f"not run: {site} did not pick it up within an hour",
                    at)
            out["expired"].append(r["id"])
            continue
        if len(out["ran"]) >= PER_RUN:
            out["pending"] = True
            continue
        try:
            result = scan(v, f"{r['actor']}@{r['requested_by']}", r["cidr"], source="request",
                          requested={"id": r["id"], "by": r["requested_by"]})
        except ScanBusy:
            out["pending"] = True
            continue
        except ValidationError as exc:
            _refuse(v, secrets, write, container, r, str(exc), at, out)
            continue
        _answer(v, secrets, write, container, r, "done", bound_result(result), at)
        out["ran"].append(r["id"])
    return out
