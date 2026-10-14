import datetime
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.scan_busy import ScanBusy
from fabriclib.ipam.scan_subnet import scan_subnet
from fabriclib.ipam.scancontrol.bound_result import bound_result
from fabriclib.ipam.scancontrol.limits import KEEP, PER_RUN, RUN_WITHIN
from fabriclib.ipam.scancontrol.read_scan_requests import read_scan_requests
from fabriclib.ipam.scancontrol.write_scan_request import write_scan_request


def _answer(v, secrets, write, container, r, state, text, at):
    """Purpose: write a request's answer back on it in AD.
    Inputs:  v, secrets — as run_scan_requests; write — write_scan_request; container — the DC's container; r — the
             request; state — "done", "refused" or "expired"; text — the result's JSON, or why; at — when (ISO).
    Returns: None.
    Fails:   ValidationError from the write.
    Feeds:   run_scan_requests."""
    write(v, secrets, "finish", r["site"], r["subnet"], r["id"], {"state": state, "result": text, "done_at": at},
          container=container)


def run_scan_requests(v, secrets, container="samba", requests=read_scan_requests, write=write_scan_request,
                      scan=scan_subnet, now=time.time):
    """Purpose: at a branch, the plan poll's step that answers the scans requested from above (decision 2.1.10.30,
             manual 1.10.4.29.3): this site's requests read from AD; each older than a day removed; one not made by
             the agent of a site above this one answered "refused" (never run); one pending longer than an hour
             answered "expired"; then at most PER_RUN run here by scan_subnet (as "<person>@<site>", source "request",
             the local-scan setting not asked, every limit kept) and the result written back, bounded (bound_result).
             A scan refused only for now (ScanBusy) stays pending; any other refusal is answered "refused" with why.
             Audited: IPAM_SCAN by scan_subnet, IPAM_SCAN_REQUEST_REFUSED for a request refused here.
    Inputs:  v — fabric vars (site_name, install_kea, …); secrets — fabric's secrets (ad_agent_password); container —
             the DC's container; requests, write, scan, now — read_scan_requests, write_scan_request, scan_subnet and
             time.time (tests give their own).
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
        if not r["from_above"]:
            why = (f"not requested by a site above {site}: the request names {r['requested_by'] or 'no site'} and was "
                   f"made by {r['owner'] or 'an unknown account'}")
            _answer(v, secrets, write, container, r, "refused", why, at)
            write_audit(f"{r['actor']}@{r['requested_by']}", "IPAM_SCAN_REQUEST_REFUSED",
                        f"site={site} subnet={r['cidr']} request={r['id']} owner={r['owner']}", "request")
            out["refused"].append(r["id"])
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
            _answer(v, secrets, write, container, r, "refused", str(exc), at)
            write_audit(f"{r['actor']}@{r['requested_by']}", "IPAM_SCAN_REQUEST_REFUSED",
                        f"site={site} subnet={r['cidr']} request={r['id']} why={exc}", "request")
            out["refused"].append(r["id"])
            continue
        _answer(v, secrets, write, container, r, "done", bound_result(result), at)
        out["ran"].append(r["id"])
    return out
