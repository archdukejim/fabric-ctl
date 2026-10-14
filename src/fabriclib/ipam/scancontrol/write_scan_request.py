from fabriclib.directory.run_op import run_op
from fabriclib.samba.writable_server import writable_server


def write_scan_request(v, secrets, do, site, subnet, rid, fields=None, container="samba"):
    """Purpose: one change to a scan request in the domain (decision 2.1.10.30, manual 1.10.4.29.3), as this site's
             agent, at a writable DC (this site's, or a read-only DC's writable partner): "add" (asked from above),
             "finish" (answered by the branch) or "remove" (the branch, a day on). AD decides who may.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server); secrets — fabric's secrets (ad_agent_password);
             do — "add", "finish" or "remove"; site — the branch; subnet — the subnet entry's name; rid — the request's
             id; fields — as the DC's write_scan_request; container — the DC's container.
    Returns: str, what changed.
    Fails:   ValidationError from samba/writable_server (a read-only DC with no writable partner) or run_op ("the
             directory refused the change (not permitted for this site)", "no such entry", the DC not reachable).
    Feeds:   request_scan, run_scan_requests."""
    server = writable_server(v, "write the scan request at")
    return run_op(v, secrets, "write_scan_request", {"do": do, "of": site, "subnet": subnet, "rid": rid,
                                                       "fields": fields or {}}, container=container, server=server)
