import datetime

from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.common.apply_plan_change import apply_plan_change
from fabriclib.ipam.scan_subnet import scan_subnet
from fabriclib.ipam.scancontrol.request_scan import request_scan


def post_ipam_scan(route, actor, data, caller=None, apply=True):
    """Purpose: the console's scans (manual 1.10.4.22, 1.10.4.36; decisions 2.1.10.26 and 2.1.10.38): POST
             /v1/ipam/scan runs one scan of this site's subnet and answers what it found; POST /v1/ipam/scan/record
             records one address it found in use but unrecorded — a reservation for the MAC ARP saw, or a static
             address when no MAC was seen — then applies it like every plan change; POST /v1/ipam/scan/request asks
             another site to scan one of its subnets (request_scan). Each function checks the signed-in person's
             right first: `scan` at the site for a scan or a request, `plan` here to record.
    Inputs:  route — segments after /v1/ (["ipam", "scan"], [..., "record"] or [..., "request"]); actor — the
             verified user; data — the body: subnet (scan: its name or network); ip, kind (reservation or static), mac,
             name (record); site, subnet (request); caller — the signed-in person (None: a root peer); apply —
             False when a find recorded is run as a held change of the Networks page (1.10.4.40.3).
    Returns: scan: scan_subnet's result. record: {"address": the address as recorded, and apply_plan_change's result}.
             request: request_scan's result.
    Fails:   ValidationError (-> 400): what scan_subnet, add_address or request_scan refuses (the grant first), a kind
             other than reservation or static, a field that is not text; RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route.py."""
    sub = route[2:]
    v = load_vars()
    if not sub:
        return scan_subnet(v, actor, read_text(data, "subnet"), source="web", caller=caller)
    if sub == ["request"]:
        return request_scan(v, actor, read_text(data, "site"), read_text(data, "subnet"), source="web", caller=caller)
    if sub != ["record"]:
        raise RouteNotFound()
    kind = read_text(data, "kind") or "reservation"
    if kind not in ("reservation", "static"):
        raise ValidationError("an address a scan found is recorded as a reservation or a static address")
    out = add_address(v, actor, read_text(data, "ip"), kind, "", read_text(data, "name"), read_text(data, "mac"), "",
                      f"found by a scan on {datetime.date.today().isoformat()}", False, None, source="web",
                      caller=caller)
    return {"address": out["result"], **apply_plan_change(v, actor, out, apply=apply)}
