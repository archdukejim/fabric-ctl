import datetime

from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.ipam.add_address import add_address
from fabriclib.ipam.scan_subnet import scan_subnet
from fabriclib.security.refresh_firewall import refresh_firewall
from fabriclib.system.apply_changes import apply_changes


def post_ipam_scan(route, actor, data):
    """Purpose: the console's scan of a subnet (manual 1.10.4.21, decision 2.1.10.26): POST /v1/ipam/scan runs one
             scan and answers what it found; POST /v1/ipam/scan/record records one address it found in use but
             unrecorded — a reservation for the MAC ARP saw ("make it a reservation?", the existing reservation unit
             add_address), or a static address when no MAC was seen — then applies it like every plan change.
    Inputs:  route — segments after /v1/ (["ipam", "scan"] or ["ipam", "scan", "record"]); actor — the verified user;
             data — the body: subnet (scan: its name or network); ip, kind (reservation or static), mac, name
             (record).
    Returns: scan: scan_subnet's result. record: {"address": the address as recorded, "warnings", "applied" (bool:
             the apply and the firewall both done), "output" (their last 2000 characters)}.
    Fails:   ValidationError (-> 400): what scan_subnet or add_address refuses, a kind other than reservation or
             static; RouteNotFound (-> 404) for another route.
    Feeds:   agent/post_route.py."""
    sub = route[2:]
    if not sub:
        return scan_subnet(load_vars(), actor, read_text(data, "subnet"), source="web")
    if sub != ["record"]:
        raise RouteNotFound()
    kind = read_text(data, "kind") or "reservation"
    if kind not in ("reservation", "static"):
        raise ValidationError("an address a scan found is recorded as a reservation or a static address")
    out = add_address(load_vars(), actor, read_text(data, "ip"), kind, "", read_text(data, "name"),
                      read_text(data, "mac"), "", f"found by a scan on {datetime.date.today().isoformat()}",
                      False, None, source="web")
    ok, output = apply_changes(actor, source="web")
    if ok:
        ok, more = refresh_firewall()
        output += "\n" + more
    return {"address": out["result"], "warnings": out["warnings"], "applied": ok, "output": output[-2000:]}
