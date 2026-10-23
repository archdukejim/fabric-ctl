import ipaddress
import secrets as _random
import time

from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.scancontrol.limits import LARGEST, MAX_PENDING, RUN_WITHIN
from fabriclib.ipam.scancontrol.read_scan_requests import read_scan_requests
from fabriclib.ipam.scancontrol.write_scan_request import write_scan_request
from fabriclib.secrets.load_secrets import load_secrets


def _subnet(plan, text):
    """Purpose: the subnet of the serving site's plan a request names, by its name or its exact network, at most a /22.
    Inputs:  plan — site_plan's result for the serving site; text — what was typed.
    Returns: {"name", "cidr"}.
    Fails:   ValidationError: nothing typed, a network written wrong, one not in that site's plan (the ones that are
             named), one larger than a /22.
    Feeds:   request_scan."""
    text = str(text or "").strip()
    if not text:
        raise ValidationError(f"name the subnet to scan at {plan['site']}: its name or its network")
    subs = plan["subnets"]
    if "/" in text:
        try:
            net = str(ipaddress.ip_network(text, strict=True))
        except ValueError:
            raise ValidationError(f"{text!r} is not a network like 10.2.20.0/24 (host bits zero)")
        found = [s for s in subs if s["cidr"] == net]
    else:
        found = [s for s in subs if s["name"] == text.lower()]
    if not found:
        raise ValidationError(f"{text} is not a subnet of {plan['site']}'s plan ("
                              + (", ".join(f"{s['name']} {s['cidr']}" for s in subs) or "it has none") + ")")
    net = ipaddress.ip_network(found[0]["cidr"])
    if net.num_addresses - 2 > LARGEST:
        raise ValidationError(f"{net} is larger than a /22: at most {LARGEST} addresses are scanned at once")
    return {"name": found[0]["name"], "cidr": str(net)}


def request_scan(v, actor, site, subnet, secrets=None, container="samba", source="cli", caller=None,
                 check=check_access, read=read_plan, requests=read_scan_requests, write=write_scan_request,
                 now=time.time):
    """Purpose: ask another site to scan one of its subnets (decision 2.1.10.38, manual 1.10.4.36): fabric-agent's
             check first (the caller holds the grants' `networks:scan` at that site; root, from the CLI, acts for the
             Enterprise Admin), then a request written into AD below the subnet's entry, as this DC's agent, naming
             the person (`<user>`, or `root@<dc>` from the CLI). The serving site's plan poll checks the person
             again by its own reading of the grants, runs it there and answers. Audited here (IPAM_SCAN_REQUEST). A
             refusal writes nothing.
    Inputs:  v — fabric vars (site_name, dc_name, ad_dc_type, ad_join_server); actor — who asks (audit); site — the
             serving site; subnet — its name or exact network; secrets — fabric's secrets (default load_secrets());
             container — the DC's container; source — "cli" or "web"; caller — the signed-in person's user name, or
             None (root); check, read, requests, write, now — check_access, read_plan, read_scan_requests,
             write_scan_request and time.time (tests give their own).
    Returns: {"id", "site", "subnet", "cidr", "state": "pending", "requested_by" (this site), "actor"}.
    Fails:   ValidationError: no site named, this site ("runs here"), check_access's refusal, _subnet's refusals, a
             request for that subnet still pending, MAX_PENDING pending at that site, the directory refusing or not
             answering; OSError from the audit log.
    Feeds:   run_scan_command (`fabricctl ipam scan <subnet> --site S`); the agent's POST /v1/ipam/scan/request
             joins in area 7 (1.10.4.41)."""
    own = v["site_name"]
    target = str(site or "").strip()
    if not target:
        raise ValidationError("name the site to scan at (--site S)")
    if target.lower() == own.lower():
        raise ValidationError(f"a scan of {own}'s own subnet runs here: fabricctl ipam scan <subnet>")
    allowed = check(v, caller, "networks:scan", {"site": target}, container)
    secrets = secrets if secrets is not None else load_secrets()
    sub = _subnet(site_plan(read(v, secrets, of=target, container=container), target), subnet)
    pending = [r for r in requests(v, target, secrets, container)
               if r["state"] == "pending" and now() - r["created_at"] < RUN_WITHIN]
    if any(r["cidr"] == sub["cidr"] for r in pending):
        raise ValidationError(f"a scan of {sub['cidr']} at {target} is already pending: its answer shows with "
                              f"fabricctl ipam scan-requests --site {target}")
    if len(pending) >= MAX_PENDING:
        raise ValidationError(f"{len(pending)} scans are already pending at {target}: wait for their answers")
    person = caller or f"root@{v.get('dc_name') or own}"
    rid = f"scan-{time.strftime('%Y%m%d%H%M%S', time.gmtime(now()))}-{_random.token_hex(3)}"
    write(v, secrets, "add", target, sub["name"], rid, {"cidr": sub["cidr"], "actor": person}, container=container)
    write_audit(actor, "IPAM_SCAN_REQUEST", f"from={v.get('dc_name') or own} site={target} subnet={sub['cidr']} "
                f"request={rid} by={allowed['by']}", source)
    return {"id": rid, "site": target, "subnet": sub["name"], "cidr": sub["cidr"], "state": "pending",
            "requested_by": own, "actor": person}
