import ipaddress
import secrets as _random
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.common.site_scope import site_scope
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.scancontrol.limits import MAX_PENDING, RUN_WITHIN
from fabriclib.ipam.scancontrol.read_scan_requests import read_scan_requests
from fabriclib.ipam.scancontrol.write_scan_request import write_scan_request
from fabriclib.ipam.scannable_subnets import LARGEST
from fabriclib.secrets.load_secrets import load_secrets


def _subnet(plan, text):
    """Purpose: the subnet of the branch's plan a request names, by its name or its exact network, at most a /22.
    Inputs:  plan — site_plan's result for the branch; text — what was typed.
    Returns: {"name", "cidr"}.
    Fails:   ValidationError: nothing typed, a network written wrong, one not in the branch's plan (the ones that are
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


def request_scan(v, actor, site, subnet, secrets=None, container="samba", source="cli", read=read_plan,
                 requests=read_scan_requests, write=write_scan_request, scope=site_scope, now=time.time):
    """Purpose: ask a site below this one to scan one of its subnets (decision 2.1.10.30, manual 1.10.4.29.3): a scan
             request written into AD below the subnet's entry in the branch's plan, which the branch's plan poll runs
             and answers there. Only from a site above (the Networks tab's scope); the scan itself always runs at the
             branch. Audited here (IPAM_SCAN_REQUEST). A refusal writes nothing.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server); actor — who asks; site — the branch; subnet — its
             name or exact network; secrets — fabric's secrets (default load_secrets()); container — the DC's
             container; source — "cli" or "web"; read, requests, write, scope, now — read_plan, read_scan_requests,
             write_scan_request, site_scope and time.time (tests give their own).
    Returns: {"id", "site", "subnet", "cidr", "state": "pending", "requested_by" (this site), "actor"}.
    Fails:   ValidationError: no site named, this site ("runs here"), a site not below this one (a sibling, a parent:
             site_scope, before the domain is asked), _subnet's refusals, a request for that subnet still pending,
             MAX_PENDING pending at the branch, the directory refusing or not answering; OSError from the audit log.
    Feeds:   run_scan_command (`fabricctl ipam scan <subnet> --site S`), agent POST /v1/ipam/scan/request."""
    own = v["site_name"]
    if not str(site or "").strip():
        raise ValidationError("name the site below this one to scan at (--site S)")
    if str(site).strip().lower() == own.lower():
        raise ValidationError(f"a scan of {own}'s own subnet runs here: Scan now, or fabricctl ipam scan <subnet>")
    branch = scope(v, site)
    secrets = secrets if secrets is not None else load_secrets()
    sub = _subnet(site_plan(read(v, secrets, of=branch, container=container), branch), subnet)
    pending = [r for r in requests(v, branch, secrets, container)
               if r["state"] == "pending" and now() - r["created_at"] < RUN_WITHIN]
    if any(r["cidr"] == sub["cidr"] for r in pending):
        raise ValidationError(f"a scan of {sub['cidr']} at {branch} is already pending: its answer shows on the "
                              "Networks tab (fabricctl ipam scan-requests --site " + branch + ")")
    if len(pending) >= MAX_PENDING:
        raise ValidationError(f"{len(pending)} scans are already pending at {branch}: wait for their answers")
    rid = f"scan-{time.strftime('%Y%m%d%H%M%S', time.gmtime(now()))}-{_random.token_hex(3)}"
    write(v, secrets, "add", branch, sub["name"], rid, {"cidr": sub["cidr"], "actor": actor}, container=container)
    write_audit(actor, "IPAM_SCAN_REQUEST", f"from={own} site={branch} subnet={sub['cidr']} request={rid}", source)
    return {"id": rid, "site": branch, "subnet": sub["name"], "cidr": sub["cidr"], "state": "pending",
            "requested_by": own, "actor": actor}
