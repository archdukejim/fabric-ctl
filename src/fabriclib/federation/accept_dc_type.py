import hashlib
import hmac
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.federation.common.federation_lock import federation_lock
from fabriclib.federation.constants import DC_TYPE_KIND, DC_TYPES, SITE_NAME_RE
from fabriclib.samba.run_converge import run_converge
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.random_password import random_password
from fabriclib.secrets.save_secrets import save_secrets

REFUSED = "the change token is not valid (unknown, used, withdrawn or expired)"


def accept_dc_type(v, req, client_ip="", now=None, op=None, converge=run_converge, load=load_secrets,
                   save=save_secrets):
    """Purpose: at the site above that asked for a site's DC type change (decision 2.1.9.23, manual 1.9.8.20.2 step 1),
             redeem the site's one-time change token for the temporary join account its DC re-joins with: the token
             checked (one message for unknown, used, withdrawn, expired or wrong), the request still in AD with the
             same type and id, the join account made (the converge's join account alone: Domain Admins, one hour,
             1.9.8.4) and the token used up.
    Inputs:  v — this site's vars: ad_domain, hostname_dc, host_ip (what the answer names), and what run_op reads;
             req — {"id", "secret", "site", "to"}; client_ip — for the audit; now — epoch seconds (tests); op — op(name,
             args) (default: run_op with load_secrets()); converge, load, save — run_converge and fabric's secrets
             (tests pass their own).
    Returns: {"site", "to", "ad_domain", "dc_host", "dc_address", "join_user", "join_password"}.
    Fails:   ValidationError: "the request is incomplete"; REFUSED (audited FED_DC_TYPE_REFUSED); "the token was made
             for …"; no matching request in AD any more; from run_converge (the DC not running), run_op, the secrets.
    Feeds:   the federation endpoint (src/federation/server.py, POST /v1/dc-type).
    Notes:   audited FED_DC_TYPE_ACCEPTED (actor "site:<name>", with the client address); the join account's password
             is only in the TLS answer, never logged."""
    now = int(now if now is not None else time.time())
    if not isinstance(req, dict) or not all(isinstance(req.get(k), str) and req.get(k)
                                            for k in ("id", "secret", "site", "to")):
        raise ValidationError("the request is incomplete")
    site, to = req["site"].strip().lower(), req["to"]
    if not SITE_NAME_RE.match(site) or to not in DC_TYPES:
        raise ValidationError("the request is incomplete")
    if op is None:
        stored = load(v=v)
        op = lambda name, args: run_op(v, stored, name, args)      # noqa: E731
    with federation_lock():
        tokens = load(v=v).get("federation_invitations") or {}
        entry = tokens.get(req["id"]) or {}
        digest = hashlib.sha256(req["secret"].encode()).hexdigest()
        if not (entry and entry.get("kind") == DC_TYPE_KIND and entry.get("expires", 0) > now
                and hmac.compare_digest(entry.get("sha256", ""), digest)):
            write_audit(f"site:{site}", "FED_DC_TYPE_REFUSED", f"id={req['id'][:16]} from={client_ip}", "federation")
            raise ValidationError(REFUSED)
        if entry.get("site") != site or entry.get("to") != to:
            raise ValidationError(f"the token was made for site {entry.get('site')} to become {entry.get('to')}")
        pending = op("read_dc_type_request", {"target": site}).get("request") or {}
        if pending.get("id") != req["id"] or pending.get("to") != to:
            raise ValidationError(f"no change of site {site}'s DC type to {to} is requested here any more: ask again "
                                  "from the site above")
        password = random_password()
        converge({"join_only": True, "site": site, "join_account": {"name": f"fabric-join-{site}",
                                                                     "password": password}})
        save({"federation_invitations": {i: e for i, e in tokens.items() if i != req["id"]}}, v=v)
    write_audit(f"site:{site}", "FED_DC_TYPE_ACCEPTED", f"site={site} to={to} id={req['id']} from={client_ip}",
                "federation")
    return {"site": site, "to": to, "ad_domain": v["ad_domain"], "dc_host": v["hostname_dc"],
            "dc_address": v["host_ip"], "join_user": f"fabric-join-{site}", "join_password": password}
