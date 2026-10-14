import base64
import datetime
import hashlib
import json
import os
import secrets
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.federation.common.federation_lock import federation_lock
from fabriclib.federation.constants import DC_TYPE_KIND, DC_TYPE_PREFIX, DC_TYPES, INVITE_TTL_SECONDS
from fabriclib.federation.site_below import site_below
from fabriclib.pki.common.ca_files import ca_files
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.samba.domain_sites import domain_sites
from fabriclib.samba.replication_healthy import replication_healthy
from fabriclib.samba.replication_status import replication_status
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets


def request_dc_type(v, actor, target, to, source="cli", now=None, op=None, sites=None, replication=None,
                    load=load_secrets, save=save_secrets, root_pem=None):
    """Purpose: at a site above another, ask for that site's DC to change type (decision 2.1.9.23, manual
             1.9.8.20.1): checked first (below), then the request written in AD in the site's own OU
             (`set_dc_type_request`) and a one-time change token made (one hour; only its hash kept), which the site's
             admin redeems at this site's federation endpoint for the temporary join account.
    Inputs:  v — fabric vars: site_name, ad_dc_type, federation_endpoint, hostname_federation, host_ip,
             deploy_base_dir (the root CA); actor — who asks (audit); target — the site; to — "writable" or "rodc";
             source — the audit's; now — epoch seconds (tests); op — op(name, args) (default: run_op with
             load_secrets()); sites — domain_sites()'s list (default: read); replication — replication_status()'s
             answer (default: read); load, save — fabric's secrets (tests pass their own); root_pem — the root
             certificate's PEM (default: read from ca_files).
    Returns: {"token" (shown once), "site", "to", "id", "expires" (epoch), "was" (the site's type now)}.
    Fails:   ValidationError, nothing written: `to` not writable or rodc ("none" not built); the federation endpoint
             off; this site's own name; this site's DC read-only; the site not in the domain, or not below this site
             (this site, a sibling, a site above); the site already of that type, or with no DC; this site's
             replication unhealthy (replication_healthy's why); OpenBao locked; a refusal by the directory (from
             run_op).
    Feeds:   run_federation_command (`fabricctl federation dc-type <site> writable|rodc`).
    Notes:   audited FED_DC_TYPE_REQUEST; a second request for the same site replaces the first and its token."""
    target = str(target or "").strip().lower()
    me = v.get("site_name")
    if to == "none":
        raise ValidationError("a change to no DC is not built (1.9.8.12's third type stays open): writable or rodc")
    if to not in DC_TYPES:
        raise ValidationError("a DC type is writable or rodc")
    if not v.get("federation_endpoint"):
        raise ValidationError("the federation endpoint is off: fabricctl federation enable (the site redeems its "
                              "change token there)")
    if target == me:
        raise ValidationError(f"{target} is this site: a site's DC type is requested from a site above it")
    if v.get("ad_dc_type") == "rodc":
        raise ValidationError("this site's domain controller is read-only: it cannot prepare the join account a DC "
                              "type change needs; ask from a site above with a writable DC")
    if op is None:
        stored = load(v=v)
        op = lambda name, args: run_op(v, stored, name, args)      # noqa: E731
    sites = domain_sites() if sites is None else sites
    below, where = site_below(sites, me, target)
    if not where:
        raise ValidationError(f"no site {target} in the domain")
    if not below:
        raise ValidationError(f"site {target} is not below this site ({where}): its DC type is requested from its "
                              "parent or a site above it")
    was = (op("read_site_dcs", {"sites": [target]})["sites"].get(target) or {}).get("type", "none")
    if was == "none":
        raise ValidationError(f"site {target} has no domain controller: a change from none is not built")
    if was == to:
        word = "writable" if to == "writable" else "read-only"
        raise ValidationError(f"site {target}'s domain controller is already {word}: nothing to change")
    ok, why = replication_healthy(replication_status() if replication is None else replication)
    if not ok:
        raise ValidationError(f"this site's replication is not healthy, so no DC type change is requested: {why}")
    now = int(now if now is not None else time.time())
    secret, token_id = secrets.token_urlsafe(32), secrets.token_hex(6)
    expires = now + INVITE_TTL_SECONDS
    request = {"to": to, "by": me, "actor": actor, "id": token_id,
               "at": datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    with federation_lock():
        stored = load(v=v)
        tokens = {i: e for i, e in (stored.get("federation_invitations") or {}).items()
                  if e.get("expires", 0) > now and not (e.get("kind") == DC_TYPE_KIND and e.get("site") == target)}
        tokens[token_id] = {"sha256": hashlib.sha256(secret.encode()).hexdigest(), "site": target, "expires": expires,
                            "actor": actor, "kind": DC_TYPE_KIND, "to": to}
        op("set_dc_type_request", {"target": target, "request": request})
        save({"federation_invitations": tokens}, v=v)
    if root_pem is None:
        root = ca_files(v)[0]
        root_pem = open(root).read() if os.path.exists(root) else ""
    body = {"v": 1, "id": token_id, "secret": secret, "site": target, "to": to, "by": me,
            "host": v.get("hostname_federation"), "address": v.get("host_ip"),
            "root_sha256": describe_cert(root_pem)["sha256"] if root_pem else "", "expires": expires}
    token = DC_TYPE_PREFIX + base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode() \
        .rstrip("=")
    write_audit(actor, "FED_DC_TYPE_REQUEST", f"site={target} to={to} was={was} id={token_id} expires={expires}",
                source)
    return {"token": token, "site": target, "to": to, "id": token_id, "expires": expires, "was": was}
