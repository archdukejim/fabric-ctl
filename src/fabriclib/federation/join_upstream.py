import datetime
import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import AUDIT_FILE, FEDERATION_FILE, FEDERATION_LOCK_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.federation.common.federation_lock import federation_lock
from fabriclib.federation.common.fetch_pinned_root import fetch_pinned_root
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.common.post_upstream import post_upstream
from fabriclib.federation.common.save_registry import save_registry
from fabriclib.federation.constants import DOMAIN_RE
from fabriclib.federation.decode_invitation import decode_invitation
from fabriclib.federation.site_networks import site_networks
from fabriclib.pki.make_site_ca_request import make_site_ca_request
from fabriclib.pki.stage_site_ca import stage_site_ca
from fabriclib.samba.dc_name_problem import dc_name_problem

ORG_KEYS = ("friendly_name", "cert_country", "cert_province", "cert_city", "cert_org", "cert_ou")


def join_upstream(v, invitation, password, work_dir, domain, address, config_dir=None, audit_path=None,
                  http_port=80, https_port=443, replace=False, dns_port=53):
    """Purpose: On a node being set up with `--join`: join the upstream that made the invitation (manual 1.9.4.1 step
                2): make this site's CA key and request, fetch and pin the upstream's root,
             send the join over TLS verified against that root, check and stage the signed intermediate, and
             record the upstream.
    Inputs:  v — fabric vars: service_users.step, image_stepca (make_site_ca_request), lan_cidr and the DHCP
             subnets (site_networks: sent so the upstream can refuse networks that overlap another site's), hostname
             (sent so the upstream never gives this site's DC the host's own name, 2.1.6.51; the DC's name is the
             upstream's to give, 2.1.6.65);
             invitation — the
             invitation text (decode_invitation); password — this site's ca_password (encrypts its CA key);
             work_dir — where the site CA key, request and certificates are kept; domain — this site's own
             domain (DOMAIN_RE); address — this host's IP (host_ip); config_dir — the install's config folder
             for federation.yaml and its lock (default: next to this code — setup runs from the package, so it
             passes <base>/fabric/config); audit_path — default AUDIT_FILE; http_port, https_port — the
             upstream's ports (the relay's, when the invitation names one), default 80 and 443 (tests); replace — join
             although an upstream is recorded
             (re-parenting: the invitation's upstream becomes this site's parent), default False; dns_port —
             the port this site's DNS is published on (bind_dns_port), default 53: linked sites send zone
             transfers and notifies there.
    Returns: {"vars": settings for this install — byoc, ca_crt_path, ica_crt_path, ica_key_path, ica_parents_path,
             site_ca_depth (stage_site_ca), site_name, org_domain, ldap_base_dn and the organisation's
             friendly_name / cert_* —, "upstream": {"site_name",
             "domain", "host", "address"}, "joined": True if this call joined, False if an earlier run had,
             "dc_name": the name the upstream gave this site's DC (also when a re-run reads it from the registry;
             "" when the join named no DC), "dns_secret": the DNS link's TSIG secret from the upstream (only when this
             call joined; the caller
             keeps it in fabric's secrets as federation_tsig["upstream"], never in the registry), "domain": the domain
             this site's DC joins ({} when the invitation named none; manual 1.9.8.4: the caller keeps its passwords
             in fabric's secrets and its settings in the vars)}.
    Fails:   ValidationError from decode_invitation, make_site_ca_request, fetch_pinned_root, post_upstream ("the
             upstream refused: ..."), stage_site_ca; "this site's domain is not valid"; "the upstream answered
             with a different root"; "this node already joined <upstream>, not the invitation's ..."; an answer that
             prepares this site's DC without giving it a usable name (an upstream older than 0.8.0), before anything
             is staged or recorded here; OSError.
    Feeds:   setup step `join` (fabriclib/setup/join_federation.py).
    Notes:   idempotent: once joined (an upstream recorded and the staged files present) a re-run returns the
             same settings without contacting the upstream, so setup can be repeated after a later failure.
             Audited as FED_JOINED."""
    inv = decode_invitation(invitation)
    domain = str(domain).strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ValidationError(f"this site's domain is not valid: {domain!r}")
    staged_files = [os.path.join(work_dir, n) for n in ("root_ca.crt", "site_ca.crt", "site_ca_key", "ca_parents.crt")]
    reg_path = os.path.join(config_dir, "federation.yaml") if config_dir else FEDERATION_FILE
    lock_path = os.path.join(config_dir, ".federation.lock") if config_dir else FEDERATION_LOCK_FILE
    registry = load_registry(reg_path)
    if registry["upstream"] and not replace:
        up = registry["upstream"]
        if up.get("site_name") != inv["upstream"] or up.get("site") != inv["site"]:
            raise ValidationError(f"this node already joined {up.get('site_name')} as {up.get('site')}, "
                                  f"not the invitation's {inv['upstream']} as {inv['site']}")
        if all(os.path.exists(p) for p in staged_files):
            return {"vars": _vars(inv, up, work_dir), "upstream": {k: up.get(k) for k in
                                                                   ("site_name", "domain", "host", "address")},
                    "joined": False, "dc_name": up.get("dc_name") or ""}

    req = make_site_ca_request(v, inv["site"], password, work_dir)
    root = fetch_pinned_root(inv["address"], inv["root_sha256"], port=http_port)
    answer = post_upstream(inv["address"], inv["host"], root, "/v1/join",
                           {"id": inv["id"], "secret": inv["secret"], "site": inv["site"], "csr": req["csr"],
                            "domain": domain, "address": address, "federation_host": f"federation.{domain}",
                            "via": inv["via"], "dns_port": int(dns_port), "networks": site_networks(v),
                            "host_name": str(v.get("hostname") or "")},
                           port=https_port)
    if not isinstance(answer, dict) or answer.get("root", "").strip() != root.strip():
        raise ValidationError("the upstream answered with a different root")
    dom = answer.get("domain") or {}
    dc_name = str(dom.get("dc_name") or "").strip().lower()
    if dom and not dom.get("moved") and (not dc_name or dc_name_problem(dc_name, "", v.get("hostname") or "")):
        raise ValidationError("the upstream prepared this site's domain controller without giving it a name it can "
                              f"have ({dc_name or 'none'}): an upstream older than 0.8.0 does not name a joining "
                              "site's DC (2.1.6.65); upgrade the upstream, then invite this site again")
    staged = stage_site_ca(work_dir, answer.get("cert", ""), answer["root"], root_sha256=inv["root_sha256"],
                           chain=answer.get("chain") or "")
    org = answer.get("org") or {}
    up = {**(answer.get("upstream") or {}), "site": inv["site"],
          "org_domain": org.get("org_domain") or inv["org_domain"],
          "ldap_base_dn": org.get("ldap_base_dn") or inv["ldap_base_dn"],
          "root_sha256": inv["root_sha256"], "site_ca_depth": staged["site_ca_depth"],
          "joined": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
          "org": {k: org[k] for k in ORG_KEYS if org.get(k)},
          "dns_key": (answer.get("dns") or {}).get("key") or f"fed-{inv['site']}",
          "dns_port": int((answer.get("dns") or {}).get("port") or 53)}
    if dc_name and not dom.get("moved"):
        up["dc_name"] = dc_name                   # the upstream's name for this site's DC (2.1.6.65): kept for re-runs
    if https_port != 443 and not inv["via"]:
        up["port"] = https_port                   # the upstream's endpoint is not on 443 (tests)
    if inv["via"]:                                # joined through a relay: later traffic goes the same way
        up["relay"] = {"site": inv["via"], "host": inv["host"], "address": inv["address"], "port": https_port}
    with federation_lock(lock_path):
        registry = load_registry(reg_path)
        registry["upstream"] = up
        save_registry(registry, reg_path)
    write_audit("root", "FED_JOINED", f"upstream={up.get('site_name')} site={inv['site']} domain={domain}", "cli",
                path=audit_path or AUDIT_FILE)
    return {"vars": _vars(inv, up, work_dir), "upstream": {k: up.get(k) for k in ("site_name", "domain", "host",
                                                                                  "address")},
            "joined": True, "dns_secret": (answer.get("dns") or {}).get("secret"),
            "domain": dom, "dc_name": up.get("dc_name") or ""}


def _vars(inv, up, work_dir):
    """Purpose: the settings a joined site is rendered with, from the invitation and the recorded upstream.
    Inputs:  inv — decode_invitation's dict; up — the registry's upstream record; work_dir — the staged files.
    Returns: dict: byoc True, ca_crt_path, ica_crt_path, ica_key_path, ica_parents_path, site_ca_depth (CAs
             between the site's CA and the root), site_name, org_domain, ldap_base_dn
             and the organisation's settings (friendly_name, cert_*).
    Fails:   never.
    Feeds:   join_upstream (both the first join and a re-run)."""
    return {"byoc": True, "ca_crt_path": os.path.join(work_dir, "root_ca.crt"),
            "ica_crt_path": os.path.join(work_dir, "site_ca.crt"), "ica_key_path": os.path.join(work_dir,
                                                                                                "site_ca_key"),
            "ica_parents_path": os.path.join(work_dir,
                                             "ca_parents.crt"), "site_ca_depth": int(up.get("site_ca_depth") or 0),
            "site_name": inv["site"], "org_domain": up.get("org_domain") or inv["org_domain"],
            "ldap_base_dn": up.get("ldap_base_dn") or inv["ldap_base_dn"], **(up.get("org") or {})}
