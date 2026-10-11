import base64
import datetime
import os
import hashlib
import hmac
import ipaddress
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.federation.common.federation_lock import federation_lock
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.common.save_registry import save_registry
from fabriclib.federation.common.signing_capacity import signing_capacity
from fabriclib.federation.constants import DOMAIN_RE, SITE_NAME_RE
from fabriclib.federation.network_conflicts import network_conflicts
from fabriclib.federation.next_id_block import next_id_block
from fabriclib.federation.read_address_plan import read_address_plan
from fabriclib.federation.site_networks import site_networks
from fabriclib.pki.sign_site_ca import sign_site_ca
from fabriclib.samba.dc_name_problem import dc_name_problem
from fabriclib.samba.domain_dc_names import domain_dc_names
from fabriclib.samba.domain_sites import domain_sites
from fabriclib.samba.prepare_site import prepare_site
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.random_password import random_password
from fabriclib.secrets.save_secrets import save_secrets

_ORG_KEYS = ("friendly_name", "cert_country", "cert_province", "cert_city", "cert_org", "cert_ou")
REFUSED = "the invitation is not valid (unknown, used, withdrawn or expired)"


def _port(value):
    """Purpose: a DNS port a joining site reported, or 53.
    Inputs:  value — anything from the request.
    Returns: int 1..65535 (53 when absent or invalid).
    Fails:   never.
    Feeds:   accept_join (the site record's dns_port)."""
    return int(value) if str(value).isdigit() and 0 < int(value) < 65536 else 53


def _check_networks(v, site, networks):
    """Purpose: refuse a joining site whose networks overlap another site's (manual 1.10.2.6): the
             upstream's copy of the address plan, plus its own networks (the plan may not list them yet).
    Inputs:  v — the upstream's vars; site — the joining site's name; networks — what the request reported
             ([{name, cidr, allow_overlap}]; an older fabric sends none).
    Returns: None.
    Fails:   ValidationError "the site's networks …" for a malformed list, or naming each overlap without an
             allow_overlap reason.
    Feeds:   accept_join."""
    if not isinstance(networks, list) or len(networks) > 256:
        raise ValidationError("the site's networks are not a list")
    mine = []
    for n in networks:
        try:
            cidr = str(ipaddress.ip_network(str(n["cidr"]), strict=False))
        except (KeyError, TypeError, ValueError):
            raise ValidationError("the site's networks are not valid") from None
        mine.append({"name": str(n.get("name") or cidr)[:64], "cidr": cidr,
                     "allow_overlap": str(n.get("allow_overlap") or "")[:200]})
    try:
        plan = read_address_plan(v)
    except (ValidationError, RuntimeError):      # the DC not answering: at least this site's own networks
        plan = []
    plan += [{**n, "site": v.get("site_name")} for n in site_networks(v)]
    bad = [c for c in network_conflicts(mine, plan, site) if not c["allowed"]]
    if bad:
        raise ValidationError("; ".join(f"{c['cidr']} overlaps {c['other_cidr']} of site {c['other_site']}"
                                        for c in bad) + ": give the joining site other networks")


def accept_join(v, req, client_ip="", now=None):
    """Purpose: On the upstream: let an invited site join (manual 1.9.4.1 step 3): check the one-time
             invitation, sign the site's intermediate CA with the root key, record the site and use up the
             invitation.
    Inputs:  v — fabric vars: domain, org_domain (default domain), ldap_base_dn, site_name, host_ip,
             hostname_federation and the organisation settings (friendly_name, cert_*), plus what sign_site_ca
             reads; req — the join request {"id", "secret", "site", "csr", "domain" (the site's own domain),
             "address" (its IP), optional "networks" (its LAN and DHCP subnets: refused when they overlap another
             site's, _check_networks) and "dc_name" (its DC's own name: refused when the domain has a computer of
             that name, _prepare_domain)};
             client_ip — str for the audit; now — epoch seconds, default time.time().
    Returns: {"root": PEM, "cert": PEM of the site's intermediate (path length: the invitation's nest), "chain":
             PEM of the CAs between it and the root ("" when this is the root site; this site's CA and its
             parents when this is a site and the new one is nested under it), "dns": {"key": "fed-<site>",
             "algorithm", "secret", "port"} — the TSIG key both sites sign zone transfers with (port: this
             site's published DNS port) (kept here in fabric's
             secrets as federation_tsig[site]; manual 1.9 M4), "org": {"org_domain", "ldap_base_dn",
             friendly_name, cert_*}, "upstream": {"site_name", "domain", "host", "address"}} and, for an invitation
             that names a DC type (made on the root), "domain": {"ad_domain", "dc_type", "dc_host", "dc_address",
             "id_range", "join_user", "join_password", "accounts" {agent, keycloak, radius}, "site_ou", "org_ou"}
             (_prepare_domain).
    Fails:   ValidationError "the join request is incomplete"; overlapping networks (_check_networks, before
             anything is signed or recorded); "the site's domain/address is not valid" or
             "a site cannot use this site's domain"; REFUSED for an unknown, expired or wrong secret (one message,
             so a caller learns nothing about which); "the invitation was made for site <x>"; "site <x> has
             joined already"; sign_site_ca's messages (the invitation is kept, so a corrected request can
             retry); ValidationError from load_secrets/save_secrets; OSError.
    Feeds:   the federation endpoint (src/federation/server.py, POST /v1/join).
    Notes:   the secret is compared by its SHA-256 in constant time; audited as FED_JOIN (actor "site:<name>",
             with the client address) and, on refusal, FED_JOIN_REFUSED."""
    now = int(now if now is not None else time.time())
    if not isinstance(req, dict) or not all(isinstance(req.get(k), str) and req.get(k)
                                            for k in ("id", "secret", "site", "csr", "domain", "address")):
        raise ValidationError("the join request is incomplete")
    site, domain = req["site"].strip().lower(), req["domain"].strip().lower().rstrip(".")
    fed_host = str(req.get("federation_host") or "").strip().lower()
    if not SITE_NAME_RE.match(site) or not DOMAIN_RE.match(domain):
        raise ValidationError("the site's name or domain is not valid")
    if domain == v["domain"]:
        raise ValidationError("a site cannot use this site's domain")
    try:
        ipaddress.ip_address(req["address"])
    except ValueError:
        raise ValidationError("the site's address is not valid") from None
    with federation_lock():
        invites = load_secrets(v=v).get("federation_invitations") or {}
        entry = invites.get(req["id"]) or {}
        digest = hashlib.sha256(req["secret"].encode()).hexdigest()
        if not (entry and entry.get("expires", 0) > now and hmac.compare_digest(entry.get("sha256", ""), digest)):
            write_audit(f"site:{site}", "FED_JOIN_REFUSED", f"id={req['id'][:16]} from={client_ip}", "federation")
            raise ValidationError(REFUSED)
        if entry.get("site") != site:
            raise ValidationError(f"the invitation was made for site {entry.get('site')}")
        registry = load_registry()
        if site in registry["sites"]:
            raise ValidationError(f"site {site} has joined already")
        _check_networks(v, site, req.get("networks") or [])     # invitation verified first: no probing the plan
        domain_answer = _prepare_domain(v, site, entry.get("dc") or "", req.get("networks") or [], registry,
                                        str(req.get("dc_name") or ""))
        cap = signing_capacity(v)
        signed = sign_site_ca(v, f"site:{site}", site, req["csr"], source="federation",
                              nest=int(entry.get("nest") or 0), as_parent=cap["as_parent"])
        tsig = base64.b64encode(os.urandom(32)).decode()       # the DNS link to this site (zone transfers)
        stored = load_secrets(v=v)
        save_secrets({"federation_invitations": {i: e for i, e in invites.items() if i != req["id"]},
                      "federation_tsig": dict(stored.get("federation_tsig") or {}, **{site: tsig})},
                     v=v)
        registry["sites"][site] = {
            "domain": domain, "address": req["address"],
            "joined": datetime.datetime.fromtimestamp(now).astimezone().isoformat(timespec="seconds"),
            "ca_serial": signed["info"]["serial"], "ca_not_after": signed["info"]["not_after"],
            "invited_by": entry.get("actor", ""), "parent": v.get("site_name"), "nest": int(entry.get("nest") or 0),
            "via": entry.get("via") or "", "dns_port": _port(req.get("dns_port")),
            "federation_host": fed_host if DOMAIN_RE.match(fed_host) else f"federation.{domain}"}
        if domain_answer:
            registry["sites"][site].update({"dc": domain_answer["dc_type"], "id_range": domain_answer["id_range"]})
        save_registry(registry)
    write_audit(f"site:{site}", "FED_JOIN", f"site={site} domain={domain} address={req['address']} "
                                            f"from={client_ip} ca_serial={signed['info']['serial']}", "federation")
    org = {"org_domain": v.get("org_domain") or v["domain"], "ldap_base_dn": v["ldap_base_dn"],
           **{k: v.get(k) for k in _ORG_KEYS if v.get(k)}}
    return {"root": signed["root"], "cert": signed["cert"], "chain": signed["chain"], "org": org,
            "dns": {"key": f"fed-{site}", "algorithm": "hmac-sha256", "secret": tsig,
                    "port": int(v.get("bind_dns_port") or 53)},
            "upstream": {"site_name": v.get("site_name"), "domain": v["domain"], "host": v["hostname_federation"],
                         "address": v["host_ip"]},
            **({"domain": domain_answer} if domain_answer else {})}

def _prepare_domain(v, site, dc_type, networks, registry, dc_name=""):
    """Purpose: at the parent (the root, or a site with a writable DC), the domain part of a join (manual 1.9.8.4,
             S8.1, 1.9.8.14): converge the new site in the domain, in this site's OU,
             (prepare_site) with fresh service-account passwords and the next id block, and a temporary join account.
    Inputs:  v — this site's vars (ad_domain, hostname_dc, host_ip and what prepare_site reads); site — the new site;
             dc_type — the invitation's ("writable", "rodc"; "" for none: nothing is prepared); networks — the join
             request's; registry — load_registry()'s dict (the blocks handed out so far); dc_name — the joining
             site's DC's own name (2.1.6.45; "" from a fabric before 0.7.0: not checked).
    Returns: {"ad_domain", "dc_type", "dc_host", "dc_address", "id_range", "join_user", "join_password",
             "accounts" {agent, keycloak, radius}, "site_ou" (its OU in this site's, 2.1.6.20), "org_ou"}; for a site
             already in the domain (moving here) {"ad_domain", "dc_type", "id_range" (its own), "moved": True,
             "site_ou", "org_ou"} (its OU moved, no join account, its service accounts keep their passwords); {}
             without a DC type.
    Fails:   ValidationError for a DC name that is not valid, or that a computer of the domain already has (naming
             the domain's DCs: two DCs cannot share a name, and a DC cannot be renamed, manual 1.6.5.23); from
             domain_dc_names or prepare_site (the root's DC not running or refusing): the invitation is kept.
    Feeds:   accept_join."""
    if not dc_type:
        return {}
    held = {s["site"]: s for s in domain_sites()}
    accounts = {kind: random_password() for kind in ("agent", "keycloak", "radius")}
    if site in held:        # a site of the domain moving here (re-parenting, 2.1.6.20): its OU moves, its DC stays
        block = held[site]["id_range"] or next_id_block(v, registry, sites=list(held.values()))
        prepare_site(v, site, networks, block, {}, None)
        site_ou = v.get("ad_site_ou") or f"OU={v['site_name']},OU=sites"
        return {"ad_domain": v["ad_domain"], "dc_type": dc_type, "id_range": block, "moved": True,
                "site_ou": f"OU={site},{site_ou}", "org_ou": v.get("ad_org_ou") or f"OU=organisation,{site_ou}"}
    if dc_name:                 # checked before anything is prepared: the join would fail at the DC, half done
        problem = dc_name_problem(dc_name)
        if problem:
            raise ValidationError(f"the site's DC name {problem}")
        names = domain_dc_names()
        if dc_name.lower() in names["computers"]:
            raise ValidationError(f"the DC name {dc_name.lower()} is taken in {v['ad_domain']} (its domain "
                                  f"controllers: {', '.join(names['dcs']) or 'none'}): give the joining site's DC "
                                  "another name (dc_name)")
    join_password = random_password()
    block = next_id_block(v, registry, sites=list(held.values()))
    prepare_site(v, site, networks, block, accounts, join_password)
    site_ou = v.get("ad_site_ou") or f"OU={v['site_name']},OU=sites"     # this site's: the new one nests in it
    return {"ad_domain": v["ad_domain"], "dc_type": dc_type, "dc_host": v["hostname_dc"], "dc_address": v["host_ip"],
            "id_range": block, "join_user": f"fabric-join-{site}", "join_password": join_password,
            "accounts": accounts, "site_ou": f"OU={site},{site_ou}",
            "org_ou": v.get("ad_org_ou") or f"OU=organisation,{site_ou}"}
