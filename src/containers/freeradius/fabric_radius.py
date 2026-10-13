"""fabric's 802.1X policy, called by FreeRADIUS's python3 module
(mods/fabric_policy).

authorize() runs in three places:
  - fabric-check-eap-tls, after the client certificate chained to the
    fabric CA: the device linked to that certificate's fingerprint must be
    enabled and hold network:eap-tls;
  - fabric-inner-tunnel, inside EAP-TTLS: a person's user name and password
    (PAP), checked by binding to the site's DC; they must be in a group mapped for
    802.1X (radius_people);
  - the main server for anything that is not EAP: MAB, the switch asking
    for a MAC (User-Name = the MAC); the device with that MAC must be
    enabled and hold network:mab.
post_auth() runs in fabric-inner-tunnel once the domain accepted a PEAP
(EAP-MSCHAPv2) answer through ntlm_auth: the person, or the domain machine
of this site, must be in a group mapped for 802.1X (2.1.11.3).
accounting() logs every Accounting-Request as one `fabric: ACCT ...` line:
the sessions the console lists, and Disconnect / CoA act on (1.11.1.4).
The client that asked (its shortname, Tmp-String-3, set by the sites) picks
its vendor's rules from fabric-radius.json: how a MAB request looks, which
VLAN attributes to send (1.11.1.2). Over RadSec, a client certificate that
is not the client's own is refused first (Tmp-String-0
"fabric-radsec-refused", set by sites/radsec; 1.11.1.3).
Accepted: the role's VLAN as Tunnel-Private-Group-Id (none: the port's
default). Refused, or the directory cannot be asked: Access-Reject (fail
closed). Every decision is logged as one `fabric: ...` line (the auth log
`fabricctl radius log` and the web UI read).
"""
import os
import re
import urllib.parse

import radiusd

from check_mab import check_mab
from check_peap import check_peap
from check_person import check_person
from directory import load_config
from lookup_device import lookup_device
from lookup_reservation import lookup_reservation
from normalize_mac import normalize_mac
from vlan_reply import vlan_reply

FP_CACHE = "/run/freeradius/fp"


def _log(decision, method, **kv):
    """Purpose: log one decision as a single `fabric: …` line in FreeRADIUS's auth log (what
             `fabricctl radius log` and the web UI read).
    Inputs:  decision — "ACCEPT" or "REJECT"; method — "eap-tls", "eap-ttls" or "mab"; kv — key=value details
             (spaces in values become "_", empty values "-").
    Returns: None.
    Fails:   never in practice (radiusd.radlog).
    Feeds:   _decide, _decide_person, authorize."""
    radiusd.radlog(radiusd.L_AUTH, "fabric: %s method=%s %s" % (
        decision, method, " ".join("%s=%s" % (k, str(v).replace(" ", "_") or "-") for k, v in kv.items())))


def _client(req):
    """Purpose: the rules of the client (switch, access point) that sent the request, from fabric-radius.json.
    Inputs:  req — dict of request attributes; Tmp-String-3 holds the client's shortname (set by the sites).
    Returns: dict {"vendor", "transport", "mab", "vlan"}; the generic rules ({}) for a client not listed or when the
             file cannot be read (the decision itself then fails closed on its own).
    Fails:   never.
    Feeds:   authorize, post_auth."""
    try:
        return (load_config().get("clients") or {}).get(req.get("Tmp-String-3", "")) or {}
    except Exception:                   # unreadable config: the directory lookup refuses anyway
        return {}


def _decide(method, attribute, value, permission, where, style="rfc3580"):
    """Purpose: decide a device (EAP-TLS by certificate fingerprint, or MAB by MAC) and log it; fail closed.
    Inputs:  method — str for the log; attribute — "fabricCertFingerprint" or "macAddress"; value — str;
             permission — "network:eap-tls" or "network:mab"; where — dict of log details (mac, nas, …);
             style — the client's VLAN attribute style (vlan_reply).
    Returns: radiusd.RLM_MODULE_REJECT, or (RLM_MODULE_OK, VLAN reply attributes, (("Auth-Type", ":=",
             "Accept"),)).
    Fails:   never raises — any exception from lookup_device or lookup_reservation (directory down, bad data)
             becomes a logged reject.
    Feeds:   authorize.
    Notes:   MAB of a MAC no device has falls back to the site's DHCP reservations (lookup_reservation, manual
             1.11.1.7), logged source=reservation; a MAC a device has is decided by the device alone."""
    source = {}
    try:
        found = lookup_device(attribute, value, permission)
        if method == "mab" and found["device"] is None and found["reason"] == "no device has it":
            by_reservation = lookup_reservation(value)
            if by_reservation["device"] is not None or by_reservation["reason"] != "no device has it":
                found, source = by_reservation, {"source": "reservation"}
    except Exception as exc:          # directory down, bind refused: never let a device in
        _log("REJECT", method, reason="directory_error:" + type(exc).__name__, **where)
        return radiusd.RLM_MODULE_REJECT
    if not found["allowed"]:
        _log("REJECT", method, device=found["device"] or "-", reason=found["reason"], **source, **where)
        return radiusd.RLM_MODULE_REJECT
    _log("ACCEPT", method, device=found["device"], vlan=found["vlan"] or "-", **source, **where)
    return radiusd.RLM_MODULE_OK, vlan_reply(found["vlan"], style), (("Auth-Type", ":=", "Accept"),)


def _decide_person(uid, password, where, style="rfc3580"):
    """Purpose: decide a person joining by user name and password (EAP-TTLS) and log it; fail closed.
    Inputs:  uid — str user name; password — str; where — dict of log details; style — the client's VLAN attribute
             style (vlan_reply).
    Returns: radiusd.RLM_MODULE_REJECT, or (RLM_MODULE_OK, VLAN reply attributes, Auth-Type := Accept).
    Fails:   never raises — any exception from check_person becomes a logged reject.
    Feeds:   authorize."""
    try:
        found = check_person(uid, password)
    except Exception as exc:          # directory down: never let anyone in
        _log("REJECT", "eap-ttls", person=uid, reason="directory_error:" + type(exc).__name__, **where)
        return radiusd.RLM_MODULE_REJECT
    if not found["allowed"]:
        _log("REJECT", "eap-ttls", person=found["person"], reason=found["reason"], **where)
        return radiusd.RLM_MODULE_REJECT
    _log("ACCEPT", "eap-ttls", person=found["person"], group=found["group"], vlan=found["vlan"] or "-", **where)
    return radiusd.RLM_MODULE_OK, vlan_reply(found["vlan"], style), (("Auth-Type", ":=", "Accept"),)


def _decide_peap(name, where, style="rfc3580"):
    """Purpose: decide an account the domain accepted over PEAP (a person, or a machine of this site) and log it;
             fail closed.
    Inputs:  name — str, the account's sAMAccountName (a machine's ends in "$"); where — dict of log details;
             style — the client's VLAN attribute style (vlan_reply).
    Returns: radiusd.RLM_MODULE_REJECT, or (RLM_MODULE_OK, VLAN reply attributes, ()).
    Fails:   never raises — any exception from check_peap becomes a logged reject.
    Feeds:   post_auth."""
    who = "machine" if name.endswith("$") else "person"
    try:
        found = check_peap(name)
    except Exception as exc:          # directory down: never let anyone in
        _log("REJECT", "peap", reason="directory_error:" + type(exc).__name__, **{who: name or "-"}, **where)
        return radiusd.RLM_MODULE_REJECT
    if not found["allowed"]:
        _log("REJECT", "peap", reason=found["reason"], **{who: found["account"]}, **where)
        return radiusd.RLM_MODULE_REJECT
    _log("ACCEPT", "peap", group=found["group"], vlan=found["vlan"] or "-", **{who: found["account"]}, **where)
    return radiusd.RLM_MODULE_OK, vlan_reply(found["vlan"], style), ()


def instantiate(p):
    """Purpose: FreeRADIUS python3 module start hook (func_instantiate in mods/fabric_policy); nothing to set up.
    Inputs:  p — the configuration pairs FreeRADIUS passes (unused).
    Returns: radiusd.RLM_MODULE_OK.
    Fails:   never.
    Feeds:   FreeRADIUS (mods/fabric_policy)."""
    return radiusd.RLM_MODULE_OK


def _where(req):
    """Purpose: the log details every decision carries: the calling MAC, the NAS as it names itself, and the client
             (its shortname in clients.conf).
    Inputs:  req — dict of request attributes.
    Returns: dict {"mac", "nas", "client"}.
    Fails:   never.
    Feeds:   authorize, post_auth."""
    return {"mac": normalize_mac(req.get("Calling-Station-Id")) or req.get("Calling-Station-Id", "-"),
            "nas": req.get("NAS-Identifier") or req.get("NAS-IP-Address") or "-",
            "client": req.get("Tmp-String-3") or "-"}


def _pairs(p):
    """Purpose: FreeRADIUS's request pairs as a dict, the first value of each attribute.
    Inputs:  p — tuple of (attribute, value) pairs, or None.
    Returns: dict {attribute: str}.
    Fails:   never.
    Feeds:   authorize, post_auth, accounting."""
    req = {}
    for attr, value in p or ():
        req.setdefault(attr, str(value))
    return req


def authorize(p):
    """Purpose: FreeRADIUS authorize hook: route the request to the right decision — a RadSec connection whose client
             certificate is not the client's own (Tmp-String-0 "fabric-radsec-refused", set by sites/radsec), a person
             inside EAP-TTLS (Tmp-String-0 "fabric-people", set by sites/inner-tunnel), a device after EAP-TLS (by
             the fingerprint record_fingerprint stored under the certificate serial), EAP still in progress (no-op),
             or MAB, read the way the client's vendor sends it (check_mab).
    Inputs:  p — tuple of (attribute, value) request pairs from FreeRADIUS (the first value of each attribute is
             used); Tmp-String-3 names the client. Reads /run/freeradius/fp/<serial> and fabric-radius.json.
    Returns: radiusd.RLM_MODULE_REJECT, RLM_MODULE_NOOP (EAP in progress), or (RLM_MODULE_OK, reply attributes,
             config attributes) from _decide / _decide_person.
    Fails:   never raises for a missing fingerprint or a directory error (logged reject); an exception here
             would make FreeRADIUS fail the module, which also rejects.
    Feeds:   FreeRADIUS (func_authorize in mods/fabric_policy; called from sites fabric, radsec, check-eap-tls,
             inner-tunnel)."""
    req = _pairs(p)
    where = _where(req)
    client = _client(req)
    style = client.get("vlan", "rfc3580")

    if req.get("Tmp-String-0") == "fabric-radsec-refused":       # sites/radsec: not this client's certificate
        _log("REJECT", "radsec", reason="certificate_not_this_client",
             cn=req.get("TLS-Client-Cert-Common-Name", "-"), **where)
        return radiusd.RLM_MODULE_REJECT

    if req.get("Tmp-String-0") == "fabric-people":               # fabric-inner-tunnel (EAP-TTLS)
        return _decide_person(req.get("User-Name", ""), req.get("User-Password", ""), where, style)

    serial = req.get("TLS-Client-Cert-Serial")
    if serial is not None:                                   # fabric-check-eap-tls
        serial = re.sub(r"[^0-9a-f]", "", serial.lower())
        while len(serial) > 2 and serial.startswith("00"):     # as record_fingerprint keys it
            serial = serial[2:]
        try:
            with open(os.path.join(FP_CACHE, serial)) as f:
                fp = f.read().strip()
        except OSError:
            _log("REJECT", "eap-tls", reason="certificate_not_recorded", serial=serial, **where)
            return radiusd.RLM_MODULE_REJECT
        return _decide("eap-tls", "fabricCertFingerprint", fp, "network:eap-tls", dict(where, sha256=fp), style)

    if "EAP-Message" in req:                                 # EAP in progress: the eap module's
        return radiusd.RLM_MODULE_NOOP

    # MAB: the switch sends the client's MAC as User-Name, in its vendor's shape (manual 1.11.1.2); anything else
    # is not a request fabric grants.
    mac, reason = check_mab(req, client.get("mab"))
    if not mac:
        _log("REJECT", "mab", reason=reason, user=req.get("User-Name", "-"), **where)
        return radiusd.RLM_MODULE_REJECT
    return _decide("mab", "macAddress", mac, "network:mab", dict(where, mac=mac), style)


def post_auth(p):
    """Purpose: FreeRADIUS post-auth hook: in fabric-inner-tunnel, once the domain accepted a PEAP answer
             (Tmp-String-0 "fabric-peap", the account in Tmp-String-1 as mschap names it), decide it; anywhere else
             nothing to do.
    Inputs:  p — tuple of (attribute, value) request pairs from FreeRADIUS.
    Returns: radiusd.RLM_MODULE_NOOP, radiusd.RLM_MODULE_REJECT, or (RLM_MODULE_OK, reply attributes, ()).
    Fails:   never raises for a directory error (logged reject).
    Feeds:   FreeRADIUS (func_post_auth in mods/fabric_policy; called from sites/inner-tunnel)."""
    req = _pairs(p)
    if req.get("Tmp-String-0") != "fabric-peap":
        return radiusd.RLM_MODULE_NOOP
    return _decide_peap(req.get("Tmp-String-1", ""), _where(req), _client(req).get("vlan", "rfc3580"))


ACCT_FIELDS = (("status", "Acct-Status-Type"), ("session", "Acct-Session-Id"), ("nas_ip", "NAS-IP-Address"),
               ("port", "NAS-Port-Id"), ("user", "User-Name"), ("ip", "Framed-IP-Address"))


def accounting(p):
    """Purpose: FreeRADIUS accounting hook: log the Accounting-Request as one `fabric: ACCT ...` line, the sessions
             the console lists and Disconnect / CoA name (manual 1.11.1.4). Nothing is stored anywhere else.
    Inputs:  p — tuple of (attribute, value) request pairs: Acct-Status-Type, Acct-Session-Id, Calling-Station-Id,
             NAS-IP-Address, NAS-Port-Id, User-Name, Framed-IP-Address; Tmp-String-3 names the client.
    Returns: radiusd.RLM_MODULE_OK (accounting is always acknowledged).
    Fails:   never raises: a value that cannot be logged is left out.
    Feeds:   FreeRADIUS (func_accounting in mods/fabric_policy; called from sites fabric and radsec); read by
             fabriclib/radius/list_radius_sessions."""
    req = _pairs(p)
    kv = [("client", req.get("Tmp-String-3") or "-"),
          ("mac", normalize_mac(req.get("Calling-Station-Id")) or req.get("Calling-Station-Id") or "-")]
    kv += [(key, req.get(attr) or "-") for key, attr in ACCT_FIELDS]
    radiusd.radlog(radiusd.L_AUTH, "fabric: ACCT " + " ".join(
        "%s=%s" % (k, urllib.parse.quote(str(v), safe="-_.:@")) for k, v in kv))
    return radiusd.RLM_MODULE_OK
