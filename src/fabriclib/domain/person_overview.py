import re

from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.directory.list_devices import list_devices
from fabriclib.directory.list_people import list_people
from fabriclib.domain.show_person import show_person
from fabriclib.pki.list_issued import list_issued

# what a person's page shows of a certificate and of a device: nothing a person could not read on the thing itself
CERT_FIELDS = ("subject", "serial", "not_after", "status", "kind")
DEVICE_FIELDS = ("name", "type", "enabled", "macs", "roles", "vlan")


def person_overview(v, uid, secrets=None, container="samba", ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE):
    """Purpose: one person as their page shows them (manual 1.6.12.4) and My account (1.8.6.6): their details as the
             DC has them (AD's standard attributes, 2.1.6.93), their state and last sign-in, the groups and sites
             they are in, the certificates fabric issued to them (by the subject's CN) and the 802.1X devices they
             own.
    Inputs:  v — rendered vars; uid — the user name; secrets — fabric's secrets (default: load_secrets(), through
             show_person and list_people); container — the DC's container; ledger, revoked — the issued-certificate
             ledger and the revocations (tests).
    Returns: {"uid", "person": {field: value}, "groups": [names], "state" ("active", "disabled", "locked"),
             "last_logon" (ISO or ""), "sites": [names], "certs": [{subject, serial, not_after, status, kind}] newest
             first, "devices": [{name, type, enabled, macs, roles, vlan}]}.
    Fails:   ValidationError from show_person (no such person in OU=people, the DC not reachable) or list_devices;
             OSError reading the ledger.
    Feeds:   my_account; agent route GET /v1/people/<uid> (people:read)."""
    me = show_person(v, uid, secrets, container)
    row = next((u for u in list_people(v, secrets).get("users") or [] if u.get("uid") == uid), {})
    cn = re.compile(rf"(^|,)\s*CN={re.escape(uid)}(,|$)")
    certs = [{k: e.get(k) for k in CERT_FIELDS} for e in list_issued(limit=1000, path=ledger, revoked=revoked)
             if cn.search(e.get("subject") or "")]
    devices = [{k: d.get(k) for k in DEVICE_FIELDS} for d in list_devices(v) if d.get("owner") == uid]
    return {"uid": uid, "person": me.get("person") or {}, "groups": me.get("groups") or [],
            "state": row.get("state") or ("disabled" if row.get("locked") else "active"),
            "last_logon": row.get("last_logon") or "", "sites": row.get("sites") or [], "certs": certs,
            "devices": devices}
