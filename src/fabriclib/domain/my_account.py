import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.directory.list_devices import list_devices
from fabriclib.domain.show_person import show_person
from fabriclib.pki.list_issued import list_issued

# what My account shows of a certificate and of a device: nothing a person could not read on the thing itself
CERT_FIELDS = ("subject", "serial", "not_after", "status", "kind")
DEVICE_FIELDS = ("name", "type", "enabled", "macs", "roles", "vlan")


def my_account(v, user, secrets=None, container="samba", ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE):
    """Purpose: My account (manual 1.8.6.6), read-only: the signed-in person's own details as the DC has them (AD's
             standard attributes, 2.1.6.93), the groups they are in, the certificates fabric issued to them and the
             802.1X devices they own. Only theirs: the person is the token's user, never a name from the caller.
    Inputs:  v — rendered vars; user — the signed-in person's user name (None: root, who is no person); secrets —
             fabric's secrets (default: load_secrets(), through show_person); container — the DC's container; ledger,
             revoked — the issued-certificate ledger and the revocations (tests).
    Returns: {"uid", "person": {field: value}, "groups": [names], "certs": [{subject, serial, not_after, status,
             kind}] newest first, "devices": [{name, type, enabled, macs, roles, vlan}]}.
    Fails:   ValidationError "a person's own account: sign in as them" for root; show_person's (the DC not running,
             no such person: a service account) and list_devices' errors; OSError reading the ledger.
    Feeds:   agent route GET /v1/account (any signed-in person, their own)."""
    if not user:
        raise ValidationError("a person's own account: sign in as them")
    me = show_person(v, user, secrets, container)
    cn = re.compile(rf"(^|,)\s*CN={re.escape(user)}(,|$)")
    certs = [{k: e.get(k) for k in CERT_FIELDS} for e in list_issued(limit=1000, path=ledger, revoked=revoked)
             if cn.search(e.get("subject") or "")]
    devices = [{k: d.get(k) for k in DEVICE_FIELDS} for d in list_devices(v) if d.get("owner") == user]
    return {"uid": user, "person": me.get("person") or {}, "groups": me.get("groups") or [], "certs": certs,
            "devices": devices}
