import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.person_guard import person_guard
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.sign_out_person import sign_out_person
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.revoke_cert import revoke_cert
from fabriclib.secrets.load_secrets import load_secrets


def _their_certs(uid, ledger, revoked):
    """Purpose: the serials of a person's certificates still in force: issued by fabric to their name (the subject's
             CN), neither expired nor revoked.
    Inputs:  uid — the user name; ledger, revoked — the issued-certificate ledger and the revocations.
    Returns: list of str serials.
    Fails:   OSError reading the ledger.
    Feeds:   remove_person."""
    cn = re.compile(rf"(^|,)CN={re.escape(uid)}(,|$)")
    return [str(e["serial"]) for e in list_issued(limit=1000000, path=ledger, revoked=revoked)
            if cn.search(e.get("subject") or "") and e.get("status") not in ("expired", "revoked") and e.get("serial")]


def remove_person(v, actor, uid, confirm, privileged=False, source="web", secrets=None, container="samba",
                  ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE):
    """Purpose: remove a person of this site (manual 1.6.3.16): their sessions end, their directory account (and its
             group memberships) and Keycloak's copy are removed, and the certificates fabric issued to them are
             revoked (published in the CRL at once, 2.1.5.10). Their uid number is never given out again.
    Inputs:  v — fabric vars (site_name, deploy_base_dir, fabric_groups', keycloak_admin's);
             actor — str, for the audit and the self check; uid — the user name; confirm — the user name typed back;
             privileged — bool: root, or system:admin (a fabric-group member needs it); source — audit source;
             secrets — fabric's secrets (default: load_secrets()); container — the DC's container; ledger, revoked —
             for tests.
    Returns: {"uid", "revoked": [serials]}.
    Fails:   ValidationError "type the user name to confirm"; person_guard's refusals (no such person; a fabric-group
             member without privileged; yourself; the last admin who can sign in); run_op's ("no such entry":
             another site's person); "Keycloak refused: …"; revoke_cert's (CalledProcessError publishing the CRL;
             the account is removed by then); load_secrets' errors.
    Feeds:   agent route POST /v1/people/<uid>/delete (people:remove); directory/run_people_command.
    Notes:   audited as PERSON_REMOVE, each revocation as PKI_REVOKE."""
    if (confirm or "").strip() != uid:
        raise ValidationError("type the user name to confirm")
    secrets = secrets if secrets is not None else load_secrets()
    person_guard(v, secrets, uid, privileged, "remove them", actor=actor, last_admin=True, container=container)
    sign_out_person(v, secrets, uid)
    run_op(v, secrets, "remove_person", {"uid": uid}, container)
    sign_out_person(v, secrets, uid, delete=True)
    serials = _their_certs(uid, ledger, revoked)
    for i, serial in enumerate(serials):        # the CRLs are published once, with the last
        revoke_cert(v, actor, serial, "cessationOfOperation", source=source, ledger=ledger, revoked=revoked,
                    publish=i == len(serials) - 1)
    write_audit(actor, "PERSON_REMOVE", f"user={uid} certificates revoked={len(serials)}", source)
    return {"uid": uid, "revoked": serials}
