import base64
import binascii
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.link_device_cert import link_device_cert
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.common.openssl import openssl
from fabriclib.pki.common.record_issued import record_issued
from fabriclib.pki.scep.common.challenge_lock import challenge_lock
from fabriclib.pki.scep.common.read_challenges import read_challenges
from fabriclib.pki.scep.common.write_challenges import write_challenges
from fabriclib.pki.scep.constants import CHALLENGES_FILE


def record_scep_issue(v, body, store=CHALLENGES_FILE, ledger=ISSUED_CERTS_FILE, link=link_device_cert):
    """Purpose: Step-CA's NOTIFYING call after it issued over SCEP (manual 1.5.3.4): record the certificate in the
             issued-certificate ledger as the person whose challenge it used, and link it to the device chosen, so
             it is listed, revocable and admitted by FreeRADIUS.
    Inputs:  v — settings (the directory, for the link); body — the webhook's JSON body: scepTransactionID and
             x509Certificate.raw (base64 DER); a failure notification (scepErrorCode, no certificate) is only
             audited; store — the challenge store; ledger — the issued-certificate ledger; link — the device link
             (link_device_cert; tests pass their own).
    Returns: {"recorded": bool, "serial", "id" (the challenge's, or "-")}. A link the directory refuses is kept in
             the challenge's record (link_error) and audited, never raised: the certificate exists either way.
    Fails:   ValidationError when the body holds no readable certificate; OSError from the ledger, store or audit.
    Feeds:   answer_hook (POST /hooks/scep/issued)."""
    transaction = str(body.get("scepTransactionID") or "")[:128]
    cert = body.get("x509Certificate") if isinstance(body.get("x509Certificate"), dict) else None
    if not cert:
        write_audit("step-ca", "SCEP_FAILED", f"transaction={transaction or '-'} code={body.get('scepErrorCode')}: "
                                              f"{str(body.get('scepErrorDescription') or '')[:200]}", "scep")
        return {"recorded": False, "serial": "", "id": "-"}
    try:
        der = base64.b64decode(str(cert.get("raw") or ""), validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError("the notification's certificate is not base64")
    if not der:
        raise ValidationError("the notification carries no certificate")
    pem = openssl("x509", "-inform", "DER", "-outform", "PEM", data=der).decode()
    info = describe_cert(pem)
    with challenge_lock(store):
        items = read_challenges(store)
        rec = next((c for c in items if transaction and c.get("transaction") == transaction
                    and c.get("outcome") == "allowed"), None)
        actor, device = (rec.get("by", "step-ca"), rec.get("device", "")) if rec else ("step-ca", "")
        link_error = ""
        if device:
            try:
                link(v, actor, device, info["sha256"], source="scep")
            except (ValidationError, subprocess.TimeoutExpired, OSError) as exc:   # the DC down, OpenBao locked
                link_error = str(exc) or type(exc).__name__
        if rec:
            rec.update({"serial": info["serial"], "link_error": link_error})
            write_challenges(store, items)
    record_issued(actor, "scep", dict(info, device="" if link_error else device), "scep", path=ledger)
    cid = rec.get("id", "-") if rec else "-"
    write_audit(actor, "SCEP_ISSUED", f"id={cid} subject={info['subject']} serial={info['serial']} "
                                      f"device={device or '-'}" + (f" link failed: {link_error}" if link_error else "")
                + ("" if rec else " (no challenge of fabric's matches this transaction)"), "scep")
    return {"recorded": True, "serial": info["serial"], "id": cid}
