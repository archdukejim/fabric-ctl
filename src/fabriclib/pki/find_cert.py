import datetime
import os
import re
import subprocess
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.pki.common.ca_files import ca_files
from fabriclib.pki.common.cert_status import parse_cert_date
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.common.revoked_serials import norm_serial
from fabriclib.pki.common.to_pem import to_pem

SERIAL_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:?){1,20}$|^[0-9A-Fa-f]{1,40}$")


def _ca_serials(v):
    """Purpose: the serials of this install's root and intermediate CA certificates: never revoked from the console.
    Inputs:  v — settings (deploy_base_dir).
    Returns: set of normalised serials (empty when the CA files cannot be read).
    Fails:   never.
    Feeds:   find_cert."""
    out = set()
    for path in ca_files(v):
        try:
            with open(path) as f:
                out.add(norm_serial(describe_cert(to_pem(f.read(), "cert")[0])["serial"]))
        except (OSError, ValidationError, IndexError):
            continue
    return out


def _signed_here(v, pem):
    """Purpose: whether this install's CA signed a certificate: it chains to the root through the intermediate (a
             leaf) or to the root itself (a site CA it signed); its dates are not checked, an expired one is still
             this CA's.
    Inputs:  v — settings (the CA files); pem — one PEM certificate.
    Returns: bool.
    Fails:   never (an unreadable CA reads as "not signed here"); FileNotFoundError only without openssl.
    Feeds:   find_cert."""
    root, intermediate = ca_files(v)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
    try:
        return subprocess.run(["openssl", "verify", "-no_check_time", "-CAfile", root, "-untrusted", intermediate,
                               f.name], capture_output=True).returncode == 0
    finally:
        os.unlink(f.name)


def find_cert(v, certs, serial="", pem=""):
    """Purpose: the certificate a revocation names, by its serial or by the certificate itself (manual 1.5.1.9.2),
             with the refusals of 1.5.1.9.6: what this install's CA did not sign, what is not a certificate, the CA's
             own certificates.
    Inputs:  v — settings (the CA files); certs — list_certs' result ({"certs", "stepca_error"}); serial — hex,
             colons allowed; pem — a PEM (or base64 DER) certificate. Exactly one of serial and pem.
    Returns: the list's row for it; for a certificate given as a file that this CA signed but no list holds (signed
             offline, or expired from Step-CA's database), a row made from the file (source "file").
    Fails:   ValidationError, saying why: neither or both given; a serial that is not hex; a file that is not a
             certificate; one this install's CA did not sign; the root's or the intermediate's own certificate; a
             serial no list holds (with why Step-CA's database could not be read, when it could not).
    Feeds:   agent route POST /v1/pki/lookup (the confirmation before Revoke), pki/revoke_cert."""
    serial, pem = str(serial or "").strip(), pem or ""
    if bool(serial) == bool(str(pem).strip()):
        raise ValidationError("give the certificate's serial or the certificate itself")
    info = None
    if pem:
        try:
            blocks = to_pem(pem, "cert")
        except ValidationError:
            raise ValidationError("that is not a certificate: give a PEM or DER certificate, or its serial")
        if not blocks:
            raise ValidationError("that is not a certificate: give a PEM or DER certificate, or its serial")
        info = describe_cert(blocks[0])
        serial = info["serial"]
    elif not SERIAL_RE.match(serial):
        raise ValidationError(f"{serial!r} is not a serial: hexadecimal digits, colons allowed")
    want = norm_serial(serial)
    if want in _ca_serials(v):
        raise ValidationError("that is this install's own CA certificate: the root and the intermediate are not "
                              "revoked from the console (a site CA this install signed is, from Issued)")
    if info is not None and not _signed_here(v, blocks[0]):
        raise ValidationError("this install's CA did not sign that certificate: only the CA that signed a "
                              "certificate can revoke it")
    row = next((c for c in certs.get("certs") or [] if c["serial"] == want), None)
    if row is not None:
        return row
    if info is None:
        why = (f" (Step-CA's own database could not be read: {certs['stepca_error']})"
               if certs.get("stepca_error") else "")
        raise ValidationError(f"this install's CA signed no certificate with the serial {want} that is still "
                              f"valid{why}: give the certificate itself to revoke one no list shows")
    expired = parse_cert_date(info["not_after"]) < datetime.datetime.now(datetime.timezone.utc)
    return {"serial": want, "subject": info["subject"], "cn": next(
        (p.strip()[3:] for p in info["subject"].split(",") if p.strip().upper().startswith("CN=")), ""),
        "sans": info["sans"], "not_after": info["not_after"], "status": "expired" if expired else "valid",
        "source": "file", "revocable": True, "is_ca": info["is_ca"], "kind": "site-ca" if info["is_ca"] else "leaf",
        "issuer_dn": info["issuer"]}
