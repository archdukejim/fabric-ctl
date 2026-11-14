import datetime
import json
import os

from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.pki.common.cert_status import OPENSSL_DATE, cert_status
from fabriclib.pki.common.revoked_serials import norm_serial, revoked_serials


def list_issued(limit=200, path=ISSUED_CERTS_FILE, now=None, revoked=REVOKED_CERTS_FILE):
    """Purpose: The hand-issued certificates from the ledger, newest first, each with its expiry status.
    Inputs:  limit — maximum entries, default 200; path — the ledger, default ISSUED_CERTS_FILE;
             now — timezone-aware datetime (tests), default the current UTC time; revoked — the revocations.
    Returns: list of ledger entries (when, actor, source, kind, subject, sans, serial, not_after, sha256,
             key, device) each plus "status": "revoked" (2.1.5.10) | "valid" | "expires soon" (under 30 days) |
             "expired";
             [] when there is no ledger. Lines that do not parse are skipped.
    Fails:   OSError if the ledger exists but cannot be read.
    Feeds:   agent route GET /v1/pki/issued; pki/list_certs (the PKI page's Issued view, 1.5.1.9); pki/revoke_cert.
    """
    if not os.path.exists(path):
        return []
    now = now or datetime.datetime.now(datetime.timezone.utc)
    gone = revoked_serials(revoked)
    out = []
    with open(path) as f:
        for line in f:
            try:
                entry = json.loads(line)
                end = datetime.datetime.strptime(entry["not_after"], OPENSSL_DATE).replace(
                    tzinfo=datetime.timezone.utc)
            except (ValueError, KeyError, TypeError):
                continue
            entry["status"] = cert_status(end, norm_serial(entry.get("serial", "")) in gone, now)
            out.append(entry)
    return out[::-1][:limit]
