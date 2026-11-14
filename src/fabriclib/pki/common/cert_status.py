import datetime

SOON = datetime.timedelta(days=30)
OPENSSL_DATE = "%b %d %H:%M:%S %Y %Z"


def parse_cert_date(text):
    """Purpose: a certificate date as openssl prints it ("Sep 30 12:00:00 2027 GMT", the ledger's) or as ISO 8601
             (Step-CA's database reader's "2027-09-30T12:00:00Z").
    Inputs:  text — str.
    Returns: an aware UTC datetime.
    Fails:   ValueError for anything else.
    Feeds:   cert_status, pki/list_certs, pki/list_issued."""
    text = str(text or "").strip()
    try:
        return datetime.datetime.strptime(text, OPENSSL_DATE).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)


def cert_status(end, revoked, now):
    """Purpose: what the issued lists say of a certificate (manual 1.5.1.3).
    Inputs:  end — its expiry (aware datetime); revoked — whether its serial is in the revocations; now — aware.
    Returns: "revoked" | "expired" | "expires soon" (under 30 days) | "valid".
    Fails:   never.
    Feeds:   pki/list_certs, pki/list_issued."""
    if revoked:
        return "revoked"
    return "expired" if end < now else ("expires soon" if end - now < SOON else "valid")
