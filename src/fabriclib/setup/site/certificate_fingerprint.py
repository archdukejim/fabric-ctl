import hashlib
import ssl


def certificate_fingerprint(pem):
    """Purpose: a certificate's SHA-256 fingerprint as browsers show it, for a person to compare by eye (1.3.6.3).
    Inputs:  pem — str, PEM; the first certificate in it counts.
    Returns: str, "AA:BB:...".
    Fails:   ValueError when it holds no certificate.
    Feeds:   setup/site/make_certificate, setup/site/guided_site."""
    end = "-----END CERTIFICATE-----"
    if end not in pem:
        raise ValueError("no certificate in the PEM")
    der = ssl.PEM_cert_to_DER_cert(pem[pem.index("-----BEGIN CERTIFICATE-----"):pem.index(end) + len(end)])
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
