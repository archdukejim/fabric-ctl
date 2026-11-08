import ipaddress
import subprocess

from fabriclib.setup.errors import SetupError
from fabriclib.setup.site.certificate_fingerprint import certificate_fingerprint
from fabriclib.setup.site.constants import CERT_DAYS


def make_certificate(addresses, hostname):
    """Purpose: the site's temporary self-signed certificate (manual 1.3.6.3, deviation 2.1.1.93): made for this run,
             valid one day, naming the host's addresses and name. The key never touches a disk: openssl writes it to
             a pipe.
    Inputs:  addresses — list of IPv4 addresses (str); hostname — this host's name (str).
    Returns: (certificate PEM, key PEM, SHA-256 fingerprint).
    Fails:   SetupError when openssl fails.
    Feeds:   setup/site/guided_site."""
    names = [f"IP:{ipaddress.IPv4Address(a)}" for a in addresses] + ["IP:127.0.0.1", "DNS:localhost"]
    if hostname:
        names.append(f"DNS:{hostname}")
    res = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                          "-keyout", "/dev/stdout", "-out", "/dev/stdout", "-days", str(CERT_DAYS), "-sha256",
                          "-subj", "/CN=fabric temporary setup site", "-addext",
                          "subjectAltName=" + ",".join(names)], capture_output=True, text=True)
    pem = res.stdout
    if res.returncode != 0 or "PRIVATE KEY" not in pem or "CERTIFICATE" not in pem:
        raise SetupError(f"the site's temporary certificate could not be made: {res.stderr[-300:]}. "
                         "Run Guided here instead: sudo fabricctl setup --terminal. Nothing was changed.")
    start = pem.index("-----BEGIN CERTIFICATE-----")
    key, cert = pem[:start], pem[start:]
    return cert, key, certificate_fingerprint(cert)
