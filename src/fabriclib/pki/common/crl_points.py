import re
import subprocess


def crl_points(cert_path):
    """Purpose: the CRL distribution points a certificate names (manual 1.5.1.6).
    Inputs:  cert_path — PEM file.
    Returns: list of the URIs in its CRL Distribution Points extension, in order ([] when it has none or openssl
             cannot read it).
    Fails:   FileNotFoundError only if openssl is not installed.
    Feeds:   setup/mint_service_certs (a service certificate naming another point is issued again)."""
    out = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-text"], capture_output=True,
                         text=True).stdout
    lines, found, depth = out.splitlines(), [], None
    for line in lines:
        indent = len(line) - len(line.lstrip())
        if depth is None:
            if line.strip().startswith("X509v3 CRL Distribution Points"):
                depth = indent
            continue
        if line.strip() and indent <= depth:          # the next extension: this one has ended
            break
        found += re.findall(r"URI:(\S+)", line)
    return found
