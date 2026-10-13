import os
import re
import subprocess


def cert_names(cert_path):
    """Purpose: the names a certificate on disk holds (its DNS and IP subject alternative names), to compare with the
             names it should hold (decision 2.1.4.8: the landing page's certificate holds exactly its names).
    Inputs:  cert_path — PEM file (only the first certificate is read).
    Returns: set of lower-case names; None when the file is missing or openssl cannot read it.
    Fails:   FileNotFoundError only if openssl is not installed.
    Feeds:   setup/mint_service_certs, deploy/renew_landing_cert."""
    if not os.path.exists(cert_path):
        return None
    res = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        return None
    return {n.lower() for n in re.findall(r"(?:DNS|IP Address):([^,\s]+)", res.stdout)}
