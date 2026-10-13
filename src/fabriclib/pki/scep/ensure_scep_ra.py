import datetime
import os
import subprocess
import tempfile

from fabriclib.pki.common.cert_dates import cert_dates
from fabriclib.pki.common.to_pem import to_pem
from fabriclib.pki.mint_offline_cert import mint_offline_cert
from fabriclib.pki.scep.constants import RA_BITS, RA_CERT, RA_DAYS, RA_KEY, RA_RENEW_DAYS


def _current(cert, key, intermediate, now):
    """Purpose: whether the RA on disk can stay: both files there, issued by the current intermediate, and more than
             RA_RENEW_DAYS left.
    Inputs:  cert, key — the RA's files; intermediate — the CA's intermediate certificate; now — aware datetime.
    Returns: bool.
    Fails:   never (openssl's refusal means False).
    Feeds:   ensure_scep_ra."""
    if not (os.path.exists(cert) and os.path.exists(key)):
        return False
    dates = cert_dates(cert)
    if not dates or dates[1] - now < datetime.timedelta(days=RA_RENEW_DAYS):
        return False
    res = subprocess.run(["openssl", "verify", "-partial_chain", "-CAfile", intermediate, cert], capture_output=True)
    return res.returncode == 0


def ensure_scep_ra(v, password, uid, gid, mint=mint_offline_cert, now=None):
    """Purpose: the SCEP provisioner's own RSA key and certificate (manual 1.5.3.3), made per install: Step-CA's
             intermediate is EC, and SCEP clients encrypt their request to an RSA key. Made when missing, when it has
             fewer than RA_RENEW_DAYS left, or when it is not from the current intermediate.
    Inputs:  v — settings: deploy_base_dir, domain, the step image and user (mint_offline_cert's); password —
             scep_ra_password, from fabric's secrets (never on a command line: it reaches openssl in a 0600 file);
             uid, gid — the step user; mint — mint_offline_cert (tests pass their own); now — aware datetime.
    Returns: True when a new RA was made (Step-CA's ca.json then changes), else False.
    Fails:   ValidationError from mint ("step-ca refused: ..."); subprocess.CalledProcessError from openssl; OSError.
    Feeds:   setup/init_pki (the pki step, with the web console)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    data = os.path.join(v["deploy_base_dir"], "stepca", "data")
    cert = os.path.join(data, "certs", RA_CERT)
    key = os.path.join(data, "secrets", RA_KEY)
    if _current(cert, key, os.path.join(data, "certs", "intermediate_ca.crt"), now):
        return False
    crt_path, key_path = mint(v, f"scep-ra.{v['domain']}", (), days=RA_DAYS, kty="RSA", size=RA_BITS)
    try:
        with open(crt_path) as f:
            leaf = to_pem(f.read(), "cert")[0]            # the bundle's first: the RA alone
        with tempfile.TemporaryDirectory(prefix="fabric-scep-ra-") as tmp:        # 0700
            pw = os.path.join(tmp, "pw")
            fd = os.open(pw, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(password)
            old = os.umask(0o077)
            try:
                subprocess.run(["openssl", "pkey", "-in", key_path, "-aes256", "-passout", f"file:{pw}",
                                "-out", key + ".new"], check=True, capture_output=True)
            finally:
                os.umask(old)
    finally:
        for path in (crt_path, key_path):
            if os.path.exists(path):
                os.remove(path)
    with open(cert + ".new", "w") as f:
        f.write(leaf)
    for path, mode in ((key + ".new", 0o600), (cert + ".new", 0o644)):
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    os.replace(key + ".new", key)
    os.replace(cert + ".new", cert)
    return True
