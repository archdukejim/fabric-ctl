import os
import subprocess
import tempfile


def export_p12(crt, key, chain_files, friendly_name, password, out, legacy=False):
    """Purpose: Bundle a certificate, its private key and the CA chain into a password-protected PKCS#12
             file for browser and device import.
    Inputs:  crt — path of the PEM certificate; key — path of the PEM key; chain_files — list of PEM
             file paths joined as the chain (may be empty); friendly_name — str shown on import;
             password — str; out — output path; legacy — True for the older form Android 11 and earlier read
             (3DES for key and certificates, SHA-1 MAC; chosen per file, manual 1.5.3.6), default False.
    Returns: None; `out` is written with mode 0600 (AES-256-CBC for key and certificates, SHA-256 MAC; with legacy,
             PBE-SHA1-3DES and a SHA-1 MAC).
    Fails:   subprocess.CalledProcessError if openssl pkcs12 fails; OSError if a chain file cannot be read
             or `out` cannot be chmod-ed.
    Feeds:   convert_cert, issue_client_cert, issue_key_pair, scep/enrol_p12.
    Notes:   the password reaches openssl as -passout file:<temp file>, never on argv. That file sits in a
             0700 temp directory and is created with the process umask; the umask 077 covers only
             openssl's writing of `out`.
    """
    ciphers = (["-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"] if legacy else
               ["-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "sha256"])
    with tempfile.TemporaryDirectory(prefix="fabric-p12-") as tmp:     # 0700
        pw_file, chain = os.path.join(tmp, "pw"), os.path.join(tmp, "chain.pem")
        with open(pw_file, "w") as f:
            f.write(password)
        with open(chain, "w") as f:
            for path in chain_files:
                with open(path) as src:
                    f.write(src.read())
        old = os.umask(0o077)
        try:
            subprocess.run(["openssl", "pkcs12", "-export", "-in", crt, "-inkey", key,
                            *(["-certfile", chain] if chain_files else []), "-name", friendly_name, *ciphers,
                            "-passout", f"file:{pw_file}", "-out", out],
                           check=True, capture_output=True)
        finally:
            os.umask(old)
    os.chmod(out, 0o600)
