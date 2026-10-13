import base64
import os
import secrets
import tempfile
import threading

from fabriclib.common.paths import ISSUED_CERTS_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.link_device_cert import link_device_cert
from fabriclib.pki.common.ca_chain_pem import ca_chain_pem
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.pki.common.record_issued import record_issued
from fabriclib.pki.common.to_pem import to_pem
from fabriclib.pki.common.valid_days import valid_days
from fabriclib.pki.export_p12 import export_p12
from fabriclib.pki.mint_offline_cert import mint_offline_cert
from fabriclib.pki.scep.common.enrol_inputs import enrol_inputs
from fabriclib.pki.scep.constants import DEFAULT_CERT_DAYS, P12_KEY_BITS

_lock = threading.Lock()                    # mint_offline_cert's file names derive from the CN


def enrol_p12(v, actor, name, device="", legacy=False, source="web", ledger=ISSUED_CERTS_FILE,
              mint=mint_offline_cert, link=link_device_cert):
    """Purpose: a password-protected PKCS#12 for one Android phone or other device (manual 1.5.3.6): a key made here,
             its certificate from fabric's intermediate and the CA chain; the key and the password are handed out
             once and kept nowhere.
    Inputs:  v — settings (install_webui, scep_cert_days (default 365, at most pki_manual_max_days), deploy_base_dir,
             the step image); actor — the person (ledger, audit); name — the certificate's CN; device — a directory
             device to link, or ""; legacy — True for Android 11 and older (3DES and a SHA-1 MAC, said on the form);
             source — the audit's; ledger — the issued-certificate ledger; mint, link — mint_offline_cert and
             link_device_cert (tests pass their own).
    Returns: {"name", "cert", "fullchain", "der_b64", "p12_b64", "p12_password" (20 characters, shown once),
             "legacy", "info": describe_cert dict, "device"}.
    Fails:   ValidationError: enrol_inputs' (no web console, a bad name, an unknown device); valid_days' (a
             scep_cert_days over the cap); mint's ("step-ca refused: ..."); the link's (raised after issuing: the
             certificate is in the ledger and can be linked by hand); subprocess.CalledProcessError from export_p12;
             OSError.
    Feeds:   agent/post_enrol (POST /v1/pki/enrol/p12) <- the web console's Enrol a device."""
    name, device = enrol_inputs(v, name, device)
    days = valid_days(v, v.get("scep_cert_days") or DEFAULT_CERT_DAYS)
    with _lock:
        crt_path, key_path = mint(v, name, (), days=days, kty="RSA", size=P12_KEY_BITS)
        try:
            with open(crt_path) as f:
                cert = to_pem(f.read(), "cert")[0]
            with open(key_path) as f:
                key = f.read()
        finally:
            for path in (crt_path, key_path):
                if os.path.exists(path):
                    os.remove(path)
    chain = ca_chain_pem(v)
    password = secrets.token_urlsafe(15)                      # 20 characters
    with tempfile.TemporaryDirectory(prefix="fabric-enrol-") as tmp:      # 0700; gone with the key in it
        files = {}
        for label, body in (("crt", cert), ("key", key), ("chain", chain)):
            files[label] = os.path.join(tmp, label)
            fd = os.open(files[label], os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(body)
        out = os.path.join(tmp, "out.p12")
        export_p12(files["crt"], files["key"], [files["chain"]], name, password, out, legacy=bool(legacy))
        with open(out, "rb") as f:
            p12_b64 = base64.b64encode(f.read()).decode()
    info = describe_cert(cert)
    record_issued(actor, "enrol-p12", dict(info, device=device), source, path=ledger)
    cipher = "3DES/SHA-1 (Android 11 and older)" if legacy else "AES-256/SHA-256"
    write_audit(actor, "PKI_ENROL_P12", f"subject={info['subject']} serial={info['serial']} days={days} "
                                        f"device={device or '-'} cipher={cipher} (key and password handed out, not "
                                        "kept)", source)
    if device:
        link(v, actor, device, info["sha256"], source=source)
    return {"name": name, "cert": cert, "fullchain": cert + chain,
            "der_b64": "".join(cert.strip().splitlines()[1:-1]),          # a PEM's body is its DER in base64
            "p12_b64": p12_b64, "p12_password": password, "legacy": bool(legacy), "info": info, "device": device}
