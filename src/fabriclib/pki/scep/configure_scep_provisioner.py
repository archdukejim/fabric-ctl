import base64
import os

from fabriclib.pki.scep.constants import (CHALLENGE_PATH, DEFAULT_CERT_DAYS, INSECURE_PORT, ISSUED_PATH, PROVISIONER,
                                          RA_CERT, RA_KEY)

LEAF_TEMPLATE = "/home/step/templates/certs/leaf.tpl"


def configure_scep_provisioner(cfg, v, data, password):
    """Purpose: converge Step-CA's SCEP provisioner in ca.json (manual 1.5.3.3): with the web console and an RA on disk,
             the provisioner `fabric-scep` with fabric's RSA decrypter, no static challenge and the two webhooks
             (challenge, notification) on the console's name, and the plain-HTTP listener; without them, neither.
    Inputs:  cfg — ca.json's parsed dict (changed in place); v — settings: install_webui, hostname_mgr,
             scep_cert_days (default 365); data — Step-CA's data folder (certs/scep_ra.crt, secrets/scep_ra_key);
             password — scep_ra_password (the RA key's), or None when the secrets have none yet.
    Returns: None. The provisioner: forceCN, 2048-bit minimum, AES-256-CBC requests (encryptionAlgorithmIdentifier 2),
             the root in GetCACert, scep_cert_days lifetimes, fabric's leaf.tpl (the CRL point), webhooks
             SCEPCHALLENGE and NOTIFYING at https://<hostname_mgr>/hooks/scep/...; cfg["insecureAddress"] ":9080".
    Fails:   OSError reading the RA files; ValueError for a scep_cert_days that is not a number (checked at apply).
    Feeds:   setup/init_pki._configure_ca_json (every pki step)."""
    provisioners = cfg.setdefault("authority", {}).setdefault("provisioners", [])
    kept = [p for p in provisioners if p.get("name") != PROVISIONER]
    cert, key = os.path.join(data, "certs", RA_CERT), os.path.join(data, "secrets", RA_KEY)
    if not (v.get("install_webui") and password and os.path.exists(cert) and os.path.exists(key)):
        provisioners[:] = kept
        if cfg.get("insecureAddress") == f":{INSECURE_PORT}":      # ours: nothing else uses plain HTTP
            cfg.pop("insecureAddress")
        return
    with open(cert, "rb") as f:
        cert_pem = f.read()
    with open(key, "rb") as f:
        key_pem = f.read()
    life = f"{int(v.get('scep_cert_days') or DEFAULT_CERT_DAYS) * 24}h"
    hooks = f"https://{v['hostname_mgr']}"
    kept.append({
        "type": "SCEP", "name": PROVISIONER, "forceCN": True, "minimumPublicKeyLength": 2048, "includeRoot": True,
        "encryptionAlgorithmIdentifier": 2,
        "decrypterCertificate": base64.b64encode(cert_pem).decode(),
        "decrypterKeyPEM": base64.b64encode(key_pem).decode(), "decrypterKeyPassword": password,
        "claims": {"minTLSCertDuration": "1h", "defaultTLSCertDuration": life, "maxTLSCertDuration": life},
        "options": {"x509": {"templateFile": LEAF_TEMPLATE}, "webhooks": [
            {"id": "fabric-scep-challenge", "name": "fabric-challenge", "url": hooks + CHALLENGE_PATH,
             "kind": "SCEPCHALLENGE", "certType": "X509"},
            {"id": "fabric-scep-issued", "name": "fabric-issued", "url": hooks + ISSUED_PATH,
             "kind": "NOTIFYING", "certType": "X509"}]}})
    provisioners[:] = kept
    cfg["insecureAddress"] = f":{INSECURE_PORT}"
