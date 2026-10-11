import datetime
import json
import os
import subprocess
import tempfile
import urllib.request

from fabriclib.common.paths import FEDERATION_FILE, REVOKED_CERTS_FILE
from fabriclib.common.write_file_if_changed import write_file_if_changed

CRL_DAYS = 7                 # a CRL's nextUpdate: published again every night (fabric-certs.timer), so a week of slack
REASONS = ("unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded",
           "cessationOfOperation", "certificateHold")


def _revoked(path):
    """Purpose: the revocations recorded by revoke_cert.
    Inputs:  path — REVOKED_CERTS_FILE (JSON lines).
    Returns: list of dicts (serial, when, reason, issuer, not_after, subject); [] without the file. Lines that do not
             parse are skipped.
    Fails:   OSError reading an existing file.
    Feeds:   publish_crl."""
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _index_line(entry):
    """Purpose: one revoked certificate as a line of openssl ca's database (index.txt).
    Inputs:  entry — a revocation (serial hex, when ISO, reason, not_after openssl date or "").
    Returns: str "R\\t<expiry>\\t<revoked>,<reason>\\t<SERIAL>\\tunknown\\t/CN=revoked".
    Fails:   ValueError for a date in another format.
    Feeds:   _gencrl."""
    fmt = "%y%m%d%H%M%SZ"
    try:
        end = datetime.datetime.strptime(entry.get("not_after") or "", "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        end = datetime.datetime(2049, 12, 31, 23, 59, 59)
    when = datetime.datetime.fromisoformat(entry["when"]).astimezone(datetime.timezone.utc)
    serial = entry["serial"].replace(":", "").upper()
    serial = serial if len(serial) % 2 == 0 else "0" + serial
    return f"R\t{end.strftime(fmt)}\t{when.strftime(fmt)},{entry.get('reason') or 'unspecified'}\t{serial}\tunknown\t" \
           f"/CN=revoked"


def _gencrl(cert, key, password_file, entries):
    """Purpose: a CRL signed by one CA key, listing entries.
    Inputs:  cert, key — the CA certificate and its (encrypted) key; password_file — the key's password; entries —
             revocations this CA issued.
    Returns: the CRL as PEM (str).
    Fails:   subprocess.CalledProcessError when openssl refuses (wrong password, not a CA key).
    Feeds:   publish_crl."""
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "index.txt"), "w").write("".join(_index_line(e) + "\n" for e in entries))
        open(os.path.join(d, "crlnumber"), "w").write(datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "\n")
        open(os.path.join(d, "ca.cnf"), "w").write(
            "[ca]\ndefault_ca = fabric\n[fabric]\n"
            f"database = {d}/index.txt\ncrlnumber = {d}/crlnumber\ndefault_md = sha256\n"
            f"default_crl_days = {CRL_DAYS}\ncrl_extensions = crl_ext\n"
            "[crl_ext]\nauthorityKeyIdentifier = keyid:always\n")
        out = os.path.join(d, "crl.pem")
        subprocess.run(["openssl", "ca", "-gencrl", "-config", os.path.join(d, "ca.cnf"), "-cert", cert,
                        "-keyfile", key, "-passin", f"file:{password_file}", "-out", out],
                       check=True, capture_output=True)
        return open(out).read()


def _site_crls(timeout=10):
    """Purpose: the intermediate CRLs of the other sites this install knows (the federation registry), so a device
             certificate from another site is checked too (2.1.5.10, 2.1.9.12).
    Inputs:  timeout — seconds per fetch.
    Returns: list of PEM CRLs fetched (http://info.<site domain>/certs/crl/intermediate.pem, 1.5.1.5); a site that
             cannot be reached is skipped (its last CRL stays until it expires).
    Fails:   never.
    Feeds:   publish_crl."""
    import yaml
    if not os.path.exists(FEDERATION_FILE):
        return []
    try:
        reg = yaml.safe_load(open(FEDERATION_FILE)) or {}
    except (OSError, yaml.YAMLError):
        return []
    out = []
    for site in list((reg.get("sites") or {}).values()) + ([reg["upstream"]] if reg.get("upstream") else []):
        domain = (site or {}).get("domain")
        if not domain:
            continue
        try:
            with urllib.request.urlopen(f"http://info.{domain}/certs/crl/intermediate.pem", timeout=timeout) as r:
                body = r.read(1_000_000).decode()
            if "BEGIN X509 CRL" in body:
                out.append(body)
        except (OSError, ValueError):
            continue
    return out


def publish_crl(v, revoked_file=REVOKED_CERTS_FILE, fetch_sites=True):
    """Purpose: publish fabric's certificate revocation lists (manual 2.1.5.10), each where its key is on this host: the
             intermediate's (every leaf fabric issues) and the root's (the site CAs it signed); served at
             info.<domain>/certs/crl/ and <host_ip>/certs/crl/ (DER for the certificates' distribution point, PEM
             too; 1.5.1.5) and given to nginx and FreeRADIUS.
    Inputs:  v — settings: deploy_base_dir, service_users (nginx); revoked_file — the revocations; fetch_sites — also
             fetch the other sites' CRLs for FreeRADIUS (False in tests).
    Returns: {"changed": True if what nginx reads changed (reload it), "radius_changed", "root": True if a root CRL
             was made}.
             Files: <base>/nginx/www/certs/crl/{intermediate,root}.{crl,pem}; <base>/nginx/certs/client-ca/crl.pem
             (intermediate + root, for the web console's ssl_crl) and <base>/nginx/config/conf.d/client-crl.inc
             (`ssl_crl …;`, or empty without a root CRL: nginx checks every level of the chain);
             <base>/freeradius/certs/ca.pem (the CA certificates, then this site's and the other sites'
             intermediate CRLs) when FreeRADIUS is installed; "radius_changed" True when it changed (restart it).
    Fails:   subprocess.CalledProcessError when openssl cannot sign (the key or its password); OSError writing.
    Feeds:   revoke_cert, setup/mint_service_certs (every setup and every renewal run)."""
    base = v["deploy_base_dir"]
    certs = os.path.join(base, "stepca", "data", "certs")
    secrets = os.path.join(base, "stepca", "data", "secrets")
    password = os.path.join(secrets, "password")
    entries = _revoked(revoked_file)
    inter = None                    # each CA's CRL where its key is on this host (the federation suite's root-only CA)
    if os.path.exists(os.path.join(secrets, "intermediate_ca_key")):
        inter = _gencrl(os.path.join(certs, "intermediate_ca.crt"), os.path.join(secrets, "intermediate_ca_key"),
                        password, [e for e in entries if e.get("issuer", "intermediate") == "intermediate"])
    root = None
    if os.path.exists(os.path.join(secrets, "root_ca_key")):
        root = _gencrl(os.path.join(certs, "root_ca.crt"), os.path.join(secrets, "root_ca_key"), password,
                       [e for e in entries if e.get("issuer") == "root"])
    www = os.path.join(base, "nginx", "www", "certs", "crl")
    os.makedirs(www, mode=0o755, exist_ok=True)
    for name, pem in (("intermediate", inter), ("root", root)):
        if pem is None:
            continue
        write_file_if_changed(os.path.join(www, f"{name}.pem"), pem, 0o644, 0, 0)
        der = subprocess.run(["openssl", "crl", "-outform", "DER"], input=pem.encode(), capture_output=True,
                             check=True).stdout
        tmp = os.path.join(www, f".{name}.crl")
        open(tmp, "wb").write(der)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(www, f"{name}.crl"))
    uid, gid = (v.get("service_users", {}).get("nginx") or {}).get("uid", 0), \
        (v.get("service_users", {}).get("nginx") or {}).get("gid", 0)
    changed = False
    client_ca = os.path.join(base, "nginx", "certs", "client-ca")
    if os.path.isdir(client_ca):
        changed |= write_file_if_changed(os.path.join(client_ca, "crl.pem"), (inter or "") + (root or ""), 0o644, uid,
                                         gid)
        conf_d = os.path.join(base, "nginx", "config", "conf.d")
        os.makedirs(conf_d, exist_ok=True)
        inc = "ssl_crl /etc/nginx/certs/client-ca/crl.pem;\n" if root and inter else \
            "# no root CRL on this host (its root key is elsewhere): the web console checks no CRL\n"
        changed |= write_file_if_changed(os.path.join(conf_d, "client-crl.inc"), inc, 0o644, uid, gid)
    radius = os.path.join(base, "freeradius", "certs")
    radius_changed = False
    if os.path.isdir(radius):
        # EAP-TLS accepts client certificates from fabric's CA only, refusing the revoked ones (check_crl: the CRLs in
        # ca.pem, this site's and the other sites'); the same bundle verifies the domain controller for the policy
        parents = os.path.join(certs, "ca_parents.crt")
        cas = [os.path.join(certs, "root_ca.crt"), os.path.join(certs, "intermediate_ca.crt")]
        if os.path.exists(parents) and os.path.getsize(parents):
            cas.append(parents)
        bundle = "".join(open(c).read() for c in cas) + (inter or "") + "".join(_site_crls() if fetch_sites else [])
        radius_changed = write_file_if_changed(os.path.join(radius, "ca.pem"), bundle, 0o644, *_owner(radius))
    return {"changed": bool(changed), "radius_changed": bool(radius_changed), "root": root is not None}


def _owner(path):
    """Purpose: the owner of a folder, to give a file in it the same.
    Inputs:  path — folder.
    Returns: (uid, gid).
    Fails:   OSError when it does not exist.
    Feeds:   publish_crl."""
    st = os.stat(path)
    return st.st_uid, st.st_gid

