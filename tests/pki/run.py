#!/usr/bin/env python3
"""Manual PKI and zone TSIG operations against a real Step-CA image.

Builds a throwaway root + intermediate with the pinned step CLI, lays it
out like an install (<base>/stepca/data/...), and drives the fabriclib
operations the web UI calls through fabric-agent: sign a CSR, generate a
key + certificate, inspect, convert, the issued ledger, and TSIG keys for a
zone — including what must be refused.

    sudo python3 tests/pki/run.py          (needs Docker, openssl, root)
"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile

import jinja2
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/pki"
IMAGE = os.environ.get("FABRIC_STEP_IMAGE") or subprocess.run(
    [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "image_ref.py"), "stepca"],
    capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, data=None, ok=True):
    res = subprocess.run(cmd, input=data, capture_output=True, text=isinstance(data, str) or data is None)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def refused(fn, *args, match=""):
    """True only if fn(*args) raises a ValidationError whose message contains `match`."""
    try:
        fn(*args)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {match!r}: {exc}")
    return False


# ---------------------------------------------------------------- layout
shutil.rmtree(W, ignore_errors=True)
data = f"{W}/stepca/data"
for d in ("certs", "secrets", "templates/certs", "artifacts"):
    os.makedirs(f"{data}/{d}")
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)   # the installed tree
os.makedirs(f"{W}/fabric/config")
with open(f"{data}/secrets/password", "w") as f:
    f.write(base64.b64encode(os.urandom(24)).decode())
env = jinja2.Environment()
for tpl in ("leaf", "subca"):
    src = open(f"{REPO}/templates/stepca/{tpl}.tpl.j2").read()
    with open(f"{data}/templates/certs/{tpl}.tpl", "w") as f:
        f.write(env.from_string(src).render(cert_country="US", cert_province="CA", cert_city="Test",
                                            cert_org="Fabric Test", cert_ou="IT"))
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])


def step(*args):
    return sh(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "--user",
               f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, *args])


step("certificate", "create", "Fabric Test Root CA", "/home/step/certs/root_ca.crt", "/home/step/secrets/root_ca_key",
     "--profile", "root-ca", "--password-file", "/home/step/secrets/password")
step("certificate", "create", "Fabric Test Intermediate CA", "/home/step/certs/intermediate_ca.crt",
     "/home/step/secrets/intermediate_ca_key", "--profile", "intermediate-ca",
     "--ca", "/home/step/certs/root_ca.crt", "--ca-key", "/home/step/secrets/root_ca_key",
     "--ca-password-file", "/home/step/secrets/password", "--password-file", "/home/step/secrets/password")
ROOT, INTER = f"{data}/certs/root_ca.crt", f"{data}/certs/intermediate_ca.crt"

V = {"deploy_base_dir": W, "domain": "lan.test", "host_ip": "192.168.7.53", "hostname_landing": "info.lan.test",
     "image_stepca": IMAGE, "service_users": {"step": {"uid": STEP_UID, "gid": STEP_UID}},
     "dns": {"dynamic_zone_var": {"zone_authority": True, "A": [{"name": "fabric", "ip": "192.168.7.53"}]},
             "7.168.192.in-addr.arpa": {"PTR": [{"name": "53", "target": "fabric.lan.test."}]}}}
with open(f"{W}/fabric/config/vars.yaml", "w") as f:
    yaml.safe_dump(V, f)

sys.path.insert(0, f"{W}/fabric/lib")
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dns.create_zone_tsig_key import create_zone_tsig_key  # noqa: E402
from fabriclib.dns.list_tsig_keys import list_tsig_keys  # noqa: E402
from fabriclib.dns.remove_tsig_key import remove_tsig_key  # noqa: E402
from fabriclib.dns.rotate_tsig_key import rotate_tsig_key  # noqa: E402
from fabriclib.pki.ca_summary import ca_summary  # noqa: E402
from fabriclib.pki.convert_cert import convert_cert  # noqa: E402
from fabriclib.pki.describe_csr import describe_csr  # noqa: E402
from fabriclib.pki.inspect_pem import inspect_pem  # noqa: E402
from fabriclib.pki.issue_key_pair import issue_key_pair  # noqa: E402
from fabriclib.pki.list_issued import list_issued  # noqa: E402
from fabriclib.pki.sign_csr import sign_csr  # noqa: E402

T = tempfile.mkdtemp(dir=W)


def csr(name, *extra, key="rsa:2048", subj=None):
    k, c = f"{T}/{name}.key", f"{T}/{name}.csr"
    sh(["openssl", "req", "-new", "-newkey", key, "-nodes", "-keyout", k, "-out", c,
        "-subj", subj or f"/CN={name}.lan.test", *extra])
    return open(c).read(), k


def verifies(pem):
    with open(f"{T}/v.pem", "w") as f:
        f.write(pem)
    return sh(["openssl", "verify", "-CAfile", ROOT, "-untrusted", INTER, f"{T}/v.pem"], ok=False).returncode == 0


def text_of(pem):
    return sh(["openssl", "x509", "-noout", "-text"], data=pem).stdout


def artifacts_empty():
    return os.listdir(f"{data}/artifacts") == []


# ---------------------------------------------------------------- sign a CSR
good, good_key = csr("dev1", "-addext", "subjectAltName=DNS:dev1.lan.test,DNS:dev1,IP:192.168.7.21")
review = describe_csr(good)
check("CSR review: names, key and no problems",
      review["sans"] == ["dev1.lan.test", "dev1", "192.168.7.21"] and review["key"] == "RSA 2048"
      and not review["problems"], review)
r = sign_csr(V, "alice", good, 90)
t = text_of(r["cert"])
check("signed CSR chains to the fabric root", verifies(r["fullchain"]))
check("signed cert keeps the CSR's names", all(n in t for n in ("DNS:dev1.lan.test", "DNS:dev1", "IP Address:192.168.7.21")), t)
check("signed cert is a leaf for server + client auth",
      "TLS Web Server Authentication" in t and "TLS Web Client Authentication" in t and "CA:TRUE" not in t, t)
check("signed cert gets the fabric subject defaults", "O=Fabric Test" in r["info"]["subject"], r["info"])
end = sh(["openssl", "x509", "-noout", "-checkend", str(89 * 86400)], data=r["cert"], ok=False).returncode == 0
end2 = sh(["openssl", "x509", "-noout", "-checkend", str(91 * 86400)], data=r["cert"], ok=False).returncode != 0
check("signed cert is valid for the requested 90 days", end and end2)
pub_cert = sh(["openssl", "x509", "-noout", "-pubkey"], data=r["cert"]).stdout
pub_key = sh(["openssl", "pkey", "-in", good_key, "-pubout"]).stdout
check("signed cert carries the device's own public key", pub_cert == pub_key)
check("DER download is the same certificate",
      sh(["openssl", "x509", "-inform", "DER", "-outform", "PEM"], data=base64.b64decode(r["der_b64"])).stdout
      .decode() == sh(["openssl", "x509"], data=r["cert"]).stdout)
check("no CSR left in the CA's artifacts directory", artifacts_empty(), os.listdir(f"{data}/artifacts"))

cn_only, _ = csr("cnonly")
r2 = sign_csr(V, "alice", cn_only, 30)
check("CN-only CSR: the CN becomes a SAN", "DNS:cnonly.lan.test" in text_of(r2["cert"]))

ca_req, _ = csr("wantsca", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "subjectAltName=DNS:wantsca.lan.test")
check("CSR asking to be a CA is flagged in review", describe_csr(ca_req)["ca_requested"])
r3 = sign_csr(V, "alice", ca_req, 30)
check("...and is still issued as a leaf (never CA:TRUE)", "CA:TRUE" not in text_of(r3["cert"]) and not r3["info"]["is_ca"])

der = sh(["openssl", "req", "-outform", "DER"], data=good.encode()).stdout
check("DER CSR (base64 upload) is accepted", describe_csr(base64.b64encode(der).decode())["sans"][0] == "dev1.lan.test")

weak, _ = csr("weak", key="rsa:1024")
check("1024-bit RSA CSR refused", refused(sign_csr, V, "alice", weak, 30, match="too small"))
tampered = bytearray(der)
tampered[-5] ^= 0xFF
check("tampered CSR (bad signature) refused",
      refused(sign_csr, V, "alice", base64.b64encode(bytes(tampered)).decode(), 30, match="signature"))
uri, _ = csr("uri", "-addext", "subjectAltName=URI:spiffe://evil/x")
check("CSR with a URI name refused", refused(sign_csr, V, "alice", uri, 30, match="unsupported"))
badcn, _ = csr("badcn", subj="/CN=not a host name!")
check("CSR naming nothing usable refused", refused(sign_csr, V, "alice", badcn, 30, match="not a host name"))
check("validity above pki_manual_max_days refused", refused(sign_csr, V, "alice", good, 1826, match="1 to 1825"))
check("validity of 0 days refused", refused(sign_csr, V, "alice", good, 0, match="days"))
check("two CSRs at once refused", refused(sign_csr, V, "alice", good + cn_only, 30, match="exactly one"))
check("junk refused", refused(sign_csr, V, "alice", "hello", 30, match="not a PEM"))
sh(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{T}/ec.key"])
sh(["openssl", "req", "-new", "-key", f"{T}/ec.key", "-subj", "/CN=ecdev.lan.test", "-out", f"{T}/ec.csr"])
check("EC P-256 CSR signed", verifies(sign_csr(V, "alice", open(f"{T}/ec.csr").read(), 30)["fullchain"]))

# ---------------------------------------------------------------- generate key + cert
for kt, want in (("RSA-2048", "Public-Key: (2048 bit)"), ("EC-P256", "prime256v1")):
    g = issue_key_pair(V, "alice", "printer.lan.test", ["printer", "192.168.7.40"], kt, 365)
    t = text_of(g["cert"])
    check(f"{kt}: generated cert chains to the fabric root", verifies(g["fullchain"]))
    check(f"{kt}: key type and names", want in t and "DNS:printer" in t and "IP Address:192.168.7.40" in t, t[:600])
    kp = f"{T}/gen.key"
    with open(kp, "w") as f:
        f.write(g["key"])
    check(f"{kt}: private key matches the certificate",
          sh(["openssl", "pkey", "-in", kp, "-pubout"]).stdout == sh(["openssl", "x509", "-noout", "-pubkey"],
                                                                        data=g["cert"]).stdout)
    p12 = f"{T}/gen.p12"
    with open(p12, "wb") as f:
        f.write(base64.b64decode(g["p12_b64"]))
    pw = f"{T}/pw"
    with open(pw, "w") as f:
        f.write(g["p12_password"])
    out = sh(["openssl", "pkcs12", "-in", p12, "-nodes", "-passin", f"file:{pw}"], ok=False)
    check(f"{kt}: .p12 opens with its password and holds key + 3 certs",
          out.returncode == 0 and out.stdout.count("BEGIN CERTIFICATE") == 3 and "PRIVATE KEY" in out.stdout,
          out.stderr[-300:])
    check(f"{kt}: key not kept in the CA's artifacts directory", artifacts_empty(), os.listdir(f"{data}/artifacts"))
check("generate: invalid name refused", refused(issue_key_pair, V, "alice", "bad name!", [], "RSA-2048", 30,
                                                match="not a host name"))
check("generate: invalid alternative name refused",
      refused(issue_key_pair, V, "alice", "ok.lan.test", ["spiffe://x"], "RSA-2048", 30, match="invalid alternative"))
check("generate: unknown key type refused", refused(issue_key_pair, V, "alice", "ok.lan.test", [], "DSA-1024", 30,
                                                    match="key type"))

# ---------------------------------------------------------------- inspect
i = inspect_pem(V, r["fullchain"])
check("inspect: chain decoded, fabric certs marked trusted",
      i["kind"] == "cert" and len(i["items"]) == 3 and all(x["trusted"] for x in i["items"]), i["kind"])
sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{T}/foreign.key", "-out",
    f"{T}/foreign.crt", "-days", "2", "-subj", "/CN=foreign.example"])
foreign = open(f"{T}/foreign.crt").read()
check("inspect: foreign certificate is not trusted", inspect_pem(V, foreign)["items"][0]["trusted"] is False)
check("inspect: DER certificate accepted",
      inspect_pem(V, base64.b64encode(sh(["openssl", "x509", "-outform", "DER"], data=foreign.encode()).stdout)
                  .decode())["items"][0]["info"]["subject"].endswith("foreign.example"))
ci = inspect_pem(V, weak)
check("inspect: CSR decoded with its policy verdict", ci["kind"] == "csr" and ci["items"][0]["info"]["problems"], ci)
check("inspect: private keys refused unread", refused(inspect_pem, V, open(good_key).read(), match="private key"))

# ---------------------------------------------------------------- convert
c = convert_cert(V, "alice", r["cert"], open(good_key).read())
check("convert: fabric cert gets the fabric chain", c["fabric_issued"] and c["fullchain"].count("BEGIN CERTIFICATE") == 3)
p7 = sh(["openssl", "pkcs7", "-inform", "DER", "-print_certs"], data=base64.b64decode(c["p7b_b64"])).stdout.decode()
check("convert: .p7b holds cert + chain", p7.count("BEGIN CERTIFICATE") == 3)
with open(f"{T}/c.p12", "wb") as f:
    f.write(base64.b64decode(c["p12_b64"]))
with open(f"{T}/cpw", "w") as f:
    f.write(c["p12_password"])
check("convert: cert + key -> .p12 that opens",
      sh(["openssl", "pkcs12", "-in", f"{T}/c.p12", "-nodes", "-passin", f"file:{T}/cpw"], ok=False).returncode == 0)
check("convert: a key that is not the certificate's is refused",
      refused(convert_cert, V, "alice", r["cert"], open(f"{T}/foreign.key").read(), match="does not belong"))
fc = convert_cert(V, "alice", foreign, open(f"{T}/foreign.key").read())
check("convert: foreign cert keeps its own (empty) chain, .p12 still works",
      not fc["fabric_issued"] and fc["p12_b64"] and fc["fullchain"].count("BEGIN CERTIFICATE") == 1)

# ---------------------------------------------------------------- ledger, CA
issued = list_issued()
check("issued ledger lists every hand-issued cert, newest first",
      len(issued) == 6 and issued[0]["kind"] == "keypair" and issued[-1]["kind"] == "csr", len(issued))
ledger = open(f"{W}/fabric/archive/issued-certs.jsonl").read()
check("ledger never holds keys", "PRIVATE" not in ledger and "p12" not in ledger)
check("ledger is 0600", oct(os.stat(f"{W}/fabric/archive/issued-certs.jsonl").st_mode & 0o777) == "0o600")
audit = open(f"{W}/fabric/archive/audit.log").read()
check("audit log records signing and generation by user",
      "alice (web) | Action: PKI_SIGN_CSR" in audit and "alice (web) | Action: PKI_ISSUE" in audit)
ca = ca_summary(V)
check("CA summary: root, intermediate, certs URL",
      ca["root"]["subject"].endswith("Fabric Test Root CA") and "Intermediate" in ca["intermediate"]["subject"]
      and ca["certs_url"] == "http://info.lan.test/certs/", ca)

# ---------------------------------------------------------------- TSIG keys for a zone
key, secret, ini = create_zone_tsig_key("alice", "npm-certbot", "lan.test", "acme-hosts", ["npm", "nas"])
check("TSIG acme-hosts key: rfc2136.ini with name, secret, server",
      "dns_rfc2136_name = npm-certbot" in ini and f"dns_rfc2136_secret = {secret}" in ini
      and "dns_rfc2136_server = 192.168.7.53" in ini, ini)
vars_now = open(f"{W}/fabric/config/vars.yaml").read()
secrets_now = open(f"{W}/fabric/config/fabric-secrets.yml").read()
check("TSIG secret kept out of vars.yaml, stored in fabric-secrets.yml", secret not in vars_now and secret in secrets_now)
scope = {k["name"]: k["scope"] for k in list_tsig_keys()}
check("acme-hosts key may update only its hosts' challenge names",
      scope["npm-certbot"] == "_acme-challenge.npm.lan.test, _acme-challenge.nas.lan.test", scope)
create_zone_tsig_key("alice", "zone-acme", "lan.test", "acme-zone")
create_zone_tsig_key("alice", "ddns", "lan.test", "any-name", types=["A", "AAAA"])
scope = {k["name"]: (k["scope"], k["types"]) for k in list_tsig_keys()}
check("acme-zone and any-name scopes", scope["zone-acme"][0].startswith("_acme-challenge (zone")
      and scope["ddns"] == ("any name in lan.test", "A AAAA"), scope)
kept = base64.b64encode(os.urandom(32)).decode()
_, s2, _ = create_zone_tsig_key("alice", "legacy", "lan.test", "acme-zone", secret=kept)
check("an existing secret is kept (current clients keep working)", s2 == kept)
check("TSIG: reverse or unknown zone refused",
      refused(create_zone_tsig_key, "alice", "x1", "7.168.192.in-addr.arpa", "acme-zone", match="forward zones")
      and refused(create_zone_tsig_key, "alice", "x2", "evil.test", "acme-zone", match="forward zones"))
check("TSIG: any-name with a type outside the list refused",
      refused(create_zone_tsig_key, "alice", "x3", "lan.test", "any-name", [], ["NS"], match="record types"))
check("TSIG: listed-hosts scope without hosts refused",
      refused(create_zone_tsig_key, "alice", "x4", "lan.test", "acme-hosts", [], match="at least one host"))
check("TSIG: invalid secret refused",
      refused(create_zone_tsig_key, "alice", "x5", "lan.test", "acme-zone", [], ["TXT"], "not-base64!", match="base64"))
check("TSIG: duplicate name refused",
      refused(create_zone_tsig_key, "alice", "npm-certbot", "lan.test", "acme-zone", match="already exists"))
check("TSIG: invalid name refused",
      refused(create_zone_tsig_key, "alice", "../etc", "lan.test", "acme-zone", match="invalid"))
check("TSIG: web keys never choose their rfc2136.ini path",
      all("out" not in k for k in yaml.safe_load(open(f"{W}/fabric/config/vars.yaml"))["tsig_keys"]))
new, ini2 = rotate_tsig_key("alice", "npm-certbot")
check("rotate: new secret, in the secrets file and the new ini",
      new != secret and new in open(f"{W}/fabric/config/fabric-secrets.yml").read() and new in ini2)
remove_tsig_key("alice", "legacy", source="web")
check("remove: key and secret gone", "legacy" not in open(f"{W}/fabric/config/vars.yaml").read()
      and kept not in open(f"{W}/fabric/config/fabric-secrets.yml").read())

# ---------------------------------------------------------------- federation site CAs (own throwaway root)
print("--- site CAs (site_ca.py)")
site = subprocess.run([sys.executable, os.path.join(REPO, "tests", "pki", "site_ca.py")], capture_output=True, text=True)
print("\n".join(line for line in site.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or site.stdout[-2000:] + site.stderr[-2000:])
check("site CAs: site_ca.py passed", site.returncode == 0, site.stderr[-400:])

print("--- renewal and its warnings (renewal.py)")
ren = subprocess.run([sys.executable, os.path.join(REPO, "tests", "pki", "renewal.py")], capture_output=True, text=True)
print("\n".join(line for line in ren.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or ren.stdout[-2000:] + ren.stderr[-2000:])
check("renewal: renewal.py passed", ren.returncode == 0, ren.stderr[-400:])

print("--- revocation and the CRLs (revocation.py)")
rev = subprocess.run([sys.executable, os.path.join(REPO, "tests", "pki", "revocation.py")], capture_output=True, text=True)
print("\n".join(line for line in rev.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or rev.stdout[-2000:] + rev.stderr[-2000:])
check("revocation: revocation.py passed", rev.returncode == 0, rev.stderr[-400:])

print("--- ACME for LAN machines (acme.py)")
acme_run = subprocess.run([sys.executable, os.path.join(REPO, "tests", "pki", "acme.py")], capture_output=True,
                          text=True)
print("\n".join(line for line in acme_run.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or acme_run.stdout[-2000:] + acme_run.stderr[-2000:])
check("ACME: acme.py passed", acme_run.returncode == 0, acme_run.stderr[-400:])

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
