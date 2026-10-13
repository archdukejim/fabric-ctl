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
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

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
     "hostname_stepca": "ca.lan.test",
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
# covers: setting:cert_org +
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
# covers: setting:pki_manual_max_days +
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
      and ca["certs_url"] == "http://ca.lan.test/certs/", ca)

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

# ---------------------------------------------------------------- the same through fabric-agent
print("--- through fabric-agent (its routes; a root peer needs no token, so the request names the actor)")
SOCK = f"{W}/agent.sock"
agent = subprocess.Popen([sys.executable, f"{W}/fabric/lib/agent/server.py", "--socket", SOCK, "--socket-gid", "0"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
for _ in range(100):
    if os.path.exists(SOCK):
        break
    time.sleep(0.1)


def agent_call(method, path, body=None):
    """(status, JSON reply) of one fabric-agent request over its unix socket, as root."""
    raw = json.dumps({"actor": "alice", **(body or {})}).encode() if method == "POST" else b""
    s = socket.socket(socket.AF_UNIX)
    s.connect(SOCK)
    s.sendall(f"{method} {path} HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n"
              .encode() + raw)
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    head, _, payload = out.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(payload or b"null")


def ledger_text():
    return open(f"{W}/fabric/archive/issued-certs.jsonl").read()


def config_files():
    """vars.yaml and fabric-secrets.yml as they are now (to prove a refusal changed nothing)."""
    return open(f"{W}/fabric/config/vars.yaml").read(), open(f"{W}/fabric/config/fabric-secrets.yml").read()


REVOKED = f"{W}/fabric/archive/revoked-certs.jsonl"


def revoked_text():
    return open(REVOKED).read() if os.path.exists(REVOKED) else ""


before = ledger_text()
st, res = agent_call("POST", "/v1/pki/sign", {"csr": good, "days": 20})
# covers: agent:post.pki.sign +
check("agent: POST /v1/pki/sign signs the CSR (chains to the root) and records it in the ledger",
      st == 200 and verifies(res["fullchain"]) and ledger_text().count("\n") == before.count("\n") + 1, (st, res))
before = ledger_text()
st, res = agent_call("POST", "/v1/pki/sign", {"csr": weak, "days": 20})
# covers: agent:post.pki.sign -
check("agent: a 1024-bit CSR is refused (400, says why), nothing signed or recorded",
      st == 400 and "too small" in res.get("error", "") and ledger_text() == before, (st, res))
st, res = agent_call("POST", "/v1/pki/issue", {"cn": "agentkey.lan.test", "sans": ["agentkey"], "key_type": "EC-P256",
                                               "days": 20})
# covers: agent:post.pki.issue +
check("agent: POST /v1/pki/issue makes a key + certificate that chains to the root",
      st == 200 and verifies(res["fullchain"]) and "PRIVATE KEY" in res["key"]
      and "DNS:agentkey" in text_of(res["cert"]), (st, str(res)[:300]))
st, res = agent_call("GET", "/v1/pki/issued")
# covers: agent:get.pki.issued +
check("agent: GET /v1/pki/issued lists them, newest first",
      st == 200 and res[0]["subject"].startswith("CN=agentkey.lan.test,") and res[0]["kind"] == "keypair", (st, res[:2]))
st, res = agent_call("GET", "/v1/cert-warnings")
# covers: agent:get.cert-warnings +
check("agent: GET /v1/cert-warnings counts the issued certificates expiring within 30 days",
      st == 200 and any(w["level"] == "warn" and "expiring within 30 days" in w["what"] for w in res), (st, res))
st, res = agent_call("POST", "/v1/pki/describe-csr", {"csr": "hello"})
# covers: agent:post.pki.describe-csr -
check("agent: describe-csr refuses what is not a CSR (400, says why)",
      st == 400 and "not a PEM" in res.get("error", ""), (st, res))
st, res = agent_call("POST", "/v1/pki/convert", {"cert": r["cert"], "key": open(f"{T}/foreign.key").read()})
# covers: agent:post.pki.convert -
check("agent: convert refuses a key that is not the certificate's (400, says why)",
      st == 400 and "does not belong" in res.get("error", ""), (st, res))
before = revoked_text()
st, res = agent_call("POST", "/v1/pki/revoke", {"target": "nobody.lan.test", "reason": "unspecified"})
# covers: agent:post.pki.revoke -
check("agent: revoking a name not in the ledger is refused (400, says why), nothing recorded",
      st == 400 and "no certificate named 'nobody.lan.test'" in res.get("error", "") and revoked_text() == before,
      (st, res))
st, res = agent_call("POST", "/v1/pki/revoke", {"target": "agentkey.lan.test", "reason": "superseded"})
# covers: agent:post.pki.revoke +
check("agent: POST /v1/pki/revoke revokes by name: recorded with its serial and reason",
      st == 200 and res["subject"].startswith("CN=agentkey.lan.test,") and res["serial"] in revoked_text()
      and '"reason": "superseded"' in revoked_text(), (st, res))
st, res = agent_call("POST", "/v1/tsig", {"name": "acme-nas", "zone": "lan.test", "scope": "acme-hosts",
                                          "hosts": ["nas"], "types": ["TXT"]})
check("agent: a DNS-01 key for one machine (acme-nas)", st == 200 and res["key"]["name"] == "acme-nas", (st, res))
st, res = agent_call("GET", "/v1/pki/acme")
# covers: agent:get.pki.acme +
check("agent: GET /v1/pki/acme: the ACME directory and the machines with a DNS-01 key",
      st == 200 and any("https://ca.lan.test/acme/acme/directory" in line for line in res["info"])
      and [m["fqdn"] for m in res["machines"]] == ["nas.lan.test"] and res["domain"] == "lan.test", (st, res))
before = config_files()
st, res = agent_call("POST", "/v1/tsig/ghost/rotate")
# covers: agent:post.tsig.*.rotate -
check("agent: rotating a TSIG key that does not exist is refused (400, names it), nothing changed",
      st == 400 and "no TSIG key named 'ghost'" in res.get("error", "") and config_files() == before, (st, res))
st, res = agent_call("POST", "/v1/tsig/ghost/delete")
# covers: agent:post.tsig.*.delete -
check("agent: deleting a TSIG key that does not exist is refused (400, names it), nothing changed",
      st == 400 and "no TSIG key named 'ghost'" in res.get("error", "") and config_files() == before, (st, res))
agent.terminate()
agent.wait()

# ---------------------------------------------------------------- fabricctl tsig and acl (the real command)
print("--- fabricctl tsig and acl (the installed command; --no-apply: no BIND runs here)")


def fabricctl(*argv, answers=None):
    """(exit status, stdout + stderr) of the installed fabricctl, answers on stdin; its own session, so a hidden
    prompt reads stdin, never a terminal."""
    res = subprocess.run([sys.executable, "-m", "fabriclib.cli", *argv], cwd=f"{W}/fabric/lib", input=answers,
                         capture_output=True, text=True, start_new_session=True)
    return res.returncode, res.stdout + res.stderr


code, out = fabricctl("tsig", "add", "cli-key", "--record", "web", "--no-apply")
# covers: cli:tsig +
check("tsig add: a key for one host's DNS-01 challenge, recorded (not applied: said so)",
      code == 0 and "TSIG key 'cli-key' added (new secret)" in out and "not applied yet" in out
      and "cli-key" in config_files()[0], (code, out))
before = config_files()
for argv, code_want, why, ids in (
        (("tsig", "frobnicate"), 2, "invalid choice", "cli:tsig"),
        (("tsig", "list", "--all"), 2, "unrecognized arguments", "cli:tsig.list"),
        (("tsig", "add", "cli-key2", "--record", "web", "--any-name", "--no-apply"), 1,
         "--record and --any-name exclude each other", "cli:tsig.add"),
        (("tsig", "add", "cli-key", "--no-apply"), 1, "TSIG key 'cli-key' already exists", "cli:tsig.add"),
        (("tsig", "update", "cli-key", "--no-apply"), 1, "nothing to change", "cli:tsig.update"),
        (("tsig", "update", "ghost", "--types", "TXT", "--no-apply"), 1, "no TSIG key named 'ghost'", "cli:tsig.update"),
        (("tsig", "set-secret", "cli-key", "--no-apply"), 1, "give the secret with --secret-prompt or --secret-file",
         "cli:tsig.set-secret"),
        (("tsig", "rotate", "ghost", "--no-apply"), 1, "no TSIG key named 'ghost'", "cli:tsig.rotate"),
        (("tsig", "remove", "ghost", "--no-apply"), 1, "no TSIG key named 'ghost'", "cli:tsig.remove")):
    code, out = fabricctl(*argv)
    # covers: cli:tsig cli:tsig.list cli:tsig.add cli:tsig.update cli:tsig.set-secret cli:tsig.rotate cli:tsig.remove -
    check(f"refused: fabricctl {' '.join(argv)} ({ids}): exit {code_want}, says why, nothing changed",
          code == code_want and why in out and config_files() == before, (code, out[-300:]))
given = base64.b64encode(os.urandom(32)).decode()
code, out = fabricctl("tsig", "set-secret", "cli-key", "--secret-prompt", "--no-apply", answers=given + "\n")
# covers: ask:tsig.secret +
check("tsig set-secret --secret-prompt: the secret typed at the hidden prompt replaces the key's (never on argv)",
      code == 0 and "secret replaced" in out and given in config_files()[1] and given not in config_files()[0],
      (code, out))
before = config_files()
code, out = fabricctl("tsig", "set-secret", "cli-key", "--secret-prompt", "--no-apply", answers="not-base64!\n")
# covers: ask:tsig.secret -
check("refused: a typed secret that is not base64 (says why, the old secret kept)",
      code == 1 and "secret is not valid base64" in out and config_files() == before, (code, out))

code, out = fabricctl("acl", "add", "cli-acl", "10.9.0.0/16", "key cli-key", "--no-apply")
# covers: cli:acl +
check("acl add: an ACL with a network and a TSIG key, recorded",
      code == 0 and 'cli-acl: 10.9.0.0/16, key "cli-key"' in out and "cli-acl" in config_files()[0], (code, out))
code, out = fabricctl("acl", "policy", "cli-acl", "--record", "web", "--no-apply")
check("acl policy: the ACL's keys may set web's DNS-01 challenge",
      code == 0 and "members may update _acme-challenge.web.lan.test (TXT)" in out, (code, out))
code, out = fabricctl("acl", "list")
# covers: cli:acl.list +
check("acl list: the ACL, its entries and its policy",
      code == 0 and 'cli-acl: 10.9.0.0/16, key "cli-key"' in out
      and "policy: members may update _acme-challenge.web.lan.test (TXT)" in out, out)
before = config_files()
for argv, code_want, why, ids in (
        (("acl",), 2, "required", "cli:acl"),
        (("acl", "list", "extra"), 2, "unrecognized arguments", "cli:acl.list"),
        (("acl", "add", "cli-acl", "not-an-address", "--no-apply"), 1, "not an IP, CIDR", "cli:acl.add"),
        (("acl", "add", "any", "10.0.0.1", "--no-apply"), 1, "invalid ACL name 'any'", "cli:acl.add"),
        (("acl", "add", "cli-acl", "key ghost", "--no-apply"), 1, "no TSIG key named 'ghost'", "cli:acl.add"),
        (("acl", "remove", "ghost-acl", "--no-apply"), 1, "no ACL named 'ghost-acl'", "cli:acl.remove"),
        (("acl", "remove", "cli-acl", "10.1.1.1", "--no-apply"), 1, "'10.1.1.1' is not in 'cli-acl'", "cli:acl.remove"),
        (("acl", "policy", "cli-acl", "--record", "web", "--any-name", "--no-apply"), 1,
         "give --record host (repeatable) or --any-name", "cli:acl.policy"),
        (("acl", "policy", "cli-acl", "--record", "bad host!", "--no-apply"), 1, "invalid record names",
         "cli:acl.policy"),
        (("acl", "policy", "ghost-acl", "--clear", "--no-apply"), 1, "ACL 'ghost-acl' has no update policy",
         "cli:acl.policy")):
    code, out = fabricctl(*argv)
    # covers: cli:acl cli:acl.list cli:acl.add cli:acl.remove cli:acl.policy -
    check(f"refused: fabricctl {' '.join(argv)} ({ids}): exit {code_want}, says why, nothing changed",
          code == code_want and why in out and config_files() == before, (code, out[-300:]))
code, out = fabricctl("acme", "info", "--deploy-base", W)      # this test install, never the host's /opt
# covers: cli:acme +
check("fabricctl acme info: the ACME directory and the names it signs",
      code == 0 and "https://ca.lan.test/acme/acme/directory" in out and ".lan.test" in out, (code, out))
for argv, ids in ((("acme", "info", "extra"), "cli:acme.info"), (("acme", "list", "--all"), "cli:acme.list")):
    code, out = fabricctl(*argv, "--deploy-base", W)
    # covers: cli:acme.info cli:acme.list -
    check(f"refused: fabricctl {' '.join(argv)} ({ids}): exit 2 with the usage", code == 2
          and "usage: fabricctl acme info" in out, (code, out[-300:]))
code, out = fabricctl("client-cert")
# covers: cli:client-cert -
check("refused: fabricctl client-cert without a user: exit 2 with the usage naming <user>",
      code == 2 and "fabricctl client-cert <user>" in out, (code, out[-300:]))
code, out = fabricctl("--client-cert")
# covers: cli:--client-cert -
check("refused: the old --client-cert with no user: the same usage (exit 2), no traceback (2.3.1.15)",
      code == 2 and "fabricctl client-cert <user>" in out and "Traceback" not in out, (code, out[-300:]))
code, out = fabricctl("acl", "remove", "cli-acl", "--no-apply")
check("acl remove: the whole ACL and its policy go", code == 0 and "cli-acl: removed" in out
      and "cli-acl" not in config_files()[0], (code, out))

# ---------------------------------------------------------------- fabricctl --mint-certs (asks on stdin)
print("--- fabricctl --mint-certs (the installed command, answering its questions)")
before = config_files()
code, out = fabricctl("--mint-certs", answers="\n")
# covers: ask:mint_certs.cn -
check("refused: no Common Name (exit 1, says why), nothing recorded",
      code == 1 and "Common Name is required" in out and config_files() == before, (code, out[-300:]))
code, out = fabricctl("--mint-certs", answers="\n".join(["kept.lan.test", "", "30", T, "RSA", "2048", "n"]) + "\n")
# covers: ask:mint_certs.confirm -
check("answering no at the confirmation: cancelled, nothing recorded or minted",
      code == 0 and "Cancelled" in out and config_files() == before and not os.path.exists(f"{T}/kept-lan-test.crt"),
      (code, out[-300:]))
# each answer checked before anything is written (2.3.1.15): refused with why, exit 1, vars.yaml and the folder as they were
for bad, answers, says in (
        ("days", ["bad.lan.test", "", "abc", T, "RSA", "2048", "y"], "whole number of days"),
        ("out_dir", ["bad.lan.test", "", "30", "/nonexistent-dir", "RSA", "2048", "y"], "No such directory"),
        ("key_type", ["bad.lan.test", "", "30", T, "DSA", "2048", "y"], "Key type must be one of RSA, EC, OKP"),
        ("key_size", ["bad.lan.test", "", "30", T, "RSA", "big", "y"], "whole number of bits")):
    code, out = fabricctl("--mint-certs", answers="\n".join(answers) + "\n")
    # covers: ask:mint_certs.days ask:mint_certs.out_dir ask:mint_certs.key_type ask:mint_certs.key_size cli:--mint-certs -
    check(f"refused: a bad {bad} answer says why, exits 1, records and mints nothing",
          code == 1 and says in out and "Traceback" not in out and config_files() == before
          and not os.path.exists(f"{T}/bad-lan-test.crt"), (code, out[-300:]))
code, out = fabricctl("--mint-certs", answers="\n".join(["minted.lan.test", "minted", "192.168.7.77", "", "30", T,
                                                          "RSA", "2048", "y"]) + "\n")
minted = f"{T}/minted-lan-test.crt"
mt = text_of(open(minted).read()) if os.path.exists(minted) else ""
# covers: cli:--mint-certs +
# covers: ask:mint_certs.cn ask:mint_certs.san ask:mint_certs.days ask:mint_certs.out_dir ask:mint_certs.key_type +
# covers: ask:mint_certs.key_size ask:mint_certs.confirm +
check("--mint-certs: the answers make a 2048-bit RSA leaf with its SANs, in the directory given, recorded in "
      "extra_certs, chaining to the root",
      code == 0 and mt and verifies(open(minted).read()) and "DNS:minted" in mt and "IP Address:192.168.7.77" in mt
      and "Public-Key: (2048 bit)" in mt and os.path.exists(f"{T}/minted-lan-test.key")
      and any(e.get("cn") == "minted.lan.test" and e.get("days") == 30
              for e in yaml.safe_load(config_files()[0]).get("extra_certs") or []), (code, out[-600:]))

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

print("--- the landing page's certificate follows the zone (landing.py)")
land = subprocess.run([sys.executable, os.path.join(REPO, "tests", "pki", "landing.py")], capture_output=True,
                      text=True)
print("\n".join(line for line in land.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or land.stdout[-2000:] + land.stderr[-2000:])
check("landing certificate: landing.py passed", land.returncode == 0, land.stderr[-400:])

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
