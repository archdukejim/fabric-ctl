#!/usr/bin/env python3
"""Federation invitations and joining (manual 1.9, M3) with the real Step-CA image:

an upstream ("hq") enables nothing but what the code needs here: its root CA (made with the pinned step
CLI), its vars and secrets files, the federation endpoint's Handler (lib/federation/server.py) behind TLS
with a certificate from that root, and a plain-HTTP certificates page. A site ("branch1") joins it with
join_upstream exactly as `fabricctl setup --join` does. Includes what must be refused.

    sudo python3 tests/federation/run.py         (needs Docker, openssl, root)
"""
import base64
import http.client
import http.server
import json
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/federation"
IMAGE = subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
                       capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def step(home, *args):
    return sh(["docker", "run", "--rm", "--network", "none", "-v", f"{home}:/home/step", "--user",
               f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, *args])


def refused(fn, *args, match="", **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {match!r}: {exc}")
    return False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------- the upstream: tree, root CA, vars
shutil.rmtree(W, ignore_errors=True)
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)     # the installed tree
# config/VERSION is set on the release candidate's branch (2.1.1.40), so this branch's tree still says the release
# before it; the upstream here is 0.8.0's, whose invitations a site accepts (2.1.6.65's revision)
with open(f"{W}/fabric/VERSION", "w") as f:
    f.write("0.8.0\n")
os.makedirs(f"{W}/fabric/config")
data = f"{W}/hq/stepca/data"
for d in ("certs", "secrets", "artifacts"):
    os.makedirs(f"{data}/{d}")
with open(f"{data}/secrets/password", "w") as f:
    f.write("Root-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/hq"])
step(data, "certificate", "create", "Fed Test Root CA", "/home/step/certs/root_ca.crt", "/home/step/secrets/root_ca_key",
     "--profile", "root-ca", "--password-file", "/home/step/secrets/password")
FED_HOST = "federation.hq.test"
step(data, "certificate", "create", FED_HOST, "/home/step/fed.crt", "/home/step/fed.key", "--profile", "leaf",
     "--ca", "/home/step/certs/root_ca.crt", "--ca-key", "/home/step/secrets/root_ca_key",
     "--ca-password-file", "/home/step/secrets/password", "--no-password", "--insecure", "--san", FED_HOST)
step(data, "certificate", "create", "evil.test", "/home/step/evil.crt", "/home/step/evil.key", "--profile", "leaf",
     "--ca", "/home/step/certs/root_ca.crt", "--ca-key", "/home/step/secrets/root_ca_key",
     "--ca-password-file", "/home/step/secrets/password", "--no-password", "--insecure", "--san", "evil.test")
ROOT_PEM = open(f"{data}/certs/root_ca.crt").read()

HTTP_PORT, HTTPS_PORT, EVIL_PORT = free_port(), free_port(), free_port()
HQ = {"deploy_base_dir": f"{W}/hq", "image_stepca": IMAGE, "service_users": {"step": {"uid": STEP_UID, "gid": STEP_UID}},
      "site_name": "hq", "domain": "hq.test", "org_domain": "hq.test", "ldap_base_dn": "dc=lan", "host_ip": "127.0.0.1",
      "ldap_organizational_units": [{"name": "accounts"}, {"name": "users", "parent": "accounts"}, {"name": "groups"}],
      "hostname_federation": FED_HOST, "federation_endpoint": False, "cert_intermediate_days": 1095,
      "friendly_name": "Fed Test Org", "cert_org": "Fed Test Org", "cert_country": "US",
      "ad_domain": "ad.hq.test", "hostname_dc": "hq.ad.hq.test", "ad_password_policy": {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0, "maximum_age_days": 0, "lockout_threshold": 5, "lockout_minutes": 15, "lockout_window_minutes": 15}}


def save_hq(**changes):
    HQ.update(changes)
    with open(f"{W}/fabric/config/vars.yaml", "w") as f:
        yaml.safe_dump(HQ, f)


save_hq()
sys.path.insert(0, f"{W}/fabric/lib")
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.federation.accept_join import accept_join  # noqa: E402
from fabriclib.federation.create_invitation import create_invitation  # noqa: E402
from fabriclib.federation.decode_invitation import decode_invitation  # noqa: E402
from fabriclib.federation.federation_status import federation_status  # noqa: E402
from fabriclib.federation.join_upstream import join_upstream  # noqa: E402
from fabriclib.federation.list_invitations import list_invitations  # noqa: E402
from fabriclib.federation.revoke_invitation import revoke_invitation  # noqa: E402
from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
sys.path.insert(0, f"{W}/fabric/lib/federation")
import server as fed_server  # noqa: E402

fed_server.Handler.after_join = None          # no apply: this is not an install

# the root's domain step of a join (prepare_site: converge the new site in its DC) needs a DC, which these protocol
# tests do not run: it is recorded instead (the real one: tests/samba/site_join.py)
import fabriclib.federation.accept_join as m_accept  # noqa: E402
PREPARED = []
m_accept.prepare_site = lambda v, site, networks, dc, dc_type, accounts, password, container="samba": \
    PREPARED.append((site, dc, sorted(accounts))) or []
m_accept.domain_sites = lambda container="samba": []      # the domain's DC records: no site moving here
DC_NAMES = {"dcs": ["dc-0001"], "computers": ["dc-0001", "hq"]}     # the root's DC and its host only
m_accept.domain_dc_names = lambda container="samba": DC_NAMES

SECRETS = f"{W}/fabric/config/fabric-secrets.yml"

# ---------------------------------------------------------------- invitations
# covers: setting:federation_endpoint +
check("invite: refused while the endpoint is off",
      refused(create_invitation, HQ, "alice", "branch1", match="endpoint is off"))
save_hq(federation_endpoint=True)
inv = create_invitation(HQ, "alice", "branch1")
body = decode_invitation(inv["invitation"])
check("invite: decodes to the site, the endpoint and the root's fingerprint",
      body["site"] == "branch1" and body["host"] == FED_HOST and body["address"] == "127.0.0.1"
      and body["root_sha256"] == describe_cert(ROOT_PEM)["sha256"] and body["org_domain"] == "hq.test"
      and body["ldap_base_dn"] == "dc=lan", body)
stored = open(SECRETS).read()
check("invite: only a hash of the secret is kept", body["secret"] not in stored and "sha256" in stored)
check("invite: the secret is not in the audit log", body["secret"] not in open(f"{W}/fabric/archive/audit.log").read())
check("invite: listed as open", [i["site"] for i in list_invitations(HQ)] == ["branch1"])
check("invite: this site's own name refused", refused(create_invitation, HQ, "alice", "hq", match="own name"))
check("invite: invalid site name refused", refused(create_invitation, HQ, "alice", "Bad_Site", match="invalid site"))
check("invite: an organisation OU as site name refused (ou=groups,dc=lan is taken)",
      refused(create_invitation, HQ, "alice", "groups", match="directory OU of the organisation"))
check("decode: not an invitation refused", refused(decode_invitation, "hello", match="not a fabric invitation"))
check("decode: a damaged invitation refused", refused(decode_invitation, inv["invitation"][:-9] + "!!!!", match="damaged"))
forged = json.loads(base64.urlsafe_b64decode(inv["invitation"].split(".", 1)[1] + "==="))
forged["address"] = "not-an-ip"
forged_text = "fabric-join-1." + base64.urlsafe_b64encode(json.dumps(forged).encode()).decode()
check("decode: a bad field refused", refused(decode_invitation, forged_text, match="bad address"))
inv_b2 = create_invitation(HQ, "alice", "branch2")
check("revoke: by site name", revoke_invitation(HQ, "alice", "branch2") == 1
      and "branch2" not in [i["site"] for i in list_invitations(HQ)])
check("revoke: nothing open refused", refused(revoke_invitation, HQ, "alice", "branch2", match="no open invitation"))
old = create_invitation(HQ, "alice", "branch3", now=time.time() - 7200)
check("invite: an expired invitation is not listed", "branch3" not in [i["site"] for i in list_invitations(HQ)])


# ---------------------------------------------------------------- the upstream's endpoint and certs page
class TLSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, cert, key):
        super().__init__(addr, fed_server.Handler)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)

    def get_request(self):
        sock, addr = super().get_request()
        return self.ctx.wrap_socket(sock, server_side=True), addr


os.makedirs(f"{W}/www/certs")
shutil.copy(f"{data}/certs/root_ca.crt", f"{W}/www/certs/root-ca.crt")
web = socketserver.TCPServer(("127.0.0.1", HTTP_PORT),
                             lambda *a: http.server.SimpleHTTPRequestHandler(*a, directory=f"{W}/www"))
tls = TLSServer(("127.0.0.1", HTTPS_PORT), f"{data}/fed.crt", f"{data}/fed.key")
evil = TLSServer(("127.0.0.1", EVIL_PORT), f"{data}/evil.crt", f"{data}/evil.key")
for srv in (web, tls, evil):
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def raw(method, path, body=b"", port=HTTPS_PORT):
    ctx = ssl.create_default_context(cadata=ROOT_PEM)
    ctx.check_hostname = False                 # the test talks to 127.0.0.1; join_upstream checks the name
    c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=60)
    c.request(method, path, body=body, headers={"Content-Type": "application/json"})
    r = c.getresponse()
    return r.status, r.read().decode()


st, page = raw("GET", "/v1/health")
check("endpoint: health answers with this site", st == 200 and json.loads(page)["site"] == "hq", (st, page))
check("endpoint: unknown paths are 404", raw("GET", "/v1/secrets")[0] == 404 and raw("POST", "/v1/admin")[0] == 404)
check("endpoint: a body that is not JSON is refused", raw("POST", "/v1/join", b"not json")[0] == 400)
check("endpoint: an oversized body is refused", raw("POST", "/v1/join", b"x" * 20000)[0] == 413)
st, page = raw("POST", "/v1/join", json.dumps({"id": body["id"], "secret": "x" * 43, "site": "branch1", "csr": "x",
                                                "domain": "branch1.hq.test", "address": "127.0.0.2"}).encode())
check("endpoint: a wrong secret is refused, without saying why", st == 400 and "not valid" in page, (st, page))
check("endpoint: the refusal is audited", "FED_JOIN_REFUSED" in open(f"{W}/fabric/archive/audit.log").read())

# ---------------------------------------------------------------- a site joins
SITE = {"image_stepca": IMAGE, "service_users": {"step": {"uid": STEP_UID, "gid": STEP_UID}}}
B1 = f"{W}/branch1"
os.makedirs(f"{B1}/config")
J = dict(config_dir=f"{B1}/config", audit_path=f"{B1}/audit.log", http_port=HTTP_PORT, https_port=HTTPS_PORT)

bad_pin = dict(forged, address="127.0.0.1", root_sha256="AA:" + body["root_sha256"][3:])
bad_pin_text = "fabric-join-1." + base64.urlsafe_b64encode(json.dumps(bad_pin).encode()).decode()
check("join: a root other than the pinned one is refused before anything is sent",
      refused(join_upstream, SITE, bad_pin_text, "Site-Pw-1", f"{B1}/site-ca", "branch1.hq.test", "127.0.0.2",
              **J, match="not the one in the invitation"))
check("join: an endpoint whose certificate does not name the federation host is refused",
      refused(join_upstream, SITE, inv["invitation"], "Site-Pw-1", f"{B1}/site-ca", "branch1.hq.test", "127.0.0.2",
              **dict(J, https_port=EVIL_PORT), match="cannot reach"))
check("join: the upstream's own domain is refused for a site",
      refused(join_upstream, SITE, inv["invitation"], "Site-Pw-1", f"{B1}/site-ca", "hq.test", "127.0.0.2", **J,
              match="cannot use this site's domain"))
check("join: an invitation for another site refused (branch1's used as branch9)",
      refused(accept_join, HQ, {"id": body["id"], "secret": body["secret"], "site": "branch9", "csr": "x",
                                "domain": "b9.hq.test", "address": "127.0.0.9"}, match="made for site branch1"))
check("join: an expired invitation is refused",
      refused(accept_join, HQ, {**{k: decode_invitation(old["invitation"])[k] for k in ("id", "secret", "site")},
                                "csr": "x", "domain": "b3.hq.test", "address": "127.0.0.3"}, match="not valid"))

SITE["hostname"] = "branch1"
# the upstream's version (2.1.6.65's revision): carried by the invitation; one older than 0.8.0, or none (an older
# upstream's), refused before anything is made, sent or staged, here and in setup --join
check("invite: the invitation carries the upstream's version", body.get("version") == "0.8.0", body.get("version"))


def _with_version(text, version):
    doc = json.loads(base64.urlsafe_b64decode(text.split(".", 1)[1] + "==="))
    doc.pop("version", None)
    if version is not None:
        doc["version"] = version
    return "fabric-join-1." + base64.urlsafe_b64encode(json.dumps(doc).encode()).decode()


import io  # noqa: E402
import types  # noqa: E402

import fabriclib.setup.collect_vars as m_cv  # noqa: E402
from fabriclib.setup.errors import SetupError as _SetupError  # noqa: E402
for label, version in (("0.7.2", "0.7.2"), ("no version (an older upstream's)", None)):
    old_text, work = _with_version(inv["invitation"], version), f"{W}/old-upstream-{label[:5]}"
    os.makedirs(f"{work}/config")
    # covers: cli:setup -
    check(f"negative: an invitation from an upstream of {label} is refused before anything is made or sent, saying "
          "to upgrade the upstream first",
          refused(join_upstream, SITE, old_text, "Site-Pw-1", f"{work}/site-ca", "branch1.hq.test", "127.0.0.2",
                  **dict(J, config_dir=f"{work}/config", audit_path=f"{work}/audit.log"),
                  match="Upgrade the upstream first")
          and not os.path.exists(f"{work}/site-ca") and not os.path.exists(f"{work}/config/federation.yaml")
          and "branch1" in [i["site"] for i in list_invitations(HQ)])
    try:
        m_cv._join_defaults(types.SimpleNamespace(join_invitation=old_text, config_dir=f"{work}/config",
                                                  vars_file=f"{work}/config/vars.yaml"), {})
        said = "accepted"
    except _SetupError as e:
        said = str(e)
    check(f"negative: setup --join with it stops at once, before any question or step ({label})",
          "Upgrade the upstream first" in said and "nothing was sent or changed" in said, said)
check("decode: an invitation's version must be text", refused(decode_invitation, _with_version(inv["invitation"], 8),
                                                              match="bad version"))
res = join_upstream(SITE, inv["invitation"], "Site-Pw-1", f"{B1}/site-ca", "branch1.hq.test", "127.0.0.2", **J)
jv = res["vars"]
check("join: the site gets the bring-your-own-CA settings and the organisation",
      res["joined"] and jv["byoc"] and jv["site_name"] == "branch1" and jv["org_domain"] == "hq.test"
      and jv["ldap_base_dn"] == "dc=lan"
      and jv["cert_org"] == "Fed Test Org" and all(os.path.isfile(jv[k]) for k in ("ca_crt_path", "ica_crt_path",
                                                                                    "ica_key_path")), res)
dom = res.get("domain") or {}
check("join: the root prepares the site and its DC in its domain and answers with it (a writable DC, the range its "
      "name gives it, the join account, the DC's service accounts' passwords)",
      dom.get("ad_domain") == "ad.hq.test" and dom.get("dc_type") == "writable" and dom.get("join_user") == "fabric-join-branch1"
      and sorted(dom.get("accounts") or {}) == ["agent", "keycloak", "radius"] and PREPARED
      and PREPARED[0][:2] == ("branch1", "dc-0002") and dom.get("id_range") == "2000000-2999999", (dom, PREPARED))
# covers: setting:dc_name +
check("join: the upstream names the joining site's DC, the lowest number the domain does not have (dc-0002: dc-0001 "
      "is the root's), in the join's answer; nobody gave a name (2.1.6.65)",
      dom.get("dc_name") == "dc-0002" and res.get("dc_name") == "dc-0002", (dom.get("dc_name"), res.get("dc_name")))
site_ca = open(jv["ica_crt_path"]).read()
check("join: the site's CA is signed by the organisation's root, path length 0",
      sh(["openssl", "verify", "-CAfile", jv["ca_crt_path"], jv["ica_crt_path"]], ok=False).returncode == 0
      and "pathlen:0" in sh(["openssl", "x509", "-in", jv["ica_crt_path"], "-noout", "-text"]).stdout)
check("join: the site's key never left it (only the request travelled)",
      "PRIVATE" not in open(f"{W}/fabric/archive/issued-certs.jsonl").read()
      and "ENCRYPTED" in open(jv["ica_key_path"]).read(80))
hq_reg = yaml.safe_load(open(f"{W}/fabric/config/federation.yaml"))
check("join: the upstream records the site", hq_reg["sites"]["branch1"]["domain"] == "branch1.hq.test"
      and hq_reg["sites"]["branch1"]["address"] == "127.0.0.2", hq_reg)
b1_reg = yaml.safe_load(open(f"{B1}/config/federation.yaml"))
check("join: the site records its upstream", b1_reg["upstream"]["site_name"] == "hq"
      and b1_reg["upstream"]["root_sha256"] == body["root_sha256"], b1_reg)
check("join: both sides record the DC's name the upstream gave (so it is never given twice, and a re-run keeps it)",
      hq_reg["sites"]["branch1"].get("dc_name") == "dc-0002" and b1_reg["upstream"].get("dc_name") == "dc-0002",
      (hq_reg["sites"]["branch1"], b1_reg["upstream"]))
check("join: the invitation is used up", "branch1" not in [i["site"] for i in list_invitations(HQ)])
hq_keys = yaml.safe_load(open(SECRETS)).get("federation_tsig") or {}
check("join: both sites hold the DNS link's TSIG key (the upstream in its secrets, never in the registry)",
      res.get("dns_secret") and hq_keys.get("branch1") == res["dns_secret"]
      and b1_reg["upstream"]["dns_key"] == "fed-branch1" and res["dns_secret"] not in open(f"{B1}/config/federation.yaml").read(),
      (hq_keys.keys(), b1_reg["upstream"].get("dns_key")))
check("join: audited on both sides", "FED_JOIN " in open(f"{W}/fabric/archive/audit.log").read()
      and "FED_JOINED" in open(f"{B1}/audit.log").read())
st, page = raw("POST", "/v1/join", json.dumps({"id": body["id"], "secret": body["secret"], "site": "branch1",
                                                "csr": "x", "domain": "branch1.hq.test", "address": "127.0.0.2"}).encode())
check("join: the same invitation cannot be used twice", st == 400 and "not valid" in page, (st, page))
check("invite: a site that joined cannot be invited again",
      refused(create_invitation, HQ, "alice", "branch1", match="joined already"))
s = federation_status(HQ)
check("status: the upstream lists its site", s["role"] == "upstream" and "branch1" in s["sites"] and s["endpoint"], s)

tls.shutdown()
again = join_upstream(SITE, inv["invitation"], "Site-Pw-1", f"{B1}/site-ca", "branch1.hq.test", "127.0.0.2", **J)
check("join: a re-run (setup repeated) reuses what was staged, without the network, and the DC's given name",
      again["joined"] is False and again["vars"] == jv and again["dc_name"] == "dc-0002", again)

# setup's join step: the joining site saves the upstream's name for its DC and joins under it (2.1.6.65)
import contextlib  # noqa: E402

import fabriclib.setup.join_federation as m_jf  # noqa: E402
for answer in (res, again):
    m_jf.join_upstream = lambda *a, answer=answer, **k: answer
    jctx = types.SimpleNamespace(join_invitation=inv["invitation"], secrets={"ca_password": "Site-Pw-1"},
                                 secrets_file=f"{B1}/config/fabric-secrets.yml", config_dir=f"{B1}/config",
                                 source_dir=os.path.join(REPO, "src"),
                                 vars={"domain": "branch1.hq.test", "host_ip": "127.0.0.2", "image_stepca": IMAGE,
                                       "hostname": "branch1"},
                                 path=lambda *p: os.path.join(B1, *p))
    said = io.StringIO()
    with contextlib.redirect_stdout(said):
        m_jf.run(jctx)
    # covers: cli:setup +
    check(f"setup's join step ({'first join' if answer is res else 're-run'}): the site's dc_name is the upstream's, "
          "dc-0002, before its DC joins; the output names no DC", jctx.vars.get("dc_name") == "dc-0002"
          and "dc-0" not in said.getvalue(), (jctx.vars.get("dc_name"), said.getvalue()))
    if answer is res:                    # the first join carries the domain's answer; a re-run reuses what was staged
        said_first = said.getvalue()
check("setup's join step says how many DCs the domain has after the join and how many can be added, not which",
      dom.get("dc_count") == 2 and "2 DCs used, 1997 can be added" in said_first, (dom.get("dc_count"), said_first))

# an older joiner (before 0.8.0) names its own DC and lays the directory out by sites: refused before anything is
# prepared, whatever name it gives (0.8.0 has no upgrade, 2.1.1.60, 2.1.6.86)
import fabriclib.federation.accept_join as m_accept2  # noqa: E402
real_sign = m_accept2.sign_site_ca
m_accept2.sign_site_ca = lambda *a, **k: {"root": ROOT_PEM, "cert": "", "chain": "",
                                          "info": {"serial": "01", "not_after": "2099-01-01"}}
inv_old = decode_invitation(create_invitation(HQ, "alice", "branch4")["invitation"])
OLD = {"id": inv_old["id"], "secret": inv_old["secret"], "site": "branch4", "csr": "x", "domain": "branch4.hq.test",
       "address": "127.0.0.4"}
try:
    prepared_before = list(PREPARED)
    # covers: setting:dc_name -
    check("negative: a joiner older than 0.8.0 (it names its own DC: a free name, a taken one, an invalid one) is "
          "refused, saying to install 0.8.0 there; nothing prepared, the invitation kept",
          all(refused(accept_join, HQ, {**OLD, "dc_name": name}, match="older than 0.8.0")
              for name in ("DC-Barn", "HQ", "dc-0002", "not_valid"))
          and PREPARED == prepared_before and "branch4" in [i["site"] for i in list_invitations(HQ)]
          and "branch4" not in yaml.safe_load(open(f"{W}/fabric/config/federation.yaml"))["sites"])
    try:
        accept_join(HQ, {**OLD, "dc_name": "HQ"})
    except ValidationError as e:
        check("…the refusal names neither the domain's DCs nor fabric's scheme", "dc-0001" not in str(e)
              and "dc-0002" not in str(e) and "hq," not in str(e).lower(), str(e))
finally:
    m_accept2.sign_site_ca = real_sign
# the 2000th DC: the join refused with the cap's message before anything is prepared, the invitation kept
inv_cap = decode_invitation(create_invitation(HQ, "alice", "branch5")["invitation"])
DC_NAMES["computers"] = [f"dc-{n:04d}" for n in range(1, 2000)]
prepared_before = list(PREPARED)
check("negative: a join past dc-1999 is refused, saying the domain has the most DCs it may have (naming no DC); "
      "nothing prepared, the invitation kept (2.1.6.63)",
      refused(accept_join, HQ, {"id": inv_cap["id"], "secret": inv_cap["secret"], "site": "branch5", "csr": "x",
                                "domain": "branch5.hq.test", "address": "127.0.0.5"},
              match="the most domain controllers it may have")
      and PREPARED == prepared_before and "branch5" in [i["site"] for i in list_invitations(HQ)]
      and "branch5" not in yaml.safe_load(open(f"{W}/fabric/config/federation.yaml"))["sites"], PREPARED)
DC_NAMES["computers"] = ["dc-0001", "hq"]
inv_other = create_invitation(dict(HQ, site_name="hq2"), "alice", "branch1x")
check("join: a node that joined one upstream refuses another's invitation",
      refused(join_upstream, SITE, inv_other["invitation"], "Site-Pw-1", f"{B1}/site-ca", "branch1.hq.test",
              "127.0.0.2", **J, match="already joined"))

# ---------------------------------------------------------------- setup --join never takes the invitation from argv
import io  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.read_join_invitation import read_join_invitation  # noqa: E402
try:
    read_join_invitation(inv["invitation"])
    inline = False
except SetupError as e:
    inline = "command line" in str(e)
check("setup --join: the invitation itself on the command line is refused", inline)
with open(f"{W}/inv.txt", "w") as f:
    f.write(inv["invitation"] + "\n")
check("setup --join @FILE reads it", read_join_invitation(f"@{W}/inv.txt") == inv["invitation"])
_stdin, sys.stdin = sys.stdin, io.StringIO(inv["invitation"])
try:
    check("setup --join - reads it from stdin", read_join_invitation("-") == inv["invitation"])
finally:
    sys.stdin = _stdin
try:
    read_join_invitation(f"@{W}/missing.txt")
    missing = False
except SetupError as e:
    missing = "cannot read" in str(e)
check("setup --join @FILE: a missing file is refused", missing)

# ---------------------------------------------------------------- remove: the site, its record and its DNS key go
from fabriclib.federation.remove_site import remove_site  # noqa: E402
removed = remove_site("alice", "branch1", v=HQ)
check("remove: the site's record and its DNS link key are gone",
      removed.get("domain") == "branch1.hq.test" and "branch1" not in yaml.safe_load(open(f"{W}/fabric/config/federation.yaml"))["sites"]
      and "branch1" not in (yaml.safe_load(open(SECRETS)).get("federation_tsig") or {}))
check("remove: an unknown site is refused", refused(remove_site, "alice", "branch1", v=HQ, match="no site branch1"))

# ---------------------------------------------------------------- the unix socket accepts only listed uids
sock_path = f"{W}/fed.sock"
srv = fed_server.UnixServer(sock_path, fed_server.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def over_socket():
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall(b"GET /v1/health HTTP/1.0\r\n\r\n")
    out = b""
    try:
        while chunk := s.recv(4096):
            out += chunk
    except ConnectionResetError:          # refused peers are cut off
        pass
    return out.decode(errors="replace")


fed_server.UnixServer.allowed_uids = {0}
check("socket: root (a listed uid) is answered", " 200 " in over_socket().splitlines()[0])
fed_server.UnixServer.allowed_uids = {12345}
check("socket: an unlisted uid gets nothing", over_socket() == "")
srv.shutdown()
for s_ in (web, evil):
    s_.shutdown()

# ---------------------------------------------------------------- DNS between sites (two real BIND servers)
print("--- DNS between sites (dns.py)")
dnst = subprocess.run([sys.executable, os.path.join(REPO, "tests", "federation", "dns.py")], capture_output=True, text=True)
print("\n".join(line for line in dnst.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or dnst.stdout[-2000:] + dnst.stderr[-2000:])
check("DNS between sites: dns.py passed", dnst.returncode == 0, dnst.stderr[-400:])

# ---------------------------------------------------------------- nested sites and re-parenting (own installs)
print("--- nested sites (nested.py)")
nested = subprocess.run([sys.executable, os.path.join(REPO, "tests", "federation", "nested.py")], capture_output=True,
                        text=True)
print("\n".join(line for line in nested.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
      or nested.stdout[-2000:] + nested.stderr[-2000:])
check("nested sites: nested.py passed", nested.returncode == 0, nested.stderr[-400:])

for title, cmd in (("the address plan's rules (address_plan.py)",
                    [sys.executable, os.path.join(REPO, "tests", "federation", "address_plan.py")]),):
    print(f"--- {title}")
    part = subprocess.run(cmd, capture_output=True, text=True)
    print("\n".join(line for line in part.stdout.splitlines() if line.startswith(("PASS", "FAIL")))
          or part.stdout[-2000:] + part.stderr[-2000:])
    check(f"{title} passed", part.returncode == 0, (part.stdout + part.stderr)[-400:])

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
