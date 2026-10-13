#!/usr/bin/env python3
"""SSH certificates for the fabric admins (manual 1.6.11.9; decisions 2.1.7.5, 2.1.6.39, 2.1.7.12), against the real
pinned OpenBao image on a private test network, initialised and unsealed through its API, with fabric's own
fabric-setup policy given to a real AppRole (the credentials file approle_login reads):

- turning them on through fabric-agent's route: the SSH engine, an Ed25519 CA made inside OpenBao, the signing role;
  the setting saved, the CA's public key published for the machines; converging again changes nothing
- a fabric admin's public key signed: an 8-hour user certificate naming only that person, signed by that CA
  (ssh-keygen -L), audited; the overview the SSH page shows
- refused: a person outside the fabric admins (audited), a private key, DSA, RSA under 3072 bits, two keys, root
  without a person, anything while off; a setup policy without the SSH engine says to run the vault step
- turning them off: nothing can be signed, the published key withdrawn, the CA kept (on again: the same key)

The membership check (Samba's fabric-admins, in-chain) is stood in for here; tests/samba/run.py runs the real one, and
the lab's linux_join test signs in to a joined machine with a certificate.

    sudo python3 tests/openbao/ssh_ca.py          (needs Docker, openssl, ssh-keygen, root)

Status: written for 0.9, not run yet (owner's direction of 2026-10-12; notes 2.3.7.3).
"""
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402
from fabriclib.vault.common.approle_login import approle_login  # noqa: E402
from fabriclib.vault.common.bao_request import bao_request  # noqa: E402
from fabriclib.vault.constants import POLICIES  # noqa: E402
from fabriclib.vault.ssh import sign_ssh_key as ssk  # noqa: E402
from fabriclib.vault.ssh.ssh_overview import ssh_overview  # noqa: E402

W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/sshca"
NET, SUBNET, BAO_IP, BAO, HOST = "sshca_net", "10.254.46.0/24", "10.254.46.90", "sshca-bao", "vault.lan.test"
FAILED = 0
AUDIT = []
ssk.write_audit = lambda actor, event, detail, source="web", **kw: AUDIT.append((actor, event, detail))
ADMINS = {"alice"}


def admin_check(v, user):
    """Stands in for the directory's in-chain fabric-admins check."""
    return user in ADMINS


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout}{res.stderr}")
    return res


def cleanup():
    sh(["docker", "rm", "-f", BAO], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def refused(fn, *args, match="", **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {match!r}: {exc}")
    return False


cleanup()
shutil.rmtree(W, ignore_errors=True)
certs, keys = os.path.join(W, "certs"), os.path.join(W, "keys")
os.makedirs(certs)
os.makedirs(keys, mode=0o700)
sh(f"cd {certs} && openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root_ca.crt -days 2 "
   "-subj '/CN=Test Root' -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign")
sh(f"cd {certs} && openssl req -newkey rsa:2048 -nodes -keyout bao.key -out bao.csr -subj '/CN={HOST}' && "
   f"printf 'subjectAltName=DNS:{HOST}\\nextendedKeyUsage=serverAuth\\n' > bao.ext && openssl x509 -req -in bao.csr "
   "-CA root_ca.crt -CAkey root.key -CAcreateserial -out bao.crt -days 2 -extfile bao.ext && chmod 644 bao.key")
os.makedirs(os.path.join(W, "config"))
with open(os.path.join(W, "config", "test.hcl"), "w") as f:
    f.write('storage "inmem" {}\ndisable_mlock = true\nui = false\n'
            'listener "tcp" {\n  address = "0.0.0.0:8200"\n  tls_cert_file = "/openbao/certs/bao.crt"\n'
            '  tls_key_file = "/openbao/certs/bao.key"\n}\n')
lock = read_images_lock(os.path.join(REPO, "config"))
sh(["docker", "network", "create", "--subnet", SUBNET, NET])
sh(["docker", "run", "-d", "--name", BAO, "--network", NET, "--ip", BAO_IP, "--entrypoint", "bao",
    "-v", f"{certs}:/openbao/certs:ro", "-v", f"{W}/config:/openbao/config:ro", lock["openbao"]["ref"],
    "server", "-config=/openbao/config/test.hcl"])
V = {"ip_openbao": BAO_IP, "hostname_openbao": HOST, "openbao_ca_file": os.path.join(certs, "root_ca.crt"),
     "openbao_key_dir": keys, "deploy_base_dir": W, "site_name": "lab",
     "service_users": {"nginx": {"uid": 0, "gid": 0}}, "ssh_certificates": False}
for _ in range(30):
    try:
        if bao_request(V, "GET", "sys/health")[0] in (200, 429, 472, 473, 501, 503):
            break
    except ValidationError:
        pass
    time.sleep(1)
init = bao_request(V, "POST", "sys/init", body={"secret_shares": 1, "secret_threshold": 1})[1]
bao_request(V, "POST", "sys/unseal", body={"key": init["keys"][0]})
ROOT = init["root_token"]


def approle(name, policy_name, policy):
    """A real AppRole with one policy, its credentials where approle_login reads them (root 0400)."""
    bao_request(V, "PUT", f"sys/policies/acl/{policy_name}", token=ROOT, body={"policy": policy})
    bao_request(V, "POST", f"auth/approle/role/{name}", token=ROOT, body={"token_policies": [policy_name],
                                                                          "token_ttl": "15m"})
    role_id = bao_request(V, "GET", f"auth/approle/role/{name}/role-id", token=ROOT)[1]["data"]["role_id"]
    secret_id = bao_request(V, "POST", f"auth/approle/role/{name}/secret-id", token=ROOT)[1]["data"]["secret_id"]
    path = os.path.join(keys, f"{name}-approle.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "w") as f:
        json.dump({"role_id": role_id, "secret_id": secret_id}, f)


bao_request(V, "POST", "sys/auth/approle", token=ROOT, body={"type": "approle"})
approle("setup", "fabric-setup", POLICIES["fabric-setup"])
old_policy = "\n".join(line for line in POLICIES["fabric-setup"].splitlines() if not line.startswith('path "ssh/'))
approle("old", "fabric-setup-0-8", old_policy)                    # setup's policy before 0.9

# ---------------------------------------------------------------- fabric-agent, from the installed tree
print("--- fabric-agent from the installed tree (a root peer names the actor)")
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)
os.makedirs(f"{W}/fabric/config", exist_ok=True)
with open(f"{W}/fabric/config/vars.yaml", "w") as f:
    yaml.safe_dump(V, f)
SOCK = f"{W}/agent.sock"
agent = subprocess.Popen([sys.executable, f"{W}/fabric/lib/agent/server.py", "--socket", SOCK, "--socket-gid", "0"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
for _ in range(100):
    if os.path.exists(SOCK):
        break
    time.sleep(0.1)


def agent_call(method, path, body=None):
    raw = json.dumps({"actor": "alice", **(body or {})}).encode() if method == "POST" else b""
    s = socket.socket(socket.AF_UNIX)
    s.connect(SOCK)
    s.sendall(f"{method} {path} HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n"
              .encode() + raw)
    out = b""
    while chunk := s.recv(65536):
        out += chunk
    s.close()
    head, _, payload = out.partition(b"\r\n\r\n")
    return int(head.split()[1]), json.loads(payload or b"null")


def saved():
    return yaml.safe_load(open(f"{W}/fabric/config/vars.yaml"))


PUB = os.path.join(W, "nginx", "www", "certs", "ssh-user-ca.pub")
st, res = agent_call("GET", "/v1/ssh")
# covers: agent:get.ssh +
check("off by default: GET /v1/ssh says off, no key, nobody may sign, why",
      st == 200 and res["on"] is False and res["public_key"] == "" and res["may_sign"] is False
      and "off" in res["why_not"], (st, res))
st, res = agent_call("POST", "/v1/ssh/on")
# covers: agent:post.ssh.on setting:ssh_certificates +
check("POST /v1/ssh/on: the engine, an Ed25519 CA, the role; the setting saved true; the key published (0644)",
      st == 200 and res["on"] and res["changed"] and res["public_key"].startswith("ssh-ed25519 ")
      and saved()["ssh_certificates"] is True and open(PUB).read().strip() == res["public_key"]
      and oct(os.stat(PUB).st_mode & 0o777) == "0o644"
      and "ssh/" in bao_request(V, "GET", "sys/mounts", token=ROOT)[1].get("data", {}), (st, res))
CA_KEY, CA_FP = res.get("public_key", ""), res.get("fingerprint", "")
role = bao_request(V, "GET", "ssh/roles/fabric-admin", token=ROOT)[1].get("data", {})
check("the role: user certificates only, 8 hours at most, permit-pty, no host certificates",
      role.get("allow_user_certificates") is True and role.get("allow_host_certificates") is False
      and role.get("max_ttl") in (28800, "8h") and "permit-pty" in json.dumps(role.get("default_extensions")), role)
st, res = agent_call("POST", "/v1/ssh/on")
check("on again: converged, nothing changed, the same CA", st == 200 and res["changed"] is False
      and res["public_key"] == CA_KEY, (st, res))
check("status lists ssh_certificates as on (a relaxation shown while it is)",
      any(r["setting"] == "ssh_certificates: true" for r in relaxed_settings(saved())), relaxed_settings(saved()))

# ---------------------------------------------------------------- signing
print("--- signing a fabric admin's key")
v_on = {**V, "ssh_certificates": True}
os.makedirs(f"{W}/user", mode=0o700)
sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "alice@laptop", "-f", f"{W}/user/id_ed25519"])
alice_pub = open(f"{W}/user/id_ed25519.pub").read()
cert = ssk.sign_ssh_key(v_on, "alice", alice_pub, admin_check=admin_check)
open(f"{W}/user/id_ed25519-cert.pub", "w").write(cert["certificate"] + "\n")
shown = sh(["ssh-keygen", "-L", "-f", f"{W}/user/id_ed25519-cert.pub"], ok=False).stdout
principals = shown.split("Principals:")[1].split("Critical Options:")[0].split() if "Principals:" in shown else []
valid = shown.split("Valid:")[1].splitlines()[0] if "Valid:" in shown else ""
# covers: agent:post.ssh.sign +
check("signed: a user certificate, principal alice only, the key id names her, signed by fabric's CA, audited",
      "user certificate" in shown and principals == ["alice"] and 'Key ID: "fabric:alice:' in shown
      and CA_FP in shown and AUDIT[-1][:2] == ("alice", "SSH_SIGN"), shown)
check("valid 8 hours (from - to)", cert["valid_hours"] == 8 and valid.count("T") == 2, valid)
ov = ssh_overview(v_on, "alice", admin_check=admin_check)
check("the SSH page for alice: on, the CA key and fingerprint, may sign",
      ov["on"] and ov["public_key"] == CA_KEY and ov["fingerprint"] == CA_FP and ov["may_sign"], ov)
ov = ssh_overview(v_on, "bob", admin_check=admin_check)
check("...for bob: may not, and says why", not ov["may_sign"] and "only fabric admins" in ov["why_not"], ov)

print("--- refusals")
# covers: agent:post.ssh.sign -
check("negative: bob is not a fabric admin: refused, audited SSH_SIGN_REFUSED",
      refused(ssk.sign_ssh_key, v_on, "bob", alice_pub, admin_check=admin_check, match="only fabric admins")
      and AUDIT[-1][:2] == ("bob", "SSH_SIGN_REFUSED"))
check("negative: root, not a person: refused",
      refused(ssk.sign_ssh_key, v_on, "root", alice_pub, admin_check=admin_check, match="for a person"))
check("negative: a private key pasted: refused, never echoed",
      refused(ssk.sign_ssh_key, v_on, "alice", open(f"{W}/user/id_ed25519").read(), admin_check=admin_check,
              match="private key"))
sh(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", f"{W}/user/id_rsa"])
check("negative: RSA under 3072 bits: refused",
      refused(ssk.sign_ssh_key, v_on, "alice", open(f"{W}/user/id_rsa.pub").read(), admin_check=admin_check,
              match="3072"))
check("negative: a DSA key: refused", refused(ssk.sign_ssh_key, v_on, "alice", "ssh-dss AAAAB3NzaC1kc3MAAACBAP== x",
                                              admin_check=admin_check, match="not signed"))
check("negative: two keys at once: refused", refused(ssk.sign_ssh_key, v_on, "alice", alice_pub + alice_pub,
                                                    admin_check=admin_check, match="one public key"))
check("negative: a certificate instead of a key: refused",
      refused(ssk.sign_ssh_key, v_on, "alice", cert["certificate"], admin_check=admin_check, match="not signed"))
st, res = agent_call("POST", "/v1/ssh/sign", {"public_key": "nonsense"})
check("negative: the agent's route refuses what is not a key (400, says why)", st == 400 and "public key" in
      res.get("error", ""), (st, res))

print("--- an OpenBao whose setup policy predates SSH certificates")
from fabriclib.vault.ssh import set_ssh_certificates as ssc  # noqa: E402
ssc.load_vars, ssc.save_vars = (lambda: dict(V)), (lambda data: None)
ssc.write_audit = lambda *a, **k: None
ssc.vars_lock = contextlib.nullcontext
check("negative: says to run the vault step; nothing saved",
      refused(ssc.set_ssh_certificates, "alice", True, login=lambda v, creds: approle_login(v, "old-approle.json"),
              publish=lambda v, key: None, match="--step vault"))

# ---------------------------------------------------------------- off
print("--- turning them off")
st, res = agent_call("POST", "/v1/ssh/off")
# covers: agent:post.ssh.off +
check("POST /v1/ssh/off: the role deleted, the key withdrawn, the setting saved false, the CA kept",
      st == 200 and res["on"] is False and not os.path.exists(PUB) and saved()["ssh_certificates"] is False
      and bao_request(V, "GET", "ssh/roles/fabric-admin", token=ROOT)[0] == 404
      and bao_request(V, "GET", "ssh/config/ca", token=ROOT)[1].get("data", {}).get("public_key", "").strip() == CA_KEY,
      (st, res))
check("negative: off: nothing is signed", refused(ssk.sign_ssh_key, V, "alice", alice_pub, admin_check=admin_check,
                                                  match="off"))
st, res = agent_call("POST", "/v1/ssh/sign", {"public_key": alice_pub})
check("negative: off: the agent's route refuses too (400)", st == 400 and "off" in res.get("error", ""), (st, res))
st, res = agent_call("POST", "/v1/ssh/off")
check("off again: nothing changed", st == 200 and res["changed"] is False, (st, res))
st, res = agent_call("POST", "/v1/ssh/on")
check("on again: the same CA, so machines need nothing new", st == 200 and res["public_key"] == CA_KEY, (st, res))
bao_request(V, "POST", "sys/seal", token=ROOT)
before = saved()
st, res = agent_call("POST", "/v1/ssh/off")
# covers: agent:post.ssh.off agent:post.ssh.on -
check("negative: OpenBao sealed: off refused (400, says why), the setting and the published key unchanged",
      st == 400 and saved() == before and os.path.exists(PUB), (st, res))
st, res = agent_call("POST", "/v1/ssh/on")
check("negative: OpenBao sealed: on refused too", st == 400, (st, res))
os.remove(f"{W}/fabric/config/vars.yaml")
st, res = agent_call("GET", "/v1/ssh")
# covers: agent:get.ssh -
check("negative: GET /v1/ssh without the settings is an error, not 'off'", st >= 400, (st, res))

agent.terminate()
agent.wait()
cleanup()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
