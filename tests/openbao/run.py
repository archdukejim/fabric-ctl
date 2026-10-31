#!/usr/bin/env python3
"""OpenBao against the real, pinned image, started from fabric's own compose
template and config: the vault key and its unlock methods (key file, USB
stick on a loop device, security key on SoftHSM2, HSM on a PyKMIP server),
static-seal auto-unseal, init, idempotent configuration, least-privilege
AppRoles and people's policies, break glass, root token revocation, fabric's
secrets moved into OpenBao, rotation, tampering, the kill switch, what
happens when the key goes missing, and hardening.

    sudo python3 tests/openbao/run.py          (needs Docker, openssl, root)
"""
import atexit
import contextlib
import getpass
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
# openbao is the product's name (fabric's health and status read it): one such run at a time
# (manual 3.1.2.6), and only this run's is removed
LOCK = testrun.product_names_lock("openbao").__enter__()
from fabriclib.common.jinja_env import jinja_env  # noqa: E402  (the environment deploy renders with)
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/openbao"
NET, SUBNET, IP = testrun.name("obtest_net"), f"{testrun.PREFIX}.19.0/24", f"{testrun.PREFIX}.19.90"   # its own range: suites may run back to back
HOST = "vault.lan.test"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout}{res.stderr}")
    return res


def health(timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        st = sh("docker inspect -f '{{.State.Health.Status}}' openbao", ok=False).stdout.strip()
        if st in ("healthy", "unhealthy"):
            return st
        time.sleep(2)
    return st


def compose(*args):
    return sh(["docker", "compose", *testrun.compose_files(f"{W}/openbao/docker-compose.yml", "openbao"), *args], ok=False)


# ---------------------------------------------------------------- layout
testrun.remove("container", "openbao")      # this run's only
testrun.remove("network", NET)
shutil.rmtree(W, ignore_errors=True)
for d in ("stepca/data/certs", "openbao/config", "openbao/data", "openbao/logs", "openbao/certs"):
    os.makedirs(f"{W}/{d}")
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)   # the installed tree
os.chdir(W)
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 2 -subj '/CN=Test Root' "
   "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign")
sh(f"openssl req -newkey rsa:2048 -nodes -keyout bao.key -out bao.csr -subj '/CN={HOST}'")
open("bao.ext", "w").write(f"subjectAltName=DNS:{HOST},DNS:openbao\nextendedKeyUsage=serverAuth,clientAuth\n")
sh("openssl x509 -req -in bao.csr -CA root.crt -CAkey root.key -CAcreateserial -out bao.crt -days 2 -extfile bao.ext")
shutil.copy("root.crt", "stepca/data/certs/root_ca.crt")
shutil.copy("bao.crt", "openbao/certs/fullchain.pem")
shutil.copy("bao.key", "openbao/certs/privkey.pem")
shutil.copy("root.crt", "openbao/certs/root_ca.crt")
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 2 -subj '/CN=Other Root'")

V = {"deploy_base_dir": W, "domain": "lan.test", "hostname_openbao": HOST, "ip_openbao": IP, "ip_bind9": f"{testrun.PREFIX}.19.30",
     "openbao_key_dir": f"{W}/keys", "openbao_runtime_dir": f"{W}/run", "openbao_seal_key_id": "fabric-1",
     "openbao_udev_rules": f"{W}/90-fabric-unlock.rules", "openbao_admin_dir": f"{W}/admin",
     "openbao_mem_limit": "256m",
     "fabric_subnet": SUBNET, "service_users": {"openbao": {"uid": 913, "gid": 913}},
     "image_openbao": sh([sys.executable, f"{REPO}/tests/image_ref.py", "openbao"]).stdout.strip()}
env = jinja_env(f"{REPO}/templates")
for tpl, dest in (("docker-compose.yml.j2", "openbao/docker-compose.yml"), ("openbao.hcl.j2", "openbao/config/openbao.hcl")):
    text = env.from_string(open(f"{REPO}/templates/openbao/{tpl}").read()).render(**V)
    open(dest, "w").write(text.replace("name: fabric_net", f"name: {NET}"))
sh(["chown", "-R", "913:913", "openbao/data", "openbao/logs"])
sh(["chmod", "-R", "a+rX", "openbao/config", "openbao/certs"])
sh(["chown", "913:913", "openbao/certs/privkey.pem"])
sh(["chmod", "0400", "openbao/certs/privkey.pem"])
testrun.create_network(NET, SUBNET)

# from here fabriclib is the installed tree's, so its paths (archive/, config/) are this install's, never the
# checkout's: the copy imported from src/ above, only to render, is dropped
sys.path.remove(os.path.join(REPO, "src"))
for _mod in [m for m in sys.modules if m == "fabriclib" or m.startswith("fabriclib.")]:
    del sys.modules[_mod]
sys.path.insert(0, f"{W}/fabric/lib")
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.vault.common.approle_login import approle_login  # noqa: E402
from fabriclib.vault.common.bao_request import bao_request  # noqa: E402
from fabriclib.vault.configure_openbao import configure_openbao  # noqa: E402
from fabriclib.vault.add_kmip_slot import add_kmip_slot  # noqa: E402
from fabriclib.vault.add_security_key_slot import add_security_key_slot  # noqa: E402
from fabriclib.vault.common.kmip_session import kmip_session  # noqa: E402
from fabriclib.vault.add_usb_slot import add_usb_slot  # noqa: E402
from fabriclib.vault.common.obtain_key import obtain_key  # noqa: E402
from fabriclib.vault.list_pkcs11_tokens import list_pkcs11_tokens  # noqa: E402
from fabriclib.vault.slots import pkcs11  # noqa: E402
from fabriclib.vault.common.read_slot_store import read_slot_store  # noqa: E402
from fabriclib.vault.vault_device_event import vault_device_event  # noqa: E402
from fabriclib.vault.ensure_vault_key import ensure_vault_key  # noqa: E402
from fabriclib.vault.list_slots import list_slots  # noqa: E402
from fabriclib.vault.remove_slot import remove_slot  # noqa: E402
from fabriclib.vault.rotate_vault_key import rotate_vault_key  # noqa: E402
from fabriclib.vault.test_slot import test_slot  # noqa: E402
from fabriclib.vault.unlock_vault import unlock_vault  # noqa: E402
from fabriclib.vault.wipe_runtime_keys import wipe_runtime_keys  # noqa: E402
from fabriclib.vault.generate_root_token import generate_root_token  # noqa: E402
from fabriclib.vault.init_openbao import init_openbao  # noqa: E402
from fabriclib.vault.revoke_token import revoke_token  # noqa: E402
from fabriclib.vault.vault_status import vault_status  # noqa: E402
from fabriclib.secrets.common.write_vault_secrets import write_vault_secrets  # noqa: E402
from fabriclib.secrets.export_secrets import export_secrets  # noqa: E402
from fabriclib.secrets.import_secrets import import_secrets  # noqa: E402
from fabriclib.secrets.load_secrets import load_secrets  # noqa: E402
from fabriclib.secrets.save_secrets import save_secrets  # noqa: E402
from fabriclib.secrets.secrets_in_openbao import secrets_in_openbao  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
import fabriclib.vault.run_vault_command as rvc  # noqa: E402


def raises(fn, text):
    try:
        fn()
        return False
    except ValidationError as exc:
        return text in str(exc)


class _Tty(io.StringIO):
    """stdin that is a terminal: the commands then ask (ask_secret) instead of reading stdin."""
    def isatty(self):
        return True


def vault_cli(*argv, stdin="", answers=None, v=None):
    """`fabricctl vault …` as the CLI routes it, in this process: (exit status, stdout, stderr, prompts asked).
    answers: what a person types at each hidden prompt (stdin is then a terminal; getpass stands in for the
    keyboard, as the consent suite answers setup's questions); otherwise stdin is piped from `stdin`. Secrets go
    in this way only, never on the command line, and nothing captured is printed."""
    out, err, asked = io.StringIO(), io.StringIO(), []
    real_stdin, real_getpass = sys.stdin, getpass.getpass
    if answers is not None:
        typed = iter(answers)

        def keyboard(prompt=""):
            asked.append(prompt)
            return next(typed)
        getpass.getpass = keyboard
        sys.stdin = _Tty()
    else:
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rvc.run_vault_command(V if v is None else v, list(argv))
    finally:
        sys.stdin, getpass.getpass = real_stdin, real_getpass
    return code, out.getvalue(), err.getvalue(), asked


def slot_ids():
    return [sl["id"] for sl in read_slot_store(V)["slots"]]


def usage_refused(*argv):
    """A form the command does not take: refused with the usage on stderr, exit 2, nothing on stdout."""
    code, out, err, _ = vault_cli(*argv)
    return code == 2 and err.startswith("usage: fabricctl vault") and not out


SECRETS = f"{W}/fabric/config/fabric-secrets.yml"
os.makedirs(os.path.dirname(SECRETS), exist_ok=True)

# ---------------------------------------------------------------- vault key and unlock methods
fresh = dict(V, openbao_key_dir=f"{W}/fresh-keys", deploy_base_dir=f"{W}/fresh")
check("fresh install: a random vault key in a key-file unlock method", ensure_vault_key(fresh) == "created"
      and [sl["type"] for sl in read_slot_store(fresh)["slots"]] == ["local"])
check("the install under test: a vault key made, in its key-file unlock method", ensure_vault_key(V) == "created"
      and os.path.exists(f"{W}/keys/local-fabric-1.key"))
legacy = open(f"{W}/keys/local-fabric-1.key", "rb").read()     # the first key (rotated below)
st = os.stat(f"{W}/keys/slots.json")
kst = os.stat(f"{W}/keys/local-fabric-1.key")
# covers: setting:openbao_key_dir +
check("store root 0600, key file root 0400, folder root 0700",
      (st.st_uid, oct(st.st_mode & 0o777)) == (0, "0o600") and (kst.st_uid, oct(kst.st_mode & 0o777)) == (0, "0o400")
      and oct(os.stat(f"{W}/keys").st_mode & 0o777) == "0o700")
# covers: setting:openbao_seal_key_id +
check("seal.hcl names the vault key; OpenBao never sees the key folder",
      'current_key_id = "fabric-1"' in open(f"{W}/openbao/config/seal.hcl").read()
      and "/keys" not in open(f"{W}/openbao/docker-compose.yml").read())
check("an existing store is never replaced", ensure_vault_key(V) == "present")
# covers: setting:openbao_runtime_dir +
check("fabric-unlock: the key goes to RAM for the openbao user only", unlock_vault(V)["slot"] == "local"
      and os.stat(f"{W}/run/fabric-1.key").st_uid == 913 and oct(os.stat(f"{W}/run/fabric-1.key").st_mode & 0o777) == "0o400"
      and open(f"{W}/run/fabric-1.key", "rb").read() == legacy)
key_bytes = legacy


def start(action="restart"):
    """What systemd does: fabric-unlock (start condition), start, wipe once unsealed."""
    if not unlock_vault(V):
        return False
    compose(action) if action != "up" else compose("up", "-d")
    ok_ = health() == "healthy"
    wipe_runtime_keys(V)
    return ok_


# ---------------------------------------------------------------- container
up = compose("up", "-d")
check("compose file starts the pinned image", up.returncode == 0, up.stderr[-400:])
if up.returncode != 0:
    print(sh("docker logs openbao", ok=False).stderr[-1500:])
check("fresh (uninitialised) server counts as healthy", health() == "healthy", sh("docker logs openbao", ok=False).stderr[-600:])
s = vault_status(V)
check("status before init: reachable, not initialised", s["reachable"] and not s["initialized"], s)
try:
    bao_request({**V, "openbao_ca_file": f"{W}/other.crt"}, "GET", "sys/health")
    tls_ok = False
except ValidationError:
    tls_ok = True
check("TLS is verified: a server cert from another CA is refused", tls_ok)

# ---------------------------------------------------------------- init + configure
check("init asked for a threshold above the share count: OpenBao refuses it, nothing initialised",
      raises(lambda: init_openbao({**V, "openbao_recovery_shares": 1, "openbao_recovery_threshold": 2}),
             "OpenBao init failed") and not vault_status(V)["initialized"])
V["openbao_recovery_shares"], V["openbao_recovery_threshold"] = 3, 2     # break glass then needs two of three
first = init_openbao(V)
# covers: setting:openbao_recovery_shares +
check("init returns the recovery keys openbao_recovery_shares asks for (3) and a root token",
      first and len(first["recovery_keys"]) == 3 and first["root_token"], first)
check("init is not repeated", init_openbao(V) is None)
check("static seal: unsealed without anyone entering a key", not vault_status(V)["sealed"] and health() == "healthy")
check("once unsealed the key is wiped from RAM; OpenBao keeps working", wipe_runtime_keys(V) == 1
      and not os.listdir(f"{W}/run") and not vault_status(V)["sealed"])
changes = configure_openbao(V, first["root_token"])
check("configuration applied", {"AppRole auth", "KV fabric/", "KV apps/"} <= set(changes), changes)
for name in ("setup-approle.json", "agent-approle.json"):
    st = os.stat(f"{W}/keys/{name}")
    check(f"{name}: root-only 0400", st.st_uid == 0 and oct(st.st_mode & 0o777) == "0o400")
setup_token = approle_login(V, "setup-approle.json")
check("re-run as fabric-setup (not root) changes nothing", configure_openbao(V, setup_token) == [])
check("root token revoked after bootstrap", revoke_token(V, first["root_token"]))
check("revoked root token is refused",
      bao_request(V, "GET", "sys/mounts", token=first["root_token"])[0] == 403)

# ---------------------------------------------------------------- break glass + the policy for people
try:
    generate_root_token(V, "tester", ["bm90IGEgcmVjb3Zlcnkga2V5"], source="test")
    bad_refused = False
except ValidationError:
    bad_refused = bao_request(V, "GET", "sys/generate-root/attempt", admin=True)[1].get("started") is False
check("break glass: a wrong recovery key is refused and the attempt cancelled", bad_refused)
check("generate-root stays off on the network listener (OpenBao's default)",
      bao_request(V, "GET", "sys/generate-root/attempt")[0] == 405)
glass = generate_root_token(V, "tester", first["recovery_keys"], source="test")
check("break glass: the recovery keys give a working root token",
      bao_request(V, "GET", "auth/token/lookup-self", token=glass)[1].get("data", {}).get("policies") == ["root"])
bao_request(V, "POST", "fabric/data/glass-probe", token=glass, body={"data": {"v": "fabric-only"}})
person = bao_request(V, "POST", "auth/token/create", token=glass,
                     body={"policies": ["fabric-console-admin"], "ttl": "5m"})[1]["auth"]["client_token"]
check("people (fabric-console-admin): their applications' secrets, read and write",
      bao_request(V, "POST", "apps/data/team/db", token=person, body={"data": {"pw": "x"}})[0] == 200
      and bao_request(V, "GET", "apps/data/team/db", token=person)[0] == 200)
check("people: fabric's own secrets are listed, never read",
      "glass-probe" in bao_request(V, "LIST", "fabric/metadata", token=person)[1].get("data", {}).get("keys", [])
      and bao_request(V, "GET", "fabric/data/glass-probe", token=person)[0] == 403
      and bao_request(V, "POST", "fabric/data/glass-probe", token=person, body={"data": {"v": "x"}})[0] == 403)
check("people: configuration readable, not writable",
      bao_request(V, "GET", "sys/policies/acl/fabric-console-admin", token=person)[0] == 200
      and bao_request(V, "PUT", "sys/policies/acl/fabric-console-admin", token=person, body={"policy": ""})[0] == 403
      and bao_request(V, "POST", "sys/auth/userpass", token=person, body={"type": "userpass"})[0] == 403)
auditor = bao_request(V, "POST", "auth/token/create", token=glass,
                      body={"policies": ["fabric-auditor"], "ttl": "5m"})[1]["auth"]["client_token"]
check("auditor bundle: application secrets listed (metadata), never read or written",
      "team/" in bao_request(V, "LIST", "apps/metadata", token=auditor)[1].get("data", {}).get("keys", [])
      and bao_request(V, "GET", "apps/data/team/db", token=auditor)[0] == 403
      and bao_request(V, "POST", "apps/data/team/db", token=auditor, body={"data": {"pw": "y"}})[0] == 403)
bao_request(V, "DELETE", "fabric/metadata/glass-probe", token=glass)
check("break glass: the root token is revoked after use", revoke_token(V, glass))

# fabricctl vault break-glass / revoke-token: keys and tokens asked hidden or read from stdin, never argv
admin_compose = open(f"{W}/openbao/docker-compose.yml").read()
# covers: setting:openbao_admin_dir +
check("openbao_admin_dir: the break-glass socket is there, mounted into OpenBao; another folder reaches nothing",
      stat.S_ISSOCK(os.stat(f"{W}/admin/bao.sock").st_mode) and f"{W}/admin:/openbao/admin" in admin_compose
      and raises(lambda: bao_request({**V, "openbao_admin_dir": f"{W}/nowhere"}, "GET", "sys/generate-root/attempt",
                                     admin=True), "not reachable"))


def attempt_open():
    return bao_request(V, "GET", "sys/generate-root/attempt", admin=True)[1].get("started")


k = first["recovery_keys"]
code, out, err, asked = vault_cli("break-glass", answers=[k[0], ""])
# covers: cli:vault.break-glass ask:vault.recovery_key -
check("vault break-glass: one recovery key typed of the two the threshold needs -> refused, attempt cancelled",
      code == 1 and "error: 1 of 2 recovery keys given" in err and not out and not attempt_open()
      and asked == ["recovery key 1 (empty line when done): ", "recovery key 2 (empty line when done): "], (err, asked))
code, out, err, _ = vault_cli("break-glass", stdin="bm90IGEgcmVjb3Zlcnkga2V5\nYW5kIG5laXRoZXIgaXMgdGhpcw==\n")
check("vault break-glass: wrong recovery keys on stdin are refused, no token shown, attempt cancelled",
      code == 1 and "error: recovery key refused" in err and "ROOT TOKEN" not in out and not attempt_open(), err)
code, out, err, asked = vault_cli("break-glass", answers=[k[2], k[0], ""])
glass = out.splitlines()[1].strip() if code == 0 and len(out.splitlines()) > 1 else ""
# covers: cli:vault.break-glass ask:vault.recovery_key setting:openbao_recovery_threshold +
check("vault break-glass: two of the three recovery keys typed (hidden) -> a working root token, shown once",
      code == 0 and out.startswith("ROOT TOKEN") and len(asked) == 3 and glass
      and bao_request(V, "GET", "auth/token/lookup-self", token=glass)[1].get("data", {}).get("policies") == ["root"],
      err)
bao_request(V, "PUT", "sys/policies/acl/lookup-only", token=glass,
            body={"policy": 'path "auth/token/lookup-self" { capabilities = ["read"] }'})
sticky = bao_request(V, "POST", "auth/token/create", token=glass,
                     body={"policies": ["lookup-only"], "no_default_policy": True, "ttl": "5m"})[1]["auth"]["client_token"]
code, out, err, asked = vault_cli("revoke-token", answers=[sticky])
# covers: cli:vault.revoke-token ask:vault.root_token -
check("vault revoke-token: a token that may not revoke itself -> refused (still works), never reported revoked",
      code == 1 and "error: the token still works (or OpenBao refused): not revoked" in err and "revoked" not in out
      and asked == ["token: "] and bao_request(V, "GET", "auth/token/lookup-self", token=sticky)[0] == 200, err)
bao_request(V, "POST", "auth/token/revoke", token=glass, body={"token": sticky})
bao_request(V, "DELETE", "sys/policies/acl/lookup-only", token=glass)
code, out, err, asked = vault_cli("revoke-token", answers=[glass])
# covers: cli:vault.revoke-token ask:vault.root_token +
check("vault revoke-token: the break-glass token typed (hidden) is revoked and refused from then on",
      code == 0 and out.strip() == "revoked" and asked == ["token: "]
      and bao_request(V, "GET", "auth/token/lookup-self", token=glass)[0] == 403, err)

agent = approle_login(V, "agent-approle.json")
check("fabric-agent may read the engine list", bao_request(V, "GET", "sys/mounts", token=agent)[0] == 200)
check("fabric-agent may not write app secrets",
      bao_request(V, "POST", "apps/data/x", token=agent, body={"data": {"a": "b"}})[0] == 403)
check("fabric-agent may not read fabric's secrets", bao_request(V, "GET", "fabric/data/x", token=agent)[0] == 403)
check("fabric-agent may not write policies",
      bao_request(V, "PUT", "sys/policies/acl/evil", token=agent, body={"policy": 'path "*" {capabilities=["sudo"]}'})[0] == 403)
check("fabric-setup may write fabric's secrets",
      bao_request(V, "POST", "fabric/data/probe", token=setup_token, body={"data": {"v": "1"}})[0] == 200)
role = bao_request(V, "GET", "auth/approle/role/fabric-agent", token=setup_token)[1]["data"]
check("AppRole tokens and secret IDs are bound to fabric_net", role["token_bound_cidrs"] == [SUBNET]
      and role["secret_id_bound_cidrs"] == [SUBNET], role)
s = vault_status(V)
check("status: unsealed, static seal, raft, KV v2 fabric/ + apps/, approle, key ok",
      s["initialized"] and not s["sealed"] and s["seal_type"] == "static" and s["storage"] == "raft"
      and {"fabric/", "apps/"} <= {m["path"] for m in s["mounts"] if m["version"] == "2"} and "approle/" in s["auth"]
      and s["key"]["ok"], s)
code, out, err, _ = vault_cli()
# covers: cli:vault +
check("fabricctl vault (no subcommand): the status — unsealed, static seal, raft — exit 0",
      code == 0 and "unsealed  (static seal, raft storage)" in out and "fabric/" in out, (out, err))
# covers: cli:vault -
check("fabricctl vault <unknown>: refused with the usage, exit 2", usage_refused("unseal"))
# covers: cli:vault.slots -
check("vault slots takes no argument: refused with the usage", usage_refused("slots", "local"))
code, out, err, _ = vault_cli("test", "nosuch")
# covers: cli:vault.test -
check("vault test: a method that does not exist is refused, says which", code == 1 and
      "error: no unlock method 'nosuch'" in err and not out, err)
code, out, err, _ = vault_cli("remove", "local", "--yes")
# covers: cli:vault.remove -
check("vault remove: the last unlock method is refused and stays", code == 1 and
      "error: the last working unlock method cannot be removed" in err and slot_ids() == ["local"], err)
check("vault remove without --yes: refused with the usage, nothing removed",
      usage_refused("remove", "local") and slot_ids() == ["local"])
code, out, err, _ = vault_cli("add-kmip", "127.0.0.1:5696", "--key-id", "1", "--label", "x", "--yes")
# covers: cli:vault.add-kmip -
check("vault add-kmip without its certificates: refused, says which are missing, nothing saved",
      code == 1 and "error: missing --ca, --cert, --key" in err and slot_ids() == ["local"], err)
code, out, err, _ = vault_cli("rotate-db", v={**V, "install_keycloak": True})
rot = json.load(open(f"{W}/fabric/archive/db-rotation.json")) if os.path.exists(f"{W}/fabric/archive/db-rotation.json") \
    else {}
# covers: cli:vault.rotate-db -
check("vault rotate-db: OpenBao has no database engine here -> refused, the old password keeps working, recorded",
      code == 1 and "error: OpenBao did not rotate it" in err and "the old password keeps working" in err
      and rot.get("ok") is False and not os.path.exists(SECRETS), err)
bao_ip = sh("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' openbao").stdout.strip()
elsewhere = vault_status({**V, "ip_openbao": f"{testrun.PREFIX}.19.91"})
# covers: setting:ip_openbao +
check("ip_openbao: OpenBao's container has that address and fabric reaches it there (not elsewhere)",
      bao_ip == IP and vault_status(V)["reachable"] and not elsewhere["reachable"]
      and f"not reachable at {testrun.PREFIX}.19.91" in elsewhere.get("error", ""), (bao_ip, elsewhere))
alias, other_name = vault_status({**V, "hostname_openbao": "openbao"}), \
    vault_status({**V, "hostname_openbao": "elsewhere.lan.test"})
# covers: setting:hostname_openbao +
check("hostname_openbao: the name its certificate is checked for, and the address shown",
      alias["reachable"] and alias["url"] == "https://openbao/" and not other_name["reachable"]
      and "certificate" in other_name.get("error", "").lower(), (alias, other_name))


def cnames(node):
    if isinstance(node, dict):
        return ([node] if set(node) == {"canonical", "name"} else []) + [c for x in node.values() for c in cnames(x)]
    return [c for x in node for c in cnames(x)] if isinstance(node, list) else []


named = yaml.safe_load(jinja_env(f"{W}/fabric/jinja").get_template("vars.yaml.j2").render(
    domain="lan.test", hostname="h", host_ip="10.0.0.5", lan_cidr="10.0.0.0/24", lan_gateway="10.0.0.1",
    cname_openbao="bao"))
# covers: setting:cname_openbao +
check("cname_openbao: OpenBao's name becomes bao.<domain> and a CNAME bao -> the host is published",
      named["hostname_openbao"] == "bao.lan.test" and {"canonical": "h", "name": "bao"} in cnames(named)
      and {"canonical": "h", "name": "vault"} not in cnames(named), named.get("hostname_openbao"))
# ---------------------------------------------------------------- fabric's secrets into OpenBao
ORIGINAL = {"ca_password": "Ca-pw-1", "rndc_secret": "cm5kYy1zZWNyZXQ=", "ad_agent_password": "Da1",
            "tsig_secrets": {"npm": "bnBtLXNlY3JldA=="}}
with open(SECRETS, "w") as f:
    yaml.safe_dump(ORIGINAL, f)
os.chmod(SECRETS, 0o600)
check("before the import: secrets come from the 0600 file", load_secrets(SECRETS, V) == ORIGINAL
      and not secrets_in_openbao(SECRETS))
check("import: written, read back, identical", import_secrets(V, SECRETS, setup_token) == "imported")
check("import: the plaintext file is gone and the marker says OpenBao holds them",
      not os.path.exists(SECRETS) and secrets_in_openbao(SECRETS))
check("after the import: the same secrets come from OpenBao", load_secrets(SECRETS, V) == ORIGINAL)
v1 = vault_status(V)["secrets"]["version"]
save_secrets({"tsig_secrets": {"nas": "bmFzLXNlY3JldA=="}}, SECRETS, V)
after = load_secrets(SECRETS, V)
check("save: a TSIG key added in OpenBao, others untouched, new version",
      after["tsig_secrets"] == {"npm": "bnBtLXNlY3JldA==", "nas": "bmFzLXNlY3JldA=="} and after["ca_password"] == "Ca-pw-1"
      and vault_status(V)["secrets"]["version"] == v1 + 1)
save_secrets({"tsig_secrets": {"npm": None}}, SECRETS, V)
check("save: a TSIG key removed", "npm" not in load_secrets(SECRETS, V)["tsig_secrets"])
ver = vault_status(V)["secrets"]["version"]
save_secrets({"ca_password": "Ca-pw-1"}, SECRETS, V)
check("save without a change writes no new version", vault_status(V)["secrets"]["version"] == ver)
try:
    write_vault_secrets(V, {"x": "y"}, ver - 1, setup_token)
    cas = False
except ValidationError as exc:
    cas = "check-and-set" in str(exc) or "cas" in str(exc).lower()
check("a write based on a stale version is refused (check-and-set)", cas)
check("no plaintext file was recreated by any of this", not os.path.exists(SECRETS))
check("fabric-agent sees the version, never the values",
      bao_request(V, "GET", "fabric/data/secrets", token=approle_login(V, "agent-approle.json"))[0] == 403
      and vault_status(V)["secrets"]["version"] == ver)
open(SECRETS, "w").close()
try:
    import_secrets(V, SECRETS, setup_token)
    empty_refused = False
except ValidationError as exc:
    empty_refused = "empty" in str(exc)
check("an empty secrets file is never imported over the real ones", empty_refused)
os.remove(SECRETS)
check("...and OpenBao still holds them", load_secrets(SECRETS, V)["ca_password"] == "Ca-pw-1")
backup = export_secrets(SECRETS, f"{W}/backup/fabric-secrets.yml", V)
check("export for a reinstall: root-only copy", oct(os.stat(backup).st_mode & 0o777) == "0o600"
      and yaml.safe_load(open(backup))["ca_password"] == "Ca-pw-1")
shutil.copy2(backup, SECRETS)
check("a restored file is used while present", load_secrets(SECRETS, V)["ca_password"] == "Ca-pw-1")
check("...and re-imported: equal to OpenBao, shredded", import_secrets(V, SECRETS, setup_token) == "unchanged"
      and not os.path.exists(SECRETS))

audit = open(f"{W}/openbao/logs/audit.log").read()
check("audit log records requests with secrets HMAC'd", '"path":"fabric/data/probe"' in audit and '"v":"1"' not in audit)

# ---------------------------------------------------------------- restarts, unlock methods, rotation
check("after a restart it unseals itself (fabric-unlock, then wiped)", start() and not vault_status(V)["sealed"]
      and not os.listdir(f"{W}/run"))
code, out, err, _ = vault_cli("unlock")
placed = sorted(os.listdir(f"{W}/run"))
wcode, wout, werr, _ = vault_cli("wipe-key")
# covers: cli:vault.unlock cli:vault.wipe-key +
check("vault unlock (systemd) puts the key in RAM through the key file; vault wipe-key wipes it again",
      code == 0 and out.strip() == "vault key in place (via local)" and placed == ["fabric-1.key"]
      and wcode == 0 and wout.strip() == "wiped 1 key file(s) from RAM" and not os.listdir(f"{W}/run"),
      (out, err, placed, wout, werr))
# covers: cli:vault.wipe-key -
check("vault wipe-key takes no argument: refused with the usage", usage_refused("wipe-key", "now"))
# covers: cli:vault.device-event -
check("vault device-event takes no argument: refused with the usage", usage_refused("device-event", "add"))
check("slot test: the key-file method unwraps the vault key", test_slot(V, "tester", "local", source="test"))
sl = list_slots(V)
check("slot list: type, presence, key version, what it was tested against",
      [(x["type"], x["present"], x["key_id"]) for x in sl] == [("local", True, "fabric-1")] and sl[0]["tested"], sl)
try:
    remove_slot(V, "tester", "local", source="test")
    last = False
except ValidationError as exc:
    last = "last" in str(exc)
check("the last unlock method cannot be removed", last)


def restart_unsealed():
    compose("restart")
    if health() != "healthy" or vault_status(V).get("sealed") is not False:
        raise ValidationError("not unsealed after restart")


res = rotate_vault_key(V, "tester", restart_unsealed, source="test")
store = read_slot_store(V)
check("rotation: new key fabric-2 in every present method, the old copy shredded",
      res["key_id"] == "fabric-2" and res["kept"] == ["local"] and store["key_id"] == "fabric-2"
      and not store.get("previous_key_id") and os.path.exists(f"{W}/keys/local-fabric-2.key")
      and not os.path.exists(f"{W}/keys/local-fabric-1.key"), res)
check("rotation: seal.hcl has only the new key; nothing left in RAM",
      "previous_key" not in open(f"{W}/openbao/config/seal.hcl").read() and not os.listdir(f"{W}/run"))
check("rotation: OpenBao opens with the new key alone, data intact", start() and
      bao_request(V, "GET", "fabric/data/probe", token=approle_login(V, "setup-approle.json"))[1]
      .get("data", {}).get("data") == {"v": "1"})
key_bytes = open(f"{W}/keys/local-fabric-2.key", "rb").read()
check("the new key is not the old one", key_bytes != legacy)

raw = json.load(open(f"{W}/keys/slots.json"))
raw["slots"][0]["label"] = "changed while locked"
open(f"{W}/keys/slots.json", "w").write(json.dumps(raw))
check("a store changed while locked is detected (and still unlocks: the key itself is verified)",
      unlock_vault(V)["tamper"] and "VAULT_SLOTS_TAMPERED" in open(f"{W}/fabric/archive/audit.log").read())
wipe_runtime_keys(V)
raw["slots"][0]["label"] = "Key file on this host"
open(f"{W}/keys/slots.json", "w").write(json.dumps(raw))
check("...and the untouched store verifies again", unlock_vault(V)["tamper"] is False)
wipe_runtime_keys(V)

os.rename(f"{W}/keys/local-fabric-2.key", f"{W}/keys/away.key")
check("no unlock method present: fabric-unlock refuses (systemd then does not start OpenBao)", unlock_vault(V) is None)
code, out, err, _ = vault_cli("unlock")
# covers: cli:vault.unlock -
check("vault unlock with no method present: refused, says OpenBao stays locked, no key in RAM",
      code == 1 and "no unlock method is present: OpenBao stays locked" in err and not out
      and not os.listdir(f"{W}/run"), err)
code, out, err, _ = vault_cli("rotate", "--yes")
# covers: cli:vault.rotate -
check("vault rotate with no method present: refused, says to plug one in; the vault key is unchanged",
      code == 1 and "error: no unlock method is present: plug one in to rotate" in err
      and read_slot_store(V)["key_id"] == "fabric-2" and not read_slot_store(V).get("previous_key_id"), err)
check("vault rotate without --yes: refused with the usage, nothing rotated",
      usage_refused("rotate") and read_slot_store(V)["key_id"] == "fabric-2")
compose("stop")
code, out, err, _ = vault_cli("status")
# covers: cli:vault.status -
check("vault status with OpenBao stopped: says unreachable, exit 1", code == 1 and out.startswith("OpenBao: unreachable"),
      out)
code, out, err, _ = vault_cli("revoke-token", stdin="s.not-a-real-token\n")
check("vault revoke-token with OpenBao stopped: refused, says it is not reachable",
      code == 1 and "error: OpenBao is not reachable" in err and not out, err)
try:
    locked = load_secrets(SECRETS, V)
    locked_ok = False
except ValidationError:
    locked = None
    locked_ok = True
check("OpenBao locked: reading fabric's secrets fails loudly (never an empty set)", locked_ok, locked)
up = compose("start")
time.sleep(8)
check("started anyway without its key (bypassing fabric-unlock): OpenBao refuses to run",
      sh("docker inspect -f '{{.State.Running}}' openbao", ok=False).stdout.strip() != "true"
      or health(30) != "healthy")
os.rename(f"{W}/keys/slots.json", f"{W}/keys/slots.away")
try:
    ensure_vault_key(V)
    refused = False
except ValidationError as exc:
    refused = "restore" in str(exc)
check("no unlock methods next to existing data: a new key is never generated", refused
      and not os.path.exists(f"{W}/keys/slots.json"))
os.rename(f"{W}/keys/slots.away", f"{W}/keys/slots.json")
os.rename(f"{W}/keys/away.key", f"{W}/keys/local-fabric-2.key")
check("method back -> unseals again, data intact", start() and
      bao_request(V, "GET", "fabric/data/probe", token=approle_login(V, "setup-approle.json"))[1]
      .get("data", {}).get("data") == {"v": "1"})
check("the key never changed", open(f"{W}/keys/local-fabric-2.key", "rb").read() == key_bytes)

# ---------------------------------------------------------------- USB stick unlock method (loop device)


def release_sticks():
    """Unmount whatever this run mounted from its stick images and detach their loop devices, also when the run
    stops part way (2.3.1.30: one left attached and mounted outlives the run)."""
    for img in (f"{W}/stick.img", f"{W}/other.img"):
        for dev in [ln.split(":", 1)[0] for ln in sh(["losetup", "-j", img], ok=False).stdout.splitlines()]:
            for point in sh(["findmnt", "-n", "-o", "TARGET", "-S", dev], ok=False).stdout.split():
                sh(["umount", point], ok=False)
            sh(["losetup", "-d", dev], ok=False)


atexit.register(release_sticks)
sh(f"truncate -s 64M {W}/stick.img")
loop = sh(f"losetup --find --show {W}/stick.img").stdout.strip()
sh(f"truncate -s 64M {W}/other.img")
other = sh(f"losetup --find --show {W}/other.img").stdout.strip()
try:
    add_usb_slot(V, "tester", loop, "safe stick", source="test")
    usb_refused = False
except ValidationError as exc:
    usb_refused = "not a USB disk" in str(exc)
check("add USB: anything that is not a USB disk is refused", usb_refused)
code, out, err, _ = vault_cli("add-usb", loop, "--label", "safe stick", "--yes")
# covers: cli:vault.add-usb -
check("vault add-usb: a disk that is not on USB is refused, never erased, nothing saved",
      code == 1 and f"error: {loop} is not a USB disk" in err and not out
      and not any(sl["type"] == "usb" for sl in read_slot_store(V)["slots"])
      and not sh(f"blkid -o value -s UUID {loop}", ok=False).stdout.strip(), err)
check("vault add-usb without --yes: refused with the usage, nothing erased", usage_refused("add-usb", loop))
os.makedirs(f"{W}/mnt", exist_ok=True)
sh(f"mkfs.ext4 -q -F {other}")
sh(f"mount {other} {W}/mnt")
try:
    add_usb_slot(V, "tester", other, "", source="test", require_usb=False)
    busy = False
except ValidationError as exc:
    busy = "in use" in str(exc)
sh(f"umount {W}/mnt")
check("add USB: a mounted disk is never erased", busy)
usb_id = add_usb_slot(V, "tester", loop, "safe stick", source="test", require_usb=False)
store = read_slot_store(V)
stick = next(sl for sl in store["slots"] if sl["id"] == usb_id)
check("add USB: stick formatted with fabric's UUID, key written and verified, method saved",
      stick["type"] == "usb" and stick["device"]["fs_uuid"] in sh(f"blkid -o value -s UUID {loop}").stdout
      and stick["wraps"].get(store["key_id"]))
check("add USB: stick not left mounted", sh(f"findmnt -n {loop}", ok=False).returncode != 0)
check("add USB: kill-switch rule written for this stick's UUID only",
      stick["device"]["fs_uuid"] in open(f"{W}/90-fabric-unlock.rules").read()
      and open(f"{W}/90-fabric-unlock.rules").read().count("ACTION==") == 1)
check("slot test through the stick", test_slot(V, "tester", usb_id, source="test"))
remove_slot(V, "tester", "local", source="test")
check("key file removed (the stick vouched): shredded, the stick is the only way in",
      not any(f.startswith("local-") for f in os.listdir(f"{W}/keys"))
      and [sl["type"] for sl in read_slot_store(V)["slots"]] == ["usb"])
check("OpenBao restarts from the stick alone", start() and not vault_status(V)["sealed"])
calls = []


def fake_systemctl(*args, running=True):
    calls.append(args)

    class R:
        returncode = 0 if (args[0] != "is-active" or running) else 3
    return R()


sh(f"losetup -d {loop}")
check("stick pulled: kill switch stops OpenBao", vault_device_event(V, lambda *a: fake_systemctl(*a, running=True))
      == "stopped" and ("stop", "openbao") in calls)
check("with the stick gone fabric-unlock refuses", unlock_vault(V) is None)
loop = sh(f"losetup --find --show {W}/stick.img").stdout.strip()
check("stick back: OpenBao is started again", vault_device_event(V, lambda *a: fake_systemctl(*a, running=False))
      == "started" and ("start", "openbao") in calls)
calls.clear()
real_device_event = rvc.vault_device_event
rvc.vault_device_event = lambda v: real_device_event(v, lambda *a: fake_systemctl(*a, running=False))
code, out, err, _ = vault_cli("device-event")
rvc.vault_device_event = real_device_event
# covers: cli:vault.device-event +
check("vault device-event (udev): the stick is present and OpenBao stopped -> it is started",
      code == 0 and out.strip() == "started" and ("start", "openbao") in calls, (out, err, calls))
check("...and unseals from it, data intact", start() and
      bao_request(V, "GET", "fabric/data/probe", token=approle_login(V, "setup-approle.json"))[1]
      .get("data", {}).get("data") == {"v": "1"})
res = rotate_vault_key(V, "tester", restart_unsealed, source="test")
check("rotation with the stick: new key on the stick, old one shredded there",
      res["kept"] == [usb_id] and res["key_id"] == "fabric-3" and test_slot(V, "tester", usb_id, source="test"))
sh(f"mount -o ro {loop} {W}/mnt")
on_stick = sorted(os.listdir(f"{W}/mnt/fabric-vault"))
key_mode = oct(os.stat(f"{W}/mnt/fabric-vault/fabric-3.key").st_mode & 0o777)
sh(f"umount {W}/mnt")
check("on the stick: only the current key, root-only", on_stick == ["fabric-3.key"] and key_mode == "0o400", on_stick)
try:
    remove_slot(V, "tester", usb_id, source="test")
    last_usb = False
except ValidationError as exc:
    last_usb = "last" in str(exc)
check("the stick, now the only method, cannot be removed", last_usb)
compose("stop")
sh(f"losetup -d {loop}")
sh(f"losetup -d {other}")

# ---------------------------------------------------------------- security key (PKCS#11; SoftHSM2 stands in)
loop = sh(f"losetup --find --show {W}/stick.img").stdout.strip()
start("up")
HSM = "/usr/lib/softhsm/libsofthsm2.so"
have_hsm = os.path.exists(HSM) and shutil.which("softhsm2-util")
try:
    import PyKCS11 as P
except ImportError:
    have_hsm = False
check("test prerequisites: softhsm2 and python3-pykcs11 installed", have_hsm)


def refused(fn, text):
    try:
        fn()
        return False
    except ValidationError as exc:
        return text in str(exc)


def token_flags(serial):
    lib = P.PyKCS11Lib()
    lib.load(HSM)
    return next(lib.getTokenInfo(sl).flags for sl in lib.getSlotList(tokenPresent=True)
                if lib.getTokenInfo(sl).serialNumber.strip() == serial)


if have_hsm:
    os.makedirs(f"{W}/softhsm/tokens", exist_ok=True)
    open(f"{W}/softhsm/softhsm2.conf", "w").write(f"directories.tokendir = {W}/softhsm/tokens\nobjectstore.backend = file\n")
    os.environ["SOFTHSM2_CONF"] = f"{W}/softhsm/softhsm2.conf"
    # softhsm2-util only takes PINs as arguments: acceptable for a throwaway software token in a test
    for label in ("fabric-a", "fabric-b", "fabric-c"):
        sh(["softhsm2-util", "--init-token", "--free", "--label", label, "--so-pin", "87654321", "--pin", "123456"])
    V["openbao_pkcs11_modules"] = [HSM]
    toks = {t["label"]: t for t in list_pkcs11_tokens(V)}
    # covers: setting:openbao_pkcs11_modules +
    check("tokens listed without a login", set(toks) == {"fabric-a", "fabric-b", "fabric-c"}
          and all(t["pin_state"] == "ok" for t in toks.values()), toks)
    A, B = toks["fabric-a"]["serial"], toks["fabric-b"]["serial"]
    check("a library not on the allowed list is refused (never loaded)",
          refused(lambda: add_security_key_slot(V, "tester", "/tmp/x.so", A, "123456", source="test"), "allowed list"))
    check("wrong PIN refused, nothing saved",
          refused(lambda: add_security_key_slot(V, "tester", HSM, A, "000000", source="test"), "wrong PIN")
          and not any(sl["type"] == "pkcs11" for sl in read_slot_store(V)["slots"])
          and not any(f.startswith("pin-") for f in os.listdir(f"{W}/keys")))
    tok = add_security_key_slot(V, "tester", HSM, A, "123456", label="token a", source="test")
    slot = next(sl for sl in read_slot_store(V)["slots"] if sl["id"] == tok)
    lib = P.PyKCS11Lib()
    lib.load(HSM)
    sess = lib.openSession(next(sl for sl in lib.getSlotList(tokenPresent=True)
                                if lib.getTokenInfo(sl).serialNumber.strip() == A))
    sess.login("123456")
    priv = sess.findObjects([(P.CKA_CLASS, P.CKO_PRIVATE_KEY), (P.CKA_ID, tuple(bytes.fromhex(slot["device"]["key_id"])))])
    attrs = sess.getAttributeValue(priv[0], [P.CKA_SENSITIVE, P.CKA_EXTRACTABLE]) if priv else None
    sess.logout()
    store_text = open(f"{W}/keys/slots.json").read()
    check("added: key pair made on the token (sensitive, not extractable); only ciphertext in the store",
          attrs == [True, False] and slot["wraps"][read_slot_store(V)["key_id"]]["alg"] == "RSA-OAEP-SHA1", attrs)
    pin_file = f"{W}/keys/pin-{tok}"
    check("PIN kept root 0400 on this host, never in the store",
          oct(os.stat(pin_file).st_mode & 0o777) == "0o400" and os.stat(pin_file).st_uid == 0 and "123456" not in store_text)
    check("slot test through the token", test_slot(V, "tester", tok, source="test"))
    check("the same token twice is refused",
          refused(lambda: add_security_key_slot(V, "tester", HSM, A, "123456", source="test"), "already"))

    # PIN guard: a stale stored PIN costs one try, unattended starts do not retry
    pkcs11.save_pin(V, slot, "000000")
    kid = read_slot_store(V)["key_id"]
    k1 = obtain_key(V, read_slot_store(V), kid, only=tok)[0]
    low = bool(token_flags(A) & P.CKF_USER_PIN_COUNT_LOW)
    pkcs11.save_pin(V, slot, "123456")
    errs = []
    k2 = obtain_key(V, read_slot_store(V), kid, only=tok, errors=errs)[0]
    check("unattended: a wrong stored PIN costs one try, then the token is not tried again",
          k1 is None and low and k2 is None and "not retried" in " ".join(errs), errs)
    check("a person's `vault test` logs in once and clears it",
          test_slot(V, "tester", tok, source="test") and not token_flags(A) & P.CKF_USER_PIN_COUNT_LOW)

    # an existing key pair (the vendor-tool path, e.g. a YubiKey PIV slot)
    sess = lib.openSession(next(sl for sl in lib.getSlotList(tokenPresent=True)
                                if lib.getTokenInfo(sl).serialNumber.strip() == B), P.CKF_SERIAL_SESSION | P.CKF_RW_SESSION)
    sess.login("123456")
    for ident, extractable in (((0x0a,), True), ((0x03,), False)):
        common = [(P.CKA_TOKEN, True), (P.CKA_ID, ident)]
        sess.generateKeyPair([(P.CKA_CLASS, P.CKO_PUBLIC_KEY), (P.CKA_ENCRYPT, True), (P.CKA_MODULUS_BITS, 2048),
                              (P.CKA_PUBLIC_EXPONENT, (1, 0, 1))] + common,
                             [(P.CKA_CLASS, P.CKO_PRIVATE_KEY), (P.CKA_PRIVATE, True), (P.CKA_SENSITIVE, not extractable),
                              (P.CKA_EXTRACTABLE, extractable), (P.CKA_DECRYPT, True)] + common,
                             mecha=P.MechanismRSAGENERATEKEYPAIR)
    sess.logout()
    check("an existing key that can be exported is refused",
          refused(lambda: add_security_key_slot(V, "tester", HSM, B, "123456", "0a", source="test"), "exported"))
    check("a key id that is not on the token is refused",
          refused(lambda: add_security_key_slot(V, "tester", HSM, B, "123456", "7f", source="test"), "no key pair"))
    tok_b = add_security_key_slot(V, "tester", HSM, B, "123456", "03", label="token b", source="test")
    check("an existing sensitive key (id 03, like a YubiKey's 9d slot) is accepted and works",
          test_slot(V, "tester", tok_b, source="test"))
    remove_slot(V, "tester", tok_b, source="test")
    check("removing a security key deletes its stored PIN", not os.path.exists(f"{W}/keys/pin-{tok_b}"))

    # the same through fabricctl vault tokens / add-key / remove (the PIN asked hidden, never on the command line)
    code, out, err, _ = vault_cli("tokens")
    C = next((t["serial"] for t in list_pkcs11_tokens(V) if t["label"] == "fabric-c"), "")
    # covers: cli:vault.tokens +
    check("vault tokens: every token the allowed libraries see, by serial, PIN state and library",
          code == 0 and C and all(s in out for s in (A, B, C)) and out.count("PIN: ok") == 3 and HSM in out, out)
    # covers: cli:vault.tokens -
    check("vault tokens takes no argument: refused with the usage", usage_refused("tokens", C))
    before = slot_ids()
    code, out, err, asked = vault_cli("add-key", "0000000000000000", "--yes", answers=["123456"])
    # covers: cli:vault.add-key -
    check("vault add-key: a serial no allowed library sees is refused before any PIN is asked, nothing saved",
          code == 1 and "error: 0 tokens with serial '0000000000000000'" in err and not asked and slot_ids() == before,
          err)
    pins = sorted(f for f in os.listdir(f"{W}/keys") if f.startswith("pin-"))
    code, out, err, asked = vault_cli("add-key", C, "--label", "token c", "--yes", answers=["000000"])
    # covers: ask:vault.token_pin -
    check("vault add-key: the PIN is asked hidden; a wrong one is refused, nothing saved",
          code == 1 and "wrong PIN" in err and asked == ["token PIN: "] and slot_ids() == before
          and sorted(f for f in os.listdir(f"{W}/keys") if f.startswith("pin-")) == pins, err)
    code, out, err, asked = vault_cli("add-key", C, "--label", "token c", "--yes", answers=["123456"])
    tok_c = out.split()[-1] if code == 0 and out.startswith("added ") else ""
    # covers: cli:vault.add-key ask:vault.token_pin +
    check("vault add-key: the right PIN typed (hidden) -> the security key is an unlock method that unwraps the key",
          tok_c and asked == ["token PIN: "] and any(sl["id"] == tok_c and sl["type"] == "pkcs11"
                                                     and sl["label"] == "token c" for sl in read_slot_store(V)["slots"])
          and test_slot(V, "tester", tok_c, source="test"), (out, err))
    code, out, err, _ = vault_cli("remove", tok_c, "--yes")
    # covers: cli:vault.remove +
    check("vault remove: the method is gone and its stored PIN deleted, the others untouched",
          code == 0 and out.strip() == f"{tok_c}: removed" and slot_ids() == before
          and not os.path.exists(f"{W}/keys/pin-{tok_c}"), (out, err))

    # the token alone
    remove_slot(V, "tester", usb_id, source="test")
    check("OpenBao restarts from the security key alone", start() and not vault_status(V)["sealed"])
    res = rotate_vault_key(V, "tester", restart_unsealed, source="test")
    check("rotation: the token wraps the new key", res["kept"] == [tok] and test_slot(V, "tester", tok, source="test"))
    check("the token, now the only method, cannot be removed",
          refused(lambda: remove_slot(V, "tester", tok, source="test"), "last"))

# ---------------------------------------------------------------- HSM / key manager (KMIP; PyKMIP server stands in)
try:
    from kmip import enums as kenums
    have_kmip = bool(shutil.which("pykmip-server"))
except ImportError:
    have_kmip = False
check("test prerequisites: python3-pykmip (client and pykmip-server) installed", have_kmip)
if have_hsm and have_kmip:
    KP = 15696
    for name, san in (("kmip-server", "DNS:kmip.lan.test"), ("kmip-client", "DNS:fabric-test")):
        sh(f"openssl req -newkey rsa:2048 -nodes -keyout {name}.key -out {name}.csr -subj '/CN={name}'")
        open(f"{name}.ext", "w").write(f"subjectAltName={san}\nextendedKeyUsage=serverAuth,clientAuth\n")
        sh(f"openssl x509 -req -in {name}.csr -CA root.crt -CAkey root.key -CAcreateserial -out {name}.crt "
           f"-days 2 -extfile {name}.ext")
    # one PEM for both settings: Debian's PyKMIP server swaps certfile and keyfile
    open("kmip-server.pem", "w").write(open("kmip-server.crt").read() + open("kmip-server.key").read())
    open("kmip.conf", "w").write(f"[server]\nhostname=127.0.0.1\nport={KP}\ncertificate_path={W}/kmip-server.pem\n"
                                 f"key_path={W}/kmip-server.pem\nca_path={W}/root.crt\nauth_suite=TLS1.2\n"
                                 f"enable_tls_client_auth=True\ndatabase_path={W}/kmip.db\nlogging_level=INFO\n")
    kmip_srv = subprocess.Popen(["pykmip-server", "-f", f"{W}/kmip.conf", "-l", f"{W}/kmip.log"],
                                stdout=open(f"{W}/kmip.out", "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", KP), 1).close()
            break
        except OSError:
            time.sleep(0.5)
    kargs = ("127.0.0.1", KP, "kmip.lan.test", f"{W}/root.crt", f"{W}/kmip-client.crt", f"{W}/kmip-client.key")
    with kmip_session(*kargs) as kc:
        kuid = kc.create(kenums.CryptographicAlgorithm.AES, 256)
        kc.activate(kuid)
    pem = {n: open(f"{W}/kmip-client.{n}").read() for n in ("crt", "key")}
    check("KMIP: a device whose certificate is not from the given CA is refused (TLS verified)",
          refused(lambda: add_kmip_slot(V, "tester", f"127.0.0.1:{KP}", kuid, open(f"{W}/other.crt").read(),
                                        pem["crt"], pem["key"], "kmip.lan.test", source="test"), "TLS handshake"))
    check("KMIP: a wrong key id is refused, nothing saved",
          refused(lambda: add_kmip_slot(V, "tester", f"127.0.0.1:{KP}", "9999", open(f"{W}/root.crt").read(),
                                        pem["crt"], pem["key"], "kmip.lan.test", source="test"), "refused")
          and not any(sl["type"] == "kmip" for sl in read_slot_store(V)["slots"]))
    hsm = add_kmip_slot(V, "tester", f"127.0.0.1:{KP}", kuid, open(f"{W}/root.crt").read(), pem["crt"], pem["key"],
                        "kmip.lan.test", "test hsm", source="test")
    kdir = f"{W}/keys/kmip-{hsm}"
    check("KMIP: added after a wrap + unwrap through the device; its certificates and key root 0400",
          all(oct(os.stat(f"{kdir}/{n}").st_mode & 0o777) == "0o400" for n in ("ca.crt", "client.crt", "client.key"))
          and test_slot(V, "tester", hsm, source="test"))
    with kmip_session(*kargs) as kc:
        kuid2 = kc.create(kenums.CryptographicAlgorithm.AES, 256)
        kc.activate(kuid2)
    before = slot_ids()
    code, out, err, _ = vault_cli("add-kmip", f"127.0.0.1:{KP}", "--key-id", kuid2, "--ca", f"{W}/root.crt",
                                  "--cert", f"{W}/kmip-client.crt", "--key", f"{W}/kmip-client.key",
                                  "--server-name", "kmip.lan.test", "--label", "cli hsm", "--yes")
    hsm2 = out.split()[-1] if code == 0 and out.startswith("added ") else ""
    # covers: cli:vault.add-kmip +
    check("vault add-kmip: certificates read from their files, the device's key made an unlock method that unwraps",
          hsm2 and any(sl["id"] == hsm2 and sl["type"] == "kmip" and sl["label"] == "cli hsm"
                       for sl in read_slot_store(V)["slots"]) and test_slot(V, "tester", hsm2, source="test"),
          (out, err))
    code, out, err, _ = vault_cli("remove", hsm2, "--yes")
    # covers: cli:vault.remove +
    check("vault remove: the HSM method added from the command line is gone again",
          code == 0 and out.strip() == f"{hsm2}: removed" and slot_ids() == before, (out, err))
    remove_slot(V, "tester", tok, source="test")
    check("OpenBao restarts from the HSM alone", start() and not vault_status(V)["sealed"])
    res = rotate_vault_key(V, "tester", restart_unsealed, source="test")
    check("rotation: the HSM wraps the new key", res["kept"] == [hsm] and test_slot(V, "tester", hsm, source="test"))
    with kmip_session(*kargs) as kc:
        kc.revoke(kenums.RevocationReasonCode.CESSATION_OF_OPERATION, kuid)
    check("KMIP kill switch: key revoked on the device -> the method no longer unwraps, fabric-unlock refuses",
          refused(lambda: test_slot(V, "tester", hsm, source="test"), "could not unwrap") and unlock_vault(V) is None)
    kmip_srv.terminate()

# ---------------------------------------------------------------- hardening
insp = json.loads(sh("docker inspect openbao").stdout)[0]
hc = insp["HostConfig"]
check("runs as 913:913, not root", insp["Config"]["User"] == "913:913")
# covers: setting:openbao_mem_limit +
check("no capabilities, no-new-privileges, read-only root, memory limit",
      hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd") and "no-new-privileges:true" in hc["SecurityOpt"]
      and hc["ReadonlyRootfs"] and hc["Memory"] == 256 * 1024 * 1024, hc)
check("effective capabilities are empty",
      "CapEff:\t0000000000000000" in sh("docker exec openbao cat /proc/1/status", ok=False).stdout)
check("key folder (RAM) mounted read-only", any(m["Destination"] == "/openbao/seal" and not m["RW"] for m in insp["Mounts"]))
check("no Docker socket", not any("docker.sock" in m["Source"] for m in insp["Mounts"]))

compose("down")
sh(f"losetup -d {loop}", ok=False)
testrun.remove("network", NET)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
