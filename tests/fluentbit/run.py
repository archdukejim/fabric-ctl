#!/usr/bin/env python3
"""Fluent Bit (optional log forwarding, design 2.1.15.1) on the real pinned image,
from fabric's own templates: it forwards OpenBao's audit log to a TLS syslog
receiver and to an HTTPS Elasticsearch-style receiver, both verified against
the fabric CA; a destination with a certificate from another CA gets
nothing; the disk buffer delivers everything once the destination is right
again; the container is hardened; `logs status` reports what was sent.

    sudo python3 tests/fluentbit/run.py          (needs Docker, openssl, root)
"""
import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/fluentbit"
NET, SUBNET, GW, IP = "fbtest_net", "10.254.21.0/24", "10.254.21.1", "10.254.21.95"
SYSLOG_PORT, ES_PORT, PW = 16514, 19200, "Es-Secret-9"
FAILED = 0
sys.path[0:0] = [os.path.join(REPO, "src"), REPO]
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.logs.deploy_fluentbit import deploy_fluentbit  # noqa: E402
from fabriclib.logs.log_status import log_status  # noqa: E402


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, cwd=W)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout}{res.stderr}")
    return res


def until(pred, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(1)
    return False


shutil.rmtree(W, ignore_errors=True)
os.makedirs(f"{W}/stepca/data/certs")
sh(f"docker rm -f fluentbit >/dev/null 2>&1; docker network rm {NET} >/dev/null 2>&1", ok=False)
for ca in ("root", "other"):
    sh(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {ca}.key -out {ca}.crt -days 2 -subj '/CN={ca} CA' "
       "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign")
for name, ca in (("siem", "root"), ("es", "root"), ("siem-other", "other")):
    host = name.split("-")[0] + ".test"
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {name}.key -out {name}.csr -subj '/CN={host}'")
    open(f"{W}/{name}.ext", "w").write(f"subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n")
    sh(f"openssl x509 -req -in {name}.csr -CA {ca}.crt -CAkey {ca}.key -CAcreateserial -out {name}.crt -days 2 "
       f"-extfile {name}.ext")
shutil.copy(f"{W}/root.crt", f"{W}/stepca/data/certs/root_ca.crt")

# ------------------------------------------------------------------ receivers
SYSLOG, BULK, AUTH = [], [], []
syslog_cert = {"name": "siem"}


def syslog_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", SYSLOG_PORT))
    srv.listen(8)
    while True:
        conn, _ = srv.accept()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{W}/{syslog_cert['name']}.crt", f"{W}/{syslog_cert['name']}.key")
        threading.Thread(target=syslog_conn, args=(ctx, conn), daemon=True).start()


def syslog_conn(ctx, conn):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        while True:
            data = tls.recv(65536)
            if not data:
                break
            SYSLOG.append(data.decode(errors="replace"))
    except (ssl.SSLError, OSError):
        pass


class ES(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply({"version": {"number": "8.15.0"}})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(errors="replace")
        AUTH.append(self.headers.get("Authorization", ""))
        BULK.append(body)
        self._reply({"errors": False, "items": []})


threading.Thread(target=syslog_server, daemon=True).start()
es = ThreadingHTTPServer(("0.0.0.0", ES_PORT), ES)
ectx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ectx.load_cert_chain(f"{W}/es.crt", f"{W}/es.key")
es.socket = ectx.wrap_socket(es.socket, server_side=True)
threading.Thread(target=es.serve_forever, daemon=True).start()

# ------------------------------------------------------------------ fabric's files, rendered
lock = read_images_lock(os.path.join(REPO, "config"))
V = {"deploy_base_dir": W, "hostname": "pi-core", "install_fluentbit": True, "ip_fluentbit": IP,
     "fluentbit_mem_limit": "64m", "fluentbit_journal": False, "image_fluentbit": lock["fluentbit"]["ref"],
     "service_users": {"fluentbit": {"uid": 914, "gid": 914}, "openbao": {"uid": 913, "gid": 913}},
     "log_forwarding": {"syslog": {"host": "siem.test", "port": SYSLOG_PORT},
                        "elastic": {"url": f"https://es.test:{ES_PORT}", "user": "fabric", "index": "fabric"},
                        "hosts": {"siem.test": GW, "es.test": GW}}}
env = jinja_env(os.path.join(REPO, "templates"))
os.makedirs(f"{W}/openbao/logs")
audit = f"{W}/openbao/logs/audit-forward.log"
open(audit, "w").close()
os.chown(f"{W}/openbao/logs", 913, 913)
os.chown(audit, 913, 913)
os.chmod(audit, 0o640)
check("config, CAs, credentials and buffer written; the password only in the root-only env file",
      deploy_fluentbit(V, {"log_elastic_password": PW}, env)
      and PW not in open(f"{W}/fluentbit/config/fluent-bit.yaml").read()
      and PW in open(f"{W}/fluentbit/config/secrets.env").read()
      and oct(os.stat(f"{W}/fluentbit/config/secrets.env").st_mode & 0o777) == "0o600")
check("re-deploying unchanged files changes nothing", deploy_fluentbit(V, {"log_elastic_password": PW}, env) is False)
compose = env.get_template("fluentbit/docker-compose.yml.j2").render(**V).replace("name: fabric_net", f"name: {NET}")
open(f"{W}/fluentbit/docker-compose.yml", "w").write(compose)
sh(f"docker network create --subnet {SUBNET} --gateway {GW} {NET}")
up = sh(f"docker compose -f {W}/fluentbit/docker-compose.yml up -d", ok=False)
check("the pinned image starts from fabric's compose file", up.returncode == 0, up.stderr[-400:])


def write_audit(marker):
    with open(audit, "a") as f:
        f.write(json.dumps({"type": "request", "request": {"path": "sys/health", "id": marker}}) + "\n")


def write_until_seen(marker, seen, timeout=90):
    """Write the marker every 5 s until seen: the tail starts at the file's end (read_from_head off), so a line
    written before Fluent Bit has opened the file is never read."""
    end, due = time.time() + timeout, 0
    while time.time() < end:
        if time.time() >= due:
            write_audit(marker)
            due = time.time() + 5
        if seen():
            return True
        time.sleep(1)
    return False


# covers: setting:log_forwarding +
check("delivered to syslog over verified TLS",
      write_until_seen("mark-one", lambda: any("mark-one" in x for x in SYSLOG)),
      SYSLOG[-2:] + [sh("docker logs fluentbit", ok=False).stderr[-600:]])
check("delivered to Elasticsearch over verified TLS, with the password from OpenBao",
      until(lambda: any("mark-one" in x for x in BULK))
      and f"Basic {base64.b64encode(f'fabric:{PW}'.encode()).decode()}" in AUTH, (BULK[-1:], AUTH[-1:]))

insp = json.loads(sh("docker inspect fluentbit").stdout)[0]
hc = insp["HostConfig"]
# covers: setting:fluentbit_mem_limit +
check("hardened: uid 914, no capabilities, no-new-privileges, read-only root, memory limit, group 913 (OpenBao's logs)",
      insp["Config"]["User"] == "914:914" and hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd")
      and "no-new-privileges:true" in hc["SecurityOpt"] and hc["ReadonlyRootfs"]
      and hc["Memory"] == 64 * 1024 * 1024 and "913" in [str(g) for g in hc.get("GroupAdd") or []], hc)

# a syslog destination whose certificate is from another CA: nothing reaches it; buffered until it is right
syslog_cert["name"] = "siem-other"
before = len(SYSLOG)
sh("docker restart fluentbit")                       # drop the established TLS connection
time.sleep(3)
write_audit("mark-two")
until(lambda: any("mark-two" in x for x in BULK), 60)
time.sleep(8)
check("a destination with a certificate from another CA gets nothing (TLS verified)",
      not any("mark-two" in x for x in SYSLOG[before:]))
syslog_cert["name"] = "siem"
check("buffered on disk: delivered once the destination is right again",
      until(lambda: any("mark-two" in x for x in SYSLOG), 120), sh("docker logs fluentbit", ok=False).stderr[-600:])

status = {}


def both_sent():
    """Fluent Bit counts a record as sent once its flush returns, a moment after the receiver has it."""
    status.update(log_status(V))
    return status.get("reachable") and len(status["outputs"]) == 2 and all(
        m["sent"] > 0 for m in status["outputs"].values())


check("fabricctl logs status: both destinations with records sent", until(both_sent, 30), status)

sh(f"docker compose -f {W}/fluentbit/docker-compose.yml down", ok=False)
sh(f"docker network rm {NET}", ok=False)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
