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
import contextlib
import getpass
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

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
import fabriclib.logs.run_logs_command as m_logs  # noqa: E402
from fabriclib.common.save_vars import save_vars  # noqa: E402
from fabriclib.secrets.save_secrets import save_secrets  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402


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

# ------------------------------------------------------------------ fabricctl logs (in-process, as fabriclib/cli.py routes it)
# An install under W as SetupContext reads it: fabric/config/vars.yaml (these vars), fabric-secrets.yml (a file, as
# before OpenBao holds them) and fabric/jinja (the templates). systemd's try-restart is stood in for by what the unit
# does (wrapper.service.j2: compose rm, then up): the container is recreated and reads secrets.env again.
os.makedirs(f"{W}/fabric/config")
os.symlink(os.path.join(REPO, "templates"), f"{W}/fabric/jinja")
SECRETS_FILE = f"{W}/fabric/config/fabric-secrets.yml"
save_vars(V, f"{W}/fabric/config/vars.yaml")
save_secrets({"log_elastic_password": PW}, SECRETS_FILE)
RESTARTS = []


def restart_unit(cmd, **kw):
    RESTARTS.append(cmd)
    if cmd == ["systemctl", "try-restart", "fluentbit"]:
        sh(f"docker compose -f {W}/fluentbit/docker-compose.yml rm -fsv", ok=False)
        return sh(f"docker compose -f {W}/fluentbit/docker-compose.yml up -d", ok=False)
    raise AssertionError(f"unexpected command {cmd}")


m_logs.subprocess = types.SimpleNamespace(run=restart_unit)


class Tty(io.StringIO):
    def isatty(self):
        return True


def logs(*argv, stdin="", typed=None):
    """fabricctl logs …: (exit status, stdout, stderr, prompts asked). stdin — one line piped in; typed — the answer
    at the hidden prompt instead (stdin a terminal; getpass stood in for, as tests/common/ask.py does)."""
    out, err, asked, real = io.StringIO(), io.StringIO(), [], (sys.stdin, getpass.getpass)
    sys.stdin = Tty() if typed is not None else io.StringIO(stdin)
    getpass.getpass = lambda prompt="": asked.append(prompt) or typed
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = m_logs.run_logs_command(SetupContext(deploy_base=W).load_state(), list(argv))
    finally:
        sys.stdin, getpass.getpass = real
    return code, out.getvalue(), err.getvalue(), asked


def stored():
    return open(SECRETS_FILE).read(), open(f"{W}/fluentbit/config/secrets.env").read()


def es_got(password, marker):
    """The Elasticsearch receiver gets a new record with this password (Basic auth) after the marker is written."""
    want = f"Basic {base64.b64encode(f'fabric:{password}'.encode()).decode()}"
    start = len(AUTH)
    return write_until_seen(marker, lambda: want in AUTH[start:], 120)


code, out, err, _ = logs()
code2, out2, _, _ = logs("status")
lines = {ln.split()[0]: ln for ln in out.splitlines() if ln.strip()}
# covers: cli:logs cli:logs.status +
check("fabricctl logs (status by default): each destination with its records sent, retries, errors, dropped",
      code == 0 and code2 == 0 and set(lines) == set(status["outputs"]) and all(
          re.search(r"sent [1-9]\d*  retries \d+  errors \d+  dropped \d+", ln) for ln in lines.values())
      and len(out2.splitlines()) == len(lines) and not err, (code, out, err))
fb_ip = insp["NetworkSettings"]["Networks"][NET]["IPAddress"]
# covers: setting:ip_fluentbit +
check("ip_fluentbit: the container runs on that address (fabric's compose file) and status asks it there",
      fb_ip == V["ip_fluentbit"] == IP and status.get("reachable"), (fb_ip, status))
code, out, err, _ = logs("bogus")
code2, out2, err2, _ = logs("status", "extra")
# covers: cli:logs -
check("fabricctl logs: an unknown command, or status with an argument, is refused with the usage (exit 2)",
      code == 2 and code2 == 2 and "usage: fabricctl logs status" in err and "usage: fabricctl logs status" in err2
      and not out and not out2, (code, err, code2, err2))

before = stored()
code, out, err, _ = logs("set-password", "elastic", stdin="\n")
code2, _, err2, _ = logs("set-password", "kibana", stdin="Pw-For-Kibana-1\n")
# covers: cli:logs.set-password -
check("set-password refused: an empty password on stdin (exit 1, why); a destination other than elastic (usage); "
      "nothing saved, nothing restarted",
      code == 1 and "error: empty password" in err and code2 == 2 and "usage: fabricctl logs" in err2
      and stored() == before and not RESTARTS, (code, err, code2, err2, RESTARTS))
code, out, err, asked = logs("set-password", "elastic", typed="")
# covers: ask:logs.elastic_password -
check("set-password at a terminal: an empty answer to the hidden question is refused (exit 1, why), nothing saved",
      code == 1 and "error: empty password" in err and asked == ["Elasticsearch password: "] and stored() == before
      and not RESTARTS, (code, err, asked))

PW2 = "Es-Piped-Secret-7"
code, out, err, _ = logs("set-password", "elastic", stdin=PW2 + "\n")
# covers: cli:logs.set-password +
check("set-password elastic (piped): saved in the secrets, Fluent Bit's credentials rewritten and the unit restarted; "
      "Elasticsearch then gets the new password",
      code == 0 and out.strip() == "saved in OpenBao and applied (fluentbit restarted)"
      and yaml.safe_load(open(SECRETS_FILE))["log_elastic_password"] == PW2
      and f"LOG_ELASTIC_PASSWORD={PW2}\n" == open(f"{W}/fluentbit/config/secrets.env").read()
      and RESTARTS == [["systemctl", "try-restart", "fluentbit"]] and es_got(PW2, "mark-three"),
      (code, out, err, RESTARTS, AUTH[-1:]))
PW3 = "Es-Typed-Secret-8"
code, out, err, asked = logs("set-password", "elastic", typed=PW3)
# covers: ask:logs.elastic_password +
check("set-password at a terminal: the password asked hidden is saved and used (Elasticsearch gets it)",
      code == 0 and asked == ["Elasticsearch password: "]
      and yaml.safe_load(open(SECRETS_FILE))["log_elastic_password"] == PW3 and es_got(PW3, "mark-four"),
      (code, out, err, asked, AUTH[-1:]))

save_vars({**V, "install_fluentbit": False}, f"{W}/fabric/config/vars.yaml")
env_before, restarts = open(f"{W}/fluentbit/config/secrets.env").read(), len(RESTARTS)
code, out, err, _ = logs("status")
code2, out2, err2, _ = logs("set-password", "elastic", stdin="Es-Saved-Only-9\n")
# covers: setting:install_fluentbit +
check("install_fluentbit false: status says log forwarding is off; set-password only saves (Fluent Bit's files and "
      "service untouched)",
      code == 0 and out.strip() == "log forwarding is off (install_fluentbit: false)" and code2 == 0
      and out2.strip() == "saved in OpenBao" and yaml.safe_load(open(SECRETS_FILE))["log_elastic_password"]
      == "Es-Saved-Only-9" and open(f"{W}/fluentbit/config/secrets.env").read() == env_before
      and len(RESTARTS) == restarts, (code, out, code2, out2, err2))
save_vars(V, f"{W}/fabric/config/vars.yaml")

sh(f"docker compose -f {W}/fluentbit/docker-compose.yml down", ok=False)
code, out, err, _ = logs("status")
# covers: cli:logs.status -
check("logs status with Fluent Bit down: exit 1, it says Fluent Bit is not answering and why",
      code == 1 and out.startswith("Fluent Bit is not answering: ") and len(out.strip()) > 30, (code, out, err))
sh(f"docker network rm {NET}", ok=False)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
