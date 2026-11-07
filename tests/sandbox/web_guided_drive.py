#!/usr/bin/env python3
"""The checks of tests/sandbox/web_guided.sh (manual 1.3.6.8), run on the machine holding the sandbox: `fabricctl setup` in a
real terminal in the box, answered as a person answers, with real ufw and a real browser on the box's network.

    python3 tests/sandbox/web_guided_drive.py <box> <network> <box's address> <output folder>
"""
import json
import os
import pty
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

BOX, NET, IP, OUT = sys.argv[1:5]
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PROBE_DIR = os.path.join(REPO, "tests", "setup", "site")
IMAGE = "fabric/webui-browser:web-guided"
CONSOLE = "fabric-ctl.lan.example"
SECRET = "Fx9-" + secrets.token_hex(12)      # chosen for this run; handed to the probe in a file, never on a command line
QUIET = 180                                   # the stream's 30 s on a silent network, the session's 120 s, and a little
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[-1500:]}"), flush=True)


def box(command, timeout=120):
    """One command in the box: (exit status, what it printed)."""
    run = subprocess.run(["docker", "exec", BOX, "bash", "-lc", command], capture_output=True, text=True, timeout=timeout)
    return run.returncode, run.stdout + run.stderr


class Setup:
    """`fabricctl setup` in a real terminal in the box."""

    def __init__(self, args, log):
        self.screen = ""
        self.log = open(os.path.join(OUT, log), "w")
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("docker", ["docker", "exec", "-it", BOX, "fabricctl", "setup", *args])

    def _read(self, wait):
        ready, _, _ = select.select([self.fd], [], [], wait)
        if not ready:
            return True
        try:
            data = os.read(self.fd, 8192).decode("utf-8", "replace")
        except OSError:
            return False
        if not data:
            return False
        self.screen += data
        self.log.write(data)
        self.log.flush()
        return True

    def plain(self):
        return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", self.screen).replace("\r", "")

    def until(self, pattern, seconds=120):
        """Read until the screen shows pattern; the match, or None at the time limit or the end."""
        end = time.time() + seconds
        while time.time() < end:
            found = re.search(pattern, self.plain())
            if found:
                return found
            if not self._read(0.5):
                return re.search(pattern, self.plain())
        return None

    def send(self, text):
        os.write(self.fd, (text + "\r").encode())

    def interrupt(self):
        os.write(self.fd, b"\x03")

    def end(self, seconds=60):
        """Wait for it to end, reading on: its exit status, or None at the limit (then it is killed)."""
        finish = time.time() + seconds
        while time.time() < finish:
            if not self._read(0.5):
                break
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.log.close()
                return os.waitstatus_to_exitcode(status)
        else:
            os.kill(self.pid, signal.SIGKILL)
        _, status = os.waitpid(self.pid, 0)
        self.log.close()
        return os.waitstatus_to_exitcode(status) if time.time() < finish else None


def listening():
    """The site's ports anyone is listening on in the box."""
    _, out = box("ss -ltnH")
    return sorted(int(m) for m in re.findall(r":(\d+)\s", out) if 8443 <= int(m) <= 8453)


def site_rules():
    _, out = box("ufw show added 2>/dev/null | grep fabric-setup-site || true")
    return out.strip()


def install_state():
    """What setup could have left: the install folder's files and the site's record."""
    _, files = box("find /opt/fabric -type f 2>/dev/null | sort; ls /run/fabric-setup/site-port 2>/dev/null; true")
    return files


def nothing_left(name, before):
    time.sleep(1)
    _, process = box("pgrep -af '[s]ite_main' || true")
    check(f"{name}: nothing listening, no rule, no record, the install folder as it was, no listener process",
          not listening() and not site_rules() and install_state() == before and not process.strip(),
          (listening(), site_rules(), install_state(), process))


def hold(ports):
    """Something else on these ports in the box, until the returned function is called."""
    code = ("import socket,time\n" + f"s=[socket.create_server(('0.0.0.0',p)) for p in {list(ports)}]\n" + "time.sleep(600)\n")
    box(f"nohup python3 -c \"{code}\" >/dev/null 2>&1 &\nsleep 1")

    def release():
        box("pkill -f 'socket.create_server' || true")
        time.sleep(1)
    return release


def guided(args=()):
    """Setup started, Guided chosen."""
    setup = Setup(list(args), f"setup-{int(time.time())}.log")
    found = setup.until(r"Guided, Advanced or Quit\? \[G/a/q\] $")
    check("a new install asks Guided or Advanced first", found, setup.plain()[-800:])
    setup.send("")
    return setup


def serves(port):
    """A GET from outside the box: the status, or None when nothing could be reached."""
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((IP, port), timeout=5) as raw, context.wrap_socket(raw) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {IP}:{port}\r\nConnection: close\r\n\r\n".encode())
            return int(tls.recv(64).split()[1])
    except (OSError, ssl.SSLError, IndexError, ValueError):
        return None


before = install_state()

# covers: cli:setup +
print("--- --terminal: the questions stay here", flush=True)
setup = guided(["--terminal"])
found = setup.until(r"DNS domain[^\n]*: $", 60)
check("--terminal: the terminal asks the first question, no site, no code",
      found and "One-time code" not in setup.plain() and not listening(), setup.plain()[-800:])
setup.interrupt()
setup.end()
nothing_left("--terminal, then Ctrl-C", before)

print("--- collisions", flush=True)
release = hold(range(8443, 8454))
setup = guided()
status = setup.end(90)
text = setup.plain()
check("every port taken: refused, saying what holds 8443 and offering --terminal",
      status != 0 and "8443" in text and "--terminal" in text and "One-time code" not in text, text[-800:])
release()
nothing_left("every port taken", before)

release = hold([8443])
setup = guided()
found = setup.until(r"One-time code:\s+(\S+)", 90)
text = setup.plain()
check("8443 taken: says so and uses 8444", found and "8444" in text and "8443" in text, text[-800:])
check("the site really serves on 8444, from outside the box", serves(8444) == 200, serves(8444))
setup.interrupt()
status = setup.end()
release()
check("Ctrl-C closes the site, saying so", status != 0 and "stopped" in setup.plain(), setup.plain()[-500:])
nothing_left("8443 taken, then Ctrl-C", before)

print("--- real ufw", flush=True)
box("ufw --force reset >/dev/null; ufw --force enable >/dev/null")
ufw_before = box("ufw status")[1]

setup = guided()
found = setup.until(r"would block the setup site[^\n]*\[[Yy]/[nN]\][^\n]*$", 90)
check("ufw on: the terminal asks before opening the port", found, setup.plain()[-800:])
setup.send("n")
status = setup.end()
text = setup.plain()
# covers: ask:setup.site_port -
check("declined: refused, offering --terminal, and no rule", status != 0 and "--terminal" in text and not site_rules(), text[-500:])
check("declined: ufw as it was", box("ufw status")[1] == ufw_before)
nothing_left("declined", before)

setup = guided()
setup.until(r"would block the setup site[^\n]*\[[Yy]/[nN]\][^\n]*$", 90)
setup.send("y")
found = setup.until(r"One-time code:\s+(\S+)", 60)
# covers: ask:setup.site_port +
check("agreed: real ufw holds the rule, with its comment", found and "fabric-setup-site" in site_rules(), (setup.plain()[-500:], site_rules()))
check("the rule lets a browser in", serves(8443) == 200, serves(8443))
_, row = box("ps -o user=,args= -C python3 | grep site_main")
check("the listener runs as nobody, and neither the code nor the key is on its command line",
      row.startswith("nobody") and found and found.group(1) not in row, row)
setup.interrupt()
setup.end()
check("Ctrl-C: real ufw has lost the rule, and is as it was", not site_rules() and box("ufw status")[1] == ufw_before,
      (site_rules(), box("ufw status")[1]))
nothing_left("agreed, then Ctrl-C", before)

setup = guided()
setup.until(r"would block the setup site[^\n]*\[[Yy]/[nN]\][^\n]*$", 90)
setup.send("y")
setup.until(r"One-time code:\s+(\S+)", 60)
box("pkill -9 -f 'fabriclib/[c]li.py setup'")
setup.end(20)
time.sleep(2)
check("a killed setup: its listener ends with it, and the port with it", not box("pgrep -f '[s]ite_main'")[1].strip() and not listening(),
      (box("pgrep -af '[s]ite_main'")[1], listening()))
check("a killed setup: the rule is left behind", "fabric-setup-site" in site_rules(), site_rules())
setup = guided(["--terminal"])
setup.until(r"DNS domain[^\n]*: $", 60)
check("the next setup clears it, on the comment's evidence", not site_rules(), site_rules())
setup.interrupt()
setup.end()
box("rm -f /run/fabric-setup/site-port; ufw --force reset >/dev/null; ufw --force disable >/dev/null")

print("--- the whole of it, every default accepted", flush=True)
DOCKERFILE = subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"], capture_output=True, text=True,
                            check=True).stdout.strip()
build = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], text=True, capture_output=True, input=(
    f"FROM {DOCKERFILE}\nRUN apt-get update && apt-get install -y --no-install-recommends chromium python3 openssl "
    "fonts-dejavu-core && rm -rf /var/lib/apt/lists/*\nRUN useradd -m probe\nUSER probe\n"))
check("the test browser image builds", build.returncode == 0, build.stderr)
folder = tempfile.mkdtemp(prefix="web-guided-", dir="/tmp")
os.chmod(folder, 0o777)


def probe(scenario, seconds):
    """The browser, on the box's network: what it printed, row by row."""
    path = os.path.join(folder, "scenario.json")
    with open(path, "w") as f:
        json.dump(scenario, f)
    run = subprocess.run(["docker", "run", "--rm", "--network", NET, "--memory", "1g", "--shm-size", "256m", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges:true", "-v", f"{PROBE_DIR}:/probe:ro", "-v", f"{folder}:/out",
                          IMAGE, "python3", "/probe/site_probe.py", "/out/scenario.json"],
                         capture_output=True, text=True, timeout=seconds + 120)
    os.remove(path)
    rows = [json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")]
    return rows + ([{"probe_failed": run.returncode, "stderr": run.stderr[-1500:]}] if run.returncode else [])


def probe_cut_off(scenario, seconds):
    """The browser up to the install's progress, then its network cut under it, so it says no goodbye: its rows."""
    path, name = os.path.join(folder, "scenario.json"), "fabric-web-guided-browser"
    with open(path, "w") as f:
        json.dump({**scenario, "stop_at": "progress", "hold": 900, "seconds": seconds}, f)
    running = subprocess.Popen(["docker", "run", "--rm", "--name", name, "--network", NET, "--memory", "1g", "--shm-size", "256m",
                                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", f"{PROBE_DIR}:/probe:ro",
                                "-v", f"{folder}:/out", IMAGE, "python3", "/probe/site_probe.py", "/out/scenario.json"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    rows = []
    for line in running.stdout:
        if line.startswith("{"):
            rows.append(json.loads(line))
            if "done" in rows[-1]:
                break
    os.remove(path)
    subprocess.run(["docker", "network", "disconnect", "--force", NET, name], capture_output=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    running.wait()
    return rows


setup = guided()
found = setup.until(r"One-time code:\s+(\S+)\s+Temporary certificate's SHA-256 fingerprint:\s+(\S+)", 90)
check("the terminal gives the URL, the code and the fingerprint", found and f"https://{IP}:8443/" in setup.plain(), setup.plain()[-800:])
if not found or f"https://{IP}:8443/" not in setup.plain():
    print(f"web_guided: {PASS} passed, {FAIL} failed: the refusals above left something behind; the install was not run", flush=True)
    sys.exit(1)
code, fingerprint = found.group(1), found.group(2)
scenario = {"url": f"https://{IP}:8443/", "code": code, "fingerprint": fingerprint, "out": "/out", "width": 1366, "secret": SECRET,
            "pictures": False, "answers": {"DNS domain": "lan.example", "First Directory": "pat.admin", "Their first": "Pat", "Their last": "Example"}}
holder = {}
terminal = threading.Thread(target=lambda: holder.update(status=setup.end(3600)), daemon=True)
terminal.start()                            # what the run prints must be read, or it would wait on a full terminal
rows = probe_cut_off(scenario, 300)
check("a real browser reached the install: every question answered, Proceed pressed",
      rows and rows[-1].get("stopped") == "progress", rows[-3:])
pages = {r["page"]: r for r in rows if "page" in r}
check("the plan lists the site's port as a host change, and the firewall's own", "8443" in pages.get("plan", {}).get("text", ""), pages.get("plan"))
print(f"    the browser's network cut; a new one after {QUIET} s, with the same code", flush=True)
time.sleep(QUIET)
rows = probe({**scenario, "finish_check": True, "restart_wait": 8, "seconds": 3400, "verify_new_certificate": True,
              "check_with": {"resolved": {f"{CONSOLE}:443": f"{IP}:443", CONSOLE: IP}}}, 3400)
pages = {r["page"]: r for r in rows if "page" in r}
check("a network gone silent stops nothing: the same code reconnects, and the install went on", "code" in pages and "finish" in pages,
      list(pages) + rows[-2:])
new = next((r for r in rows if r.get("event") == "new certificate"), {})
check("the site moved to fabric's certificate", new.get("fingerprint") and new["fingerprint"] != fingerprint, new)
verified = next((r for r in rows if r.get("event") == "verifies against the root"), {})
check("real step-ca's certificate verifies against the offered root, for the host's address", verified.get("ok") is True, verified)
checks = {r["stage"]: r["text"] for r in rows if r.get("event") == "check"}
check("the finish's check: the name does not resolve in this browser, and it says so", "did not resolve" in checks.get("first", ""), checks)
check("the finish's check: with the name resolving, real DNS and the real console pass", checks.get("resolved", "").startswith("OK:"), checks)
check("Finish pressed", rows and rows[-1].get("done") is True, rows[-2:])
terminal.join(120)
check("setup ended well in the terminal", holder.get("status") == 0, (holder, setup.plain()[-800:]))
text = setup.plain()
check("the terminal printed the root's and the new certificate's fingerprints", "root certificate, SHA-256" in text and "new certificate, SHA-256" in text, text[-800:])

print("--- after Finish", flush=True)
check("nothing listens on the site's ports", not listening(), listening())
check("no firewall rule of the site's, with ufw on", not site_rules() and "Status: active" in box("ufw status")[1], (site_rules(), box("ufw status")[1]))
check("no record, no listener, no certificate of the site's left",
      box("test ! -e /run/fabric-setup/site-port && ! pgrep -f '[s]ite_main' && ! find /opt/stepca/data/artifacts -name 'setup-site*' | grep -q .")[0] == 0,
      box("ls /run/fabric-setup; pgrep -af '[s]ite_main'; find /opt/stepca/data/artifacts -name 'setup-site*'")[1])
pw_file = os.path.join(folder, "pw")
with open(pw_file, "w") as f:
    f.write(SECRET)
subprocess.run(["docker", "cp", pw_file, f"{BOX}:/tmp/pw"], check=True)
hits = box("grep -rlF -f /tmp/pw /opt/fabric/config /var/log /run /tmp --exclude=pw 2>/dev/null; rm -f /tmp/pw; true", 300)[1]
check("the first admin's password is in no file or log", not hits.strip(), hits)
journal = box(f"journalctl --no-pager | grep -cF '{code}' || true")[1].strip()
check("the one-time code is in no log", journal == "0", journal)
status, out = box("fabricctl doctor > /tmp/doctor.log 2>&1; s=$?; tail -30 /tmp/doctor.log; exit $s", 600)
with open(os.path.join(OUT, "doctor.log"), "w") as f:
    f.write(out)
check("doctor passes on what the site installed", status == 0 and "✗" not in out and box("test -e /opt/fabric/config/fabric.yaml -o -e /opt/fabric/config/vars.yaml")[0] == 0, out)
check("the console answers on its name, verified by fabric's root",
      box(f"curl -sS -o /dev/null -w '%{{http_code}}' --cacert /opt/nginx/www/certs/root-ca.crt --resolve {CONSOLE}:443:{IP} https://{CONSOLE}/")[0] == 0,
      box(f"curl -sS -o /dev/null --cacert /opt/nginx/www/certs/root-ca.crt --resolve {CONSOLE}:443:{IP} https://{CONSOLE}/")[1])

shutil.rmtree(folder, ignore_errors=True)
subprocess.run(["docker", "rmi", IMAGE], capture_output=True)
print(f"web_guided: {PASS} passed, {FAIL} failed", flush=True)
sys.exit(1 if FAIL else 0)
