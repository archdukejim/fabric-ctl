#!/usr/bin/env python3
"""Web-guided setup's clean-machine run (manual 3.1.5.13, 1.3.6.8): the package on a fresh lab VM, `sudo fabricctl setup`
in a real terminal (Windows OpenSSH with the lab key, 3.1.5.4), Guided in a real browser on this machine, every default
accepted, through to Finish; then the host as it was left. From WSL on gaming-23, as root (Docker).

    python3 tests/lab/web_guided_lab.py 10.88.0.10 <fabricctl_….deb>
"""
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time

VM, DEB = sys.argv[1:3]
if not VM.startswith("10.88.0."):
    sys.exit(f"refused: {VM} is not a lab address (10.88.0.0/24, manual 3.1.5.1)")
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROBE_DIR = os.path.join(REPO, "tests", "setup", "site")
IMAGE = "fabric/webui-browser:web-guided-lab"
HOME = subprocess.run(["cmd.exe", "/c", "echo %USERPROFILE%"], capture_output=True, text=True, cwd="/mnt/c").stdout.strip()
SSH_EXE = "/mnt/c/Windows/System32/OpenSSH/ssh.exe"
SCP_EXE = "/mnt/c/Windows/System32/OpenSSH/scp.exe"
OPTS = ["-i", f"{HOME}\\.ssh\\g23_lab", "-o", f"UserKnownHostsFile={HOME}\\fabric-lab\\known_hosts", "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=8"]
SECRET = "Lab-" + secrets.token_hex(12)     # made for this run; to the browser in a file, never on a command line
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[-1500:]}"), flush=True)


def on(command, timeout=600):
    """One command on the VM, as labadmin (sudo inside it): (exit status, output without OpenSSH's notices)."""
    run = subprocess.run([SSH_EXE, *OPTS, f"labadmin@{VM}", command], capture_output=True, text=True, timeout=timeout)
    out = "\n".join(line for line in (run.stdout + run.stderr).splitlines()
                    if not re.search(r"post-quantum|store now|upgraded\. See", line))
    return run.returncode, out


class Terminal:
    """`sudo fabricctl setup` on the VM in a real terminal: OpenSSH asked for one with -tt."""

    def __init__(self, log):
        self.screen, self.log = "", open(log, "w")
        self.proc = subprocess.Popen([SSH_EXE, "-tt", *OPTS, f"labadmin@{VM}", "sudo fabricctl setup"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.chunks = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            data = self.proc.stdout.read1(8192)
            if not data:
                return
            text = data.decode("utf-8", "replace")
            self.chunks.append(text)
            self.log.write(text)
            self.log.flush()

    def plain(self):
        self.screen = "".join(self.chunks)
        return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", self.screen).replace("\r", "")

    def until(self, pattern, seconds):
        end = time.time() + seconds
        while time.time() < end:
            found = re.search(pattern, self.plain())
            if found or self.proc.poll() is not None:
                return found or re.search(pattern, self.plain())
            time.sleep(0.5)
        return None

    def send(self, text):
        self.proc.stdin.write((text + "\r").encode())
        self.proc.stdin.flush()

    def end(self, seconds):
        try:
            return self.proc.wait(seconds)
        except subprocess.TimeoutExpired:
            return None


out_dir = tempfile.mkdtemp(prefix="web-guided-lab-", dir="/tmp")
os.chmod(out_dir, 0o777)
print(f"--- the package on {VM}: {os.path.basename(DEB)}", flush=True)
shutil.copy(DEB, os.path.join(out_dir, "fabricctl.deb"))
windows_deb = subprocess.run(["wslpath", "-w", os.path.join(out_dir, "fabricctl.deb")], capture_output=True, text=True).stdout.strip()
copied = subprocess.run([SCP_EXE, "-q", *OPTS, windows_deb, f"labadmin@{VM}:/tmp/fabricctl.deb"], capture_output=True, text=True)
check("the package reaches the VM", copied.returncode == 0, copied.stderr)
status, text = on("sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/fabricctl.deb >/dev/null; "
                  "dpkg-query -W -f='${Package} ${Version}' fabricctl; echo; ufw status 2>/dev/null | head -1; sudo ufw status | head -1")
check("apt installs it, with its dependencies from Ubuntu's archive", status == 0 and "fabricctl " in text, text)
_, before = on("sudo ufw status | head -1; ls /opt 2>/dev/null | tr '\\n' ' '")
print(f"    before setup: {before.strip()}", flush=True)

print("--- sudo fabricctl setup, Guided, every default", flush=True)
term = Terminal(os.path.join(out_dir, "terminal.log"))
check("a new install asks Guided or Advanced first", term.until(r"Guided, Advanced or Quit\? \[G/a/q\]", 180), term.plain()[-800:])
term.send("")
found = term.until(r"would block the setup site|One-time code:\s+(\S+)\s+Temporary certificate's SHA-256 fingerprint:\s+(\S+)", 120)
if found and "would block" in found.group(0):
    term.send("")                                  # the default: open the port until the site stops
    found = term.until(r"One-time code:\s+(\S+)\s+Temporary certificate's SHA-256 fingerprint:\s+(\S+)", 60)
urls = re.findall(r"https://[0-9.]+:\d+/", term.plain())
check("the terminal gives the URL, the code and the fingerprint", found and urls, term.plain()[-1000:])
if not (found and urls):
    print(f"web_guided_lab: {PASS} passed, {FAIL} failed: the site did not open; nothing more was run", flush=True)
    sys.exit(1)
code, fingerprint, url = found.group(1), found.group(2), next((u for u in urls if VM in u), urls[0])

build = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], text=True, capture_output=True, input=(
    f"FROM {subprocess.run([sys.executable, os.path.join(REPO, 'tests', 'image_ref.py'), 'debian'], capture_output=True, text=True).stdout.strip()}\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends chromium python3 openssl fonts-dejavu-core "
    "&& rm -rf /var/lib/apt/lists/*\nRUN useradd -m probe\nUSER probe\n"))
check("the test browser image builds", build.returncode == 0, build.stderr)
scenario = {"url": url, "code": code, "fingerprint": fingerprint, "out": "/out", "width": 1366, "secret": SECRET, "pictures": True,
            "seconds": 5400, "restart_wait": 8, "finish_check": True, "verify_new_certificate": True,
            "answers": {"First Directory": "pat.admin", "Their first": "Pat", "Their last": "Example"},
            # the check's second pass: every name under setup's default domain resolving to the VM, as fabric's DNS
            "check_with": {"resolved": {"*.home.arpa": VM}}}
holder = {}
threading.Thread(target=lambda: holder.update(status=term.end(5700)), daemon=True).start()
with open(os.path.join(out_dir, "scenario.json"), "w") as f:
    json.dump(scenario, f)
started = time.time()
run = subprocess.Popen(["docker", "run", "--rm", "--name", "fabric-web-guided-lab", "--network", "host", "--memory", "1g",
                        "--shm-size", "256m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                        "-v", f"{PROBE_DIR}:/probe:ro", "-v", f"{out_dir}:/out", IMAGE, "python3", "/probe/site_probe.py",
                        "/out/scenario.json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
rows = []
for line in run.stdout:
    if not line.startswith("{"):
        continue
    row = json.loads(line)
    rows.append(row)
    if row.get("page") == "plan":
        print("    the plan shown; Proceed", flush=True)
    if row.get("page") == "progress":
        print(f"    installing ({round((time.time() - started) / 60)} min in)", flush=True)
run.wait()
os.remove(os.path.join(out_dir, "scenario.json"))
pages = {r["page"]: r for r in rows if "page" in r}
check("a real browser went from the code to the finish, every default accepted", "finish" in pages, rows[-3:])
check("the page reported no script error or policy refusal", not [e for r in rows for e in r.get("errors", [])],
      [e for r in rows for e in r.get("errors", [])])
new = next((r for r in rows if r.get("event") == "new certificate"), {})
check("the site moved to fabric's certificate", new.get("fingerprint") and new["fingerprint"] != fingerprint, new)
verified = next((r for r in rows if r.get("event") == "verifies against the root"), {})
check("its certificate verifies against the offered root, for the VM's address", verified.get("ok") is True, verified)
checks = {r["stage"]: r["text"] for r in rows if r.get("event") == "check"}
check("the finish's check, without fabric's DNS here: says the name is not yet resolving", "did not resolve" in checks.get("first", ""), checks)
check("the finish's check, with the domain resolving to the VM: the console answers with fabric's certificate",
      checks.get("resolved", "").startswith("OK:"), checks)
check("Finish pressed: the site says it stopped", rows and rows[-1].get("done") is True, rows[-2:])

time.sleep(5)
status = holder.get("status")
if status is None:
    status = term.end(120)
check("setup ended well in the terminal", status == 0, term.plain()[-1500:])
plain = term.plain()
check("the terminal printed the root's and the new certificate's fingerprints",
      "root certificate, SHA-256" in plain and "new certificate, SHA-256" in plain, plain[-800:])

print("--- the host afterwards", flush=True)
_, ports = on("sudo ss -ltnH | awk '{print $4}' | grep -E ':(84(4[3-9]|5[0-3]))$' || true")
check("nothing listens on the site's ports", not ports.strip(), ports)
_, rules = on("sudo ufw status | head -1; sudo ufw show added | grep -c fabric-setup-site || true")
check("ufw is on, and holds no rule of the site's", "Status: active" in rules and rules.strip().endswith("0"), rules)
status_left, left = on("test ! -e /run/fabric-setup/site-port && ! pgrep -f '[s]ite_main' && ! sudo find /opt/stepca/data/artifacts -name 'setup-site*' | grep -q .")
check("no record, listener or minted file of the site's left", status_left == 0, left)
pw = os.path.join(out_dir, "pw")
with open(pw, "w") as f:
    f.write(SECRET)
subprocess.run([SCP_EXE, "-q", *OPTS, subprocess.run(["wslpath", "-w", pw], capture_output=True, text=True).stdout.strip(),
                f"labadmin@{VM}:/tmp/lab-pw-check"], capture_output=True)
os.remove(pw)
_, hits = on("sudo grep -rlF -f /tmp/lab-pw-check /opt/fabric/config /var/log /run /tmp --exclude=lab-pw-check 2>/dev/null; rm -f /tmp/lab-pw-check; true")
check("the first admin's password is in no file or log", not hits.strip(), hits)
_, journal = on(f"sudo journalctl --no-pager | grep -cF '{code}' || true")
check("the one-time code is in no log", journal.strip() == "0", journal)
doctor_status, doctor = on("sudo fabricctl doctor > /tmp/doctor.log 2>&1; s=$?; tail -25 /tmp/doctor.log; exit $s", 900)
check("fabricctl doctor passes", doctor_status == 0 and "✗" not in doctor, doctor)
name = re.search(r"Check (fabric-ctl\.[A-Za-z0-9.-]+)", pages.get("finish", {}).get("text", ""))
console = name.group(1) if name else "fabric-ctl.home.arpa"
# the root as a person gets it, from http://<host>/certs/ (nginx's own folder is not labadmin's to read)
curl_status, curl = on(f"curl -sS -o /tmp/lab-root.crt http://{VM}/certs/root-ca.crt && curl -sS -o /dev/null -w '%{{http_code}}' "
                       f"--cacert /tmp/lab-root.crt --resolve {console}:443:{VM} https://{console}/; s=$?; rm -f /tmp/lab-root.crt; exit $s")
check(f"the console answers on {console}, verified by the root published at /certs/", curl_status == 0, curl)

print(f"    pictures and the terminal's log: {out_dir}", flush=True)
subprocess.run(["docker", "rmi", IMAGE], capture_output=True)
print(f"web_guided_lab: {PASS} passed, {FAIL} failed", flush=True)
sys.exit(1 if FAIL else 0)
