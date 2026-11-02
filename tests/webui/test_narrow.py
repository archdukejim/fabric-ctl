#!/usr/bin/env python3
"""Every console page at a phone's width (manual 1.8.6.9): nothing wider than the screen, the top bar's menus (the
site selector's nested list, 1.8.6.12; the person's menu) open on each. The dev preview serves the
production pages; headless Chromium in the test browser image (decision 2.1.8.15: the pinned Debian base and Debian's
own chromium package, driven over its DevTools pipe by narrow_probe.py) opens each at 375 px and measures it. Needs
Docker; the image, its container and the preview's port are this run's own (manual 3.1.2.6) and removed after.

    python3 tests/webui/test_narrow.py
"""
import contextlib
import json
import os
import subprocess
import sys
import time
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
IMAGE, NAME = "fabric/webui-browser:" + testrun.name("test"), testrun.name("cnarrow")
PORT = testrun.port(18790)
WIDTH = 375
DEBIAN = subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"], capture_output=True,
                        text=True, check=True).stdout.strip()
DOCKERFILE = f"""FROM {DEBIAN}
RUN apt-get update && apt-get install -y --no-install-recommends chromium python3 fonts-dejavu-core \\
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m probe
USER probe
"""
# every page of the navigation, a detail page of each kind, and the pages a form leads to
PAGES = ["/", "/overview/doctor", "/overview/updates", "/audit", "/dns/zones", "/dns/zones?zone=iot.home.arpa",
         "/dns/zones?view=reverse", "/dns/zones?view=tsig", "/dns/zones?view=landing", "/dns-filter",
         "/dns-filter?view=lists", "/dns-filter?view=rules", "/dns-filter?view=querylog", "/dns-filter?view=settings",
         "/kea", "/networks", "/networks?site=parents", "/networks?site=lan&vlan=20", "/networks?site=lan&subnet=iot",
         "/networks?site=lan&subnet=iot&address=10.1.20.150", "/networks?site=lan&view=new-vlan", "/networks/scan",
         "/networks/options", "/networks/options?site=lan&target=subnet:iot",
         "/pki", "/pki?view=sign", "/pki?view=issue", "/pki?view=inspect", "/pki?view=convert",
         "/pki?view=issued", "/pki/acme", "/directory", "/directory/people", "/directory/people/jim",
         "/directory/people/lee", "/directory/people/_new", "/directory/groups", "/directory/groups/lab-users",
         "/directory/groups/_new", "/directory/policies", "/directory/policies/sudo", "/directory/computers",
         "/directory/computers/host-1", "/directory/computers/_groups", "/directory/ous", "/directory/ous?ou=people/staff",
         "/directory/access", "/directory/access/lan-helpdesk", "/directory/access/_new?template=helpdesk",
         "/directory/sites", "/directory/sites/lan", "/directory/kerberos", "/8021x/devices/_new",
         "/8021x/roles/_new", "/8021x/roles/trusted", "/8021x/clients/_new", "/8021x/clients/ap-hall",
         "/8021x/people/_new", "/8021x/people/staff", "/pki/issued/5a1c0e", "/pki/acme/acme-nas",
         "/secrets/method?slot=local", "/dns/zones?view=new", "/dns/zones?view=key&key=npm-certbot",
         "/directory/policies/gpo?match=example", "/8021x", "/8021x/decisions", "/8021x/guides?view=switches",
         "/8021x/guides?view=windows", "/8021x/devices", "/8021x/devices/jims-laptop", "/8021x/roles",
         "/8021x/roles/iot", "/secrets", "/secrets/unlock", "/secrets/disk", "/secrets/secrets",
         "/secrets/add-security-key", "/federation", "/settings", "/settings/sign-in", "/preview/denied",
         "/account", "/account/groups", "/changes/people"]
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:1500]}"))


@contextlib.contextmanager
def preview():
    proc = subprocess.Popen([sys.executable, os.path.join(REPO, "src", "ux", "web", "devserver.py"), "--port",
                             str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        for _ in range(150):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/static/app.css", timeout=2)
                break
            except OSError:
                time.sleep(0.1)
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=5)


build = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], input=DOCKERFILE, text=True,
                       capture_output=True)
check("the test browser image builds (pinned Debian, Debian's chromium)", build.returncode == 0, build.stderr[-800:])
if build.returncode:
    sys.exit(1)
try:
    with preview():
        run = subprocess.run(["docker", "run", "--rm", "--name", NAME, *testrun.labels(), "--network", "host", "--memory", "1g",
                              "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                              "-v", f"{HERE}:/probe:ro", IMAGE, "python3", "/probe/narrow_probe.py", str(WIDTH)]
                             + [f"http://127.0.0.1:{PORT}{p}" for p in PAGES],
                             capture_output=True, text=True, timeout=600)
    rows = [json.loads(ln) for ln in run.stdout.splitlines() if ln.startswith("{")]
    check(f"Chromium measured every page ({len(PAGES)})", len(rows) == len(PAGES) and not any("error" in r for r in rows),
          [r for r in rows if "error" in r] or run.stderr[-800:])
    bad = {r["url"].split(str(PORT), 1)[1]: r for r in rows if r.get("status") not in (200, 403)}
    check("every page answered (200; the refused sign-in's preview 403)", not bad, bad)
    wide = {r["url"].split(str(PORT), 1)[1]: (r.get("scroll_width"), r.get("wide"))
            for r in rows if r.get("scroll_width", 0) > WIDTH or r.get("wide")}
    check(f"at {WIDTH} px nothing is wider than the screen on any page (scrollWidth; no element past the edge, nor scrolling inside a card)",
          not wide, json.dumps(wide, indent=1))
finally:
    testrun.remove("container", NAME)      # this run's only
    subprocess.run(["docker", "rmi", IMAGE], capture_output=True)
sys.exit(1 if FAILED else 0)
