#!/usr/bin/env python3
"""The dhcp campaign's console checks (manual 3.1.5.10, design 1.10.4.39 and 1.10.4.40), as root on the fabric VM,
over the real console, fabric-agent and DC. Three people, each with a one-time password from fabric's own reset in
a root-only file (/root/<uid>-pw; Keycloak then asks for a new one, which stays in this process):

- the first Directory Administrator (vars' webui_admin_user, /root/lab-admin-pw): sees Networks, adds VLAN 30 and
  applies it, Sync now, the scan page and Scan now, a DHCP option on VLAN 30's subnet, a reservation outside its
  subnet refused at Apply;
- nora, in network-operators (dhcp:write) but in no group a networks grant names: every change refused at hold,
  Sync now refused, the scan page offering no scan;
- carol, in auditors (dhcp:read): Networks shown with no form, a posted change refused.

    python3 dhcp_console.py /opt/fabric/config/vars.yaml <site>
Prints PASS/FAIL lines; exit 1 when one failed.
"""
import re
import subprocess
import sys

import yaml

from console_session import Console

V = yaml.safe_load(open(sys.argv[1]))
SITE = sys.argv[2]
FAILED = 0


def check(name, cond, detail=""):
    """Purpose: one check's line. Inputs: name, cond, detail shown on failure. Returns: cond."""
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"), flush=True)
    return cond


def pw(path):
    """Purpose: a password from a root-only file. Inputs: path. Returns: str."""
    return open(path).read().strip()


def plan():
    """Purpose: this site's plan as the DC holds it, through the CLI. Returns: the export's CSV text."""
    return subprocess.run(["fabricctl", "ipam", "export", SITE], capture_output=True, text=True).stdout


def kea_subnets():
    """Purpose: the subnets Kea serves now. Returns: list of CIDR str (empty when Kea's config is unreadable)."""
    try:
        text = open("/opt/kea/config/kea-dhcp4.conf").read()      # with // comments: read, not parsed as JSON
    except OSError:
        return []
    return re.findall(r'"subnet": "([0-9./]+)"', text)


# --- the Directory Administrator
admin = Console(V)
st, page, seen = admin.login(V["webui_admin_user"], pw("/root/lab-admin-pw"))
check("the Directory Administrator signs in to the console", st == 200, (st, seen, page[:300]))
st, _, page = admin.get(f"/networks?site={SITE}")
# covers: web:get.networks +
check(f"Networks shows the site {SITE} with VLANs 10 and 20 and their subnets",
      st == 200 and "10.88.10.0/24" in page and "10.88.20.0/24" in page, (st, page[:400]))
st, msg, page = admin.post(f"/networks/plan/{SITE}/vlans", {
    "id": "30", "name": "vlan30", "subnet": "10.88.30.0/24", "no_subnet": "off", "gateway": "10.88.30.1",
    "access": "full", "dhcp": "on", "split": "on", "relay": "", "purpose": "the lab's third VLAN", "notes": "",
    "allow_overlap": ""})
# covers: web:post.networks.plan.*.vlans +
check("Add VLAN 30 is held for Apply", msg[0] == "ok" and "Waiting for Apply" in msg[1], msg)
check("held, it is not yet in the plan", "10.88.30.0/24" not in plan(), plan()[:300])
st, review = admin.apply("networks")
check("Apply runs it: VLAN 30 in the plan and Kea serving 10.88.30.0/24",
      "10.88.30.0/24" in plan() and "10.88.30.0/24" in kea_subnets(), (st, review[-600:], kea_subnets()))
st, msg, page = admin.post(f"/networks/plan/{SITE}/addresses", {
    "ip": "10.88.99.5", "vlan": "30", "kind": "reservation", "name": "outside", "mac": "02:88:00:99:00:05",
    "owner": "", "notes": ""})
st, review = admin.apply("networks")
# covers: web:post.networks.plan.*.addresses -
check("a reservation outside VLAN 30's subnet is refused (at hold or at Apply), saying why, and not written",
      (msg[0] == "bad" or "refused" in review.lower()) and "10.88.99.5" not in plan(), (msg, review[-600:]))
st, msg, page = admin.post("/networks/sync", {})
# covers: web:post.networks.sync +
check("Sync now runs at once and says what it did", msg[0] == "ok", msg)
st, _, page = admin.get("/networks/scan")
check("the scan page offers Scan now over this site's subnets", st == 200 and "10.88.10.0/24" in page, page[:300])
st, msg, page = admin.post("/networks/scan", {"subnet": "10.88.10.0/24"})
# covers: web:post.networks.scan +
check("Scan now over VLAN 10 lists what answered: the gateway 10.88.10.1", "10.88.10.1" in page, (msg, page[-800:]))
st, msg, page = admin.post("/networks/options/options", {
    "site": SITE, "view_target": "", "action": "set", "where": "subnet:vlan30", "option": "ntp-servers",
    "data": "10.88.0.10"})
check("an option on VLAN 30's subnet is held on DHCP options", msg[0] == "ok", msg)
st, review = admin.apply("options")
out = subprocess.run(["fabricctl", "ipam", "option", "show", "subnet", "vlan30"], capture_output=True, text=True)
check("Apply writes it: option show subnet vlan30 names ntp-servers 10.88.0.10",
      "ntp-servers" in out.stdout and "10.88.0.10" in out.stdout, (review[-400:], out.stdout[-400:]))

# --- nora: dhcp:write, but no networks grant
nora = Console(V)
st, page, seen = nora.login("nora", pw("/root/nora-pw"))
check("nora (network-operators) signs in", st == 200, (st, seen, page[:300]))
st, msg, page = nora.post(f"/networks/plan/{SITE}/vlans", {
    "id": "40", "name": "vlan40", "subnet": "", "no_subnet": "on", "gateway": "", "access": "full", "dhcp": "on",
    "split": "off", "relay": "", "purpose": "", "notes": "", "allow_overlap": ""})
# covers: web:post.networks.plan.*.vlans -
check("nora's Add VLAN is refused at hold: no grant gives her networks plan at the site",
      msg[0] == "bad" and "no grant gives you networks plan" in msg[1], msg)
st, msg, page = nora.post("/networks/sync", {})
# covers: web:post.networks.sync -
check("nora's Sync now is refused, saying why", msg[0] == "bad" and "networks plan" in msg[1], msg)
st, _, page = nora.get("/networks/scan")
check("nora's scan page says she may not scan here and offers no Scan now",
      st == 200 and "Scan now" not in page, page[-600:])

# --- carol: an auditor (dhcp:read)
carol = Console(V)
st, page, seen = carol.login("carol", pw("/root/carol-pw"))
check("carol (auditors) signs in", st == 200, (st, seen, page[:300]))
st, _, page = carol.get(f"/networks?site={SITE}")
check("carol sees Networks without its forms", st == 200 and "10.88.10.0/24" in page
      and f'action="/networks/plan/{SITE}/vlans"' not in page, page[:300])
st, msg, page = carol.post(f"/networks/plan/{SITE}/vlans", {"id": "41", "name": "x", "no_subnet": "on"})
check("carol's posted change is refused (403), nothing held", st == 403, (st, msg))

sys.exit(1 if FAILED else 0)
