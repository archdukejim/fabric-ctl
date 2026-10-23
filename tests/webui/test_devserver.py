#!/usr/bin/env python3
"""The web UI dev preview: the production routes and pages over sample data (a fake agent in the process), edits in
memory only, the console's frame and navigation per bundle (manual 1.8.6), and no way to switch the preview on in the
production server."""
import contextlib
import http.client
import os
import re
import subprocess
import sys
import time
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEBUI = os.path.join(REPO, "src", "webui")
UX_WEB = os.path.join(REPO, "src", "ux", "web")          # server.py and the dev preview's devserver.py
sys.path.insert(0, os.path.join(REPO, "src"))
from webui import views  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402

PORT = int(os.environ.get("WEBUI_DEV_PORT", "18765"))
START_WAIT = 15                             # seconds a dev server may take to answer (about 6 under WSL's /mnt)
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:300]}"))


def req(method, path, form=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    body = urllib.parse.urlencode(form) if form is not None else None
    c.request(method, path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {})
    r = c.getresponse()
    data = r.read().decode()
    return r.status, r.getheader("Location"), r.getheader("Content-Security-Policy"), data


def get(path):
    return req("GET", path)[3]


def post(path, form):
    """POST a form as a browser does, following a 303: (status, location, the page shown after it)."""
    st, loc, _, page = req("POST", path, {"csrf": "dev", **form})
    if st == 303 and loc:
        page = get(loc)
    return st, loc or "", page


def flash(page):
    """The message the page shows for the last action (manual 1.8.6.3), '' when none."""
    m = re.search(r'<p class="flash (ok|bad)" role="(?:status|alert)">(.*?)</p>', page, re.S)
    return (m.group(1) + ": " + m.group(2).replace("&#39;", "'")) if m else ""


def nav(page):
    """The navigation's entries and their links, read from the page."""
    side = page.split('<nav class="side"', 1)[1].split("</nav>", 1)[0] if '<nav class="side"' in page else ""
    return re.findall(r'<li class="entry[^"]*"><a href="([^"]+)"[^>]*>([^<]+)', side)


@contextlib.contextmanager
def serve(bundle=None):
    global PORT
    PORT += 1
    args = [sys.executable, os.path.join(UX_WEB, "devserver.py"), "--port", str(PORT)]
    proc = subprocess.Popen(args + (["--as", bundle] if bundle else []), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        end = time.time() + START_WAIT
        while time.time() < end:
            try:
                req("GET", "/static/app.css")
                break
            except OSError:
                time.sleep(0.1)
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=5)


PAGES = ["/", "/overview/doctor", "/overview/updates", "/audit", "/dns/zones", "/dns-filter", "/kea", "/pki",
         "/pki/acme", "/directory/people", "/directory/domain", "/directory/machines", "/directory/gpo", "/8021x",
         "/8021x/decisions", "/8021x/guides", "/8021x/devices", "/8021x/roles", "/secrets", "/secrets/unlock",
         "/secrets/disk", "/federation", "/settings", "/settings/sign-in"]
# 1.8.6.4's moved addresses -> where each answers now
MOVED = {"/bind9": "/dns/zones", "/bind9?zone=iot.home.arpa&msg=x": "/dns/zones?zone=iot.home.arpa",
         "/bind9?view=tsig": "/dns/zones?view=tsig", "/stepca": "/pki", "/stepca?view=sign": "/pki?view=sign",
         "/stepca?view=acme": "/pki/acme", "/openbao": "/secrets", "/openbao?view=unlock": "/secrets/unlock",
         "/openbao?view=disk&err=hello": "/secrets/disk", "/freeradius": "/8021x",
         "/freeradius?view=windows": "/8021x/guides?view=windows", "/security": "/settings/sign-in",
         "/directory": "/directory/people", "/directory?view=devices": "/8021x/devices",
         "/directory?view=device&name=jims-laptop": "/8021x/devices/jims-laptop",
         "/directory?view=roles": "/8021x/roles", "/directory?view=role&name=iot": "/8021x/roles/iot",
         "/directory?view=people": "/directory/people", "/directory?view=domain": "/directory/domain",
         "/directory?view=machines": "/directory/machines", "/directory?view=gpo&match=ex": "/directory/gpo?match=ex",
         "/directory/devices/jims-laptop": "/8021x/devices/jims-laptop", "/directory/roles/iot": "/8021x/roles/iot"}
# each bundle's navigation entries (1.8.2.1.1's bundles against 1.8.6.4's table), written out as the oracle
ENTRIES = {
    "admin": ["Overview", "DNS", "DHCP", "PKI", "Directory", "802.1X", "Secrets", "Federation", "Settings"],
    "fabric-auditor": ["Overview", "DNS", "DHCP", "PKI", "Directory", "802.1X", "Secrets", "Federation"],
    "fabric-network-operator": ["Overview", "DNS", "DHCP", "PKI", "Secrets"],
    "fabric-equipment-operator": ["Overview", "DNS", "PKI", "Directory", "802.1X"],
    "fabric-pki-operator": ["Overview", "PKI", "802.1X"],
    "fabric-helpdesk": ["Overview", "DNS", "PKI", "Directory", "802.1X"],
}

with serve():
    st, _, csp, page = req("GET", "/")
    # covers: web:get.home +
    check("Overview · Health renders with the DEV PREVIEW banner, in the frame (top bar, navigation)",
          st == 200 and "DEV PREVIEW" in page and "services healthy" in page and 'class="topbar"' in page
          and '<nav class="side"' in page and "pi-core · home.arpa" in page)
    check("strict Content-Security-Policy, like production; no script anywhere",
          csp and "default-src 'none'" in csp and "<script" not in page, csp)
    bad = [(p, s) for p, s in ((p, req("GET", p)[0]) for p in PAGES) if s != 200]
    check(f"every page of the navigation renders ({len(PAGES)})", not bad, bad)
    check("no page carries a script or inline style (the strict CSP; pages work with JavaScript off)",
          not [p for p in PAGES if re.search(r"<script|style=|\son[a-z]+=", get(p))])
    detail = PAGES + ["/8021x/devices/jims-laptop", "/8021x/roles/iot", "/secrets/secrets", "/dns/zones?view=tsig"]
    unlabelled = {p: n for p in detail if (n := len(re.findall(r'<span class="light [a-z]*"(?! role="img" '
                                                                   r'aria-label="[^"]+")', get(p))))}
    check("every status light says what it means (role=img, aria-label: never colour alone, 1.8.6.3)",
          not unlabelled, unlabelled)
    cells = re.findall(r"<td( [^>]*)?>", get("/8021x/devices") + get("/kea") + get("/directory/people"))
    check("a list's cells carry their column's name (data-label) for the cards a list folds into on a phone",
          cells and sum("data-label=" in (c or "") for c in cells) >= len(cells) * 0.6, cells[:12])
    page = get("/dns/zones")
    check("the navigation: every entry for the admin, the page shown's entry open with its pages, marked current",
          [label for _, label in nav(page)] == ENTRIES["admin"]
          and '<a href="/dns/zones" class="active" aria-current="page">Zones</a>' in page
          and '<a href="/dns-filter">DNS filter</a>' in page and 'href="/pki/acme"' not in page, nav(page))
    check("narrow screens: the navigation folds behind a Menu button, a checkbox and its label (CSS only)",
          'id="navtoggle"' in page and '<label for="navtoggle" class="navbutton">Menu</label>' in page
          and ".navtoggle:checked~.frame .side{display:block}" in get("/static/app.css"))
    check("the person's menu: sign out (a form, POST with CSRF)", '<details class="usermenu"><summary>dev</summary>'
          in page and 'action="/logout"' in page)
    wrong = {}
    for old, new in MOVED.items():
        st, loc, _, _ = req("GET", old)
        if st != 303 or loc != new:
            wrong[old] = (st, loc)
    check(f"every old address answers with a redirect to its new one ({len(MOVED)}; msg and err dropped)", not wrong,
          wrong)
    # covers: web:get.home -
    check("an unknown page is 404", req("GET", "/nowhere")[0] == 404)

    page = get("/8021x")
    check("802.1X → RADIUS clients: server, RADIUS clients, the add form; no decisions here",
          "radius.home.arpa" in page and "switch1" in page and "not required" in page
          and 'action="/freeradius/clients"' in page and "Recent decisions" not in page.split("<main>")[1])
    st, _, page = post("/freeradius/clients", {"name": "switch2", "address": "192.168.1.9",
                                               "message_authenticator": "1"})
    check("802.1X: add client -> secret shown once, then listed", st == 200 and "shown only now" in page
          and "switch2" in get("/8021x"), st)
    page = get("/8021x/decisions")
    check("802.1X → Recent decisions: accepted and refused, a person's login", "jims-laptop" in page
          and "device disabled" in page and "alice" in page)
    page = get("/8021x/guides?view=switches")
    check("802.1X → Setup guides: Connect a switch — this server's IP, ports, UniFi steps, keep uplinks open",
          "192.168.1.2" in page and "1812" in page and "UniFi" in page and "Force Authorized" in page
          and 'class="section active"' in page)
    page = get("/8021x/guides?view=windows")
    check("802.1X → Setup guides: Connect Windows — both scripts downloadable, groups listed plainly",
          'download="fabric-8021x-tls.ps1"' in page and 'download="fabric-8021x-ttls.ps1"' in page
          and "&lt;/code&gt;" not in page and "<code>staff</code>" in page)
    st, loc, page = post("/freeradius/people", {"group": "contractors", "vlan": "70"})
    check("802.1X: map a group -> back on RADIUS clients, listed, the message from the result (not the address)",
          st == 303 and loc == "/8021x" and "contractors" in page and "may join by password" in flash(page), loc)
    check("the message shows once: the next page has none", flash(get("/8021x")) == "")
    page = get("/kea")
    check("DHCP · Kea: subnets, reservations, leases, reserve form", "192.168.1.0/24" in page and "printer" in page
          and "laptop1.dhcp.home.arpa" in page and 'action="/kea/reservations"' in page)
    check("DHCP named a preview until 0.8.0 (2.1.1.49, manual 1.10.3.9); no other page says so",
          "DHCP is a preview in this release" in page and "a preview in this release" not in get("/8021x"))
    st, loc, page = post("/kea/reservations", {"mac": "02:00:00:00:00:99", "ip": "192.168.1.30", "hostname": "nas"})
    check("Kea: reserve -> listed, said", st == 303 and loc == "/kea" and "192.168.1.30" in page
          and "Reserved 192.168.1.30" in flash(page), (st, loc, flash(page)))
    page = get("/kea?off=1")
    check("Kea: DHCP off shows how to turn it on (the preview's own switch)", 'action="/kea/on"' in page)
    page = get("/dns-filter")
    check("DNS filter: statistics, the most blocked names, its sections",
          "Last 24 hours" in page and "browser.events.data.msn.com" in page and "?view=querylog" in page)
    st, loc, page = post("/dns-filter/rules", {"kind": "block", "name": "www.wikipedia.org", "back": "querylog"})
    check("DNS filter: Block from the query log -> back there, listed in the rules",
          st == 303 and "view=querylog" in loc and "www.wikipedia.org" in get("/dns-filter?view=rules"), loc)
    page = get("/dns/zones?zone=dynamic_zone_var")
    check("DNS · Zones shows records and the add form", "nas" in page and "192.168.1.10" in page)
    st, loc, page = post("/bind9/zone/dynamic_zone_var/add", {"type": "A", "name": "preview", "value": "192.168.1.99"})
    check("adding a record works (in memory), said on the zone's page", st == 303
          and loc == "/dns/zones?zone=dynamic_zone_var" and "192.168.1.99" in page and "Added A preview" in flash(page),
          (loc, flash(page)))
    idx = re.search(r'name="index" value="(\d+)"><input type="hidden" name="name" value="preview"', page)
    post("/bind9/zone/dynamic_zone_var/delete", {"type": "A", "index": idx.group(1) if idx else "-1",
                                                 "name": "preview"})
    page = get("/dns/zones?zone=dynamic_zone_var")
    check("deleting a record works (in memory)", "192.168.1.99" not in page)
    form = page.split('/bind9/zone/dynamic_zone_var/add"')[1].split("</form>")[0]
    css = get("/static/app.css")
    check("record form: type, name, value; priority, weight, port only for MX/SRV; no landing-page fields",
          'name="value"' in form and 'class="f-prio"' in form and form.count('class="f-srv"') == 2
          and 'name="ip"' not in form and 'name="link"' not in form and '<option value="SRV">' in form
          and 'option[value="SRV"]:checked' in css and ".f-srv{display:none}" in css, form)
    st, loc, page = post("/bind9/zone/dynamic_zone_var/add", {"type": "MX", "name": "@", "value": "mail2",
                                                              "priority": "20"})
    check("record form: an MX record from value and priority", "10 mail" in page and "20 mail2" in page, loc)
    st, loc, page = post("/bind9/zone/dynamic_zone_var/add", {"type": "SRV", "name": "_sip._tcp", "value": "pbx",
                                                              "priority": "0", "weight": "5"})
    check("record form refused: an SRV record without its port, saying why",
          st == 303 and "port must be a number" in flash(page), flash(page))
    rows = page.split("<tr")
    ca_row = [row.split("</tr>")[0] for row in rows if ">ca " in row][0]
    info_rows = [row.split("</tr>")[0] for row in rows if ">info<" in row]
    check("fabric's own names marked 'provided by fabric', with the setting instead of a Delete button; the landing "
          "page's info is the admin's since 0.7.1 (2.1.4.6), with its Delete button",
          "provided by fabric" in ca_row and "cname_ca" in ca_row and "Delete</button>" not in ca_row
          and info_rows and all("provided by fabric" not in r and "Delete</button>" in r for r in info_rows),
          (info_rows, ca_row))
    st, loc, page = post("/bind9/zone/dynamic_zone_var/delete", {"type": "CNAME", "index": "3", "name": "ca"})
    check("deleting fabric's own name (ca) is refused, naming its setting",
          "provided by fabric" in flash(page) and "cname_ca" in flash(page) and ">ca " in page, flash(page))
    st, loc, page = post("/bind9/zone/dynamic_zone_var/delete", {"type": "CNAME", "index": "10", "name": "info"})
    after = [row for row in page.split("<tr") if ">info<" in row]
    check("deleting an info record works (the admin's since 0.7.1)",
          "Record deleted" in flash(page) and len(after) == len(info_rows) - 1, flash(page))
    page = get("/dns/zones?view=landing")
    check("Landing page section: what the page is, its links (label, address), the add form with the zone's records",
          "Landing page" in page and "fabric's start page" in page and "https://nas.home.arpa:5001/" in page
          and 'action="/bind9/landing/add"' in page and 'value="A|6|printer"' in page
          and 'action="/bind9/landing/remove"' in page)
    st, loc, page = post("/bind9/landing/add", {"record": "A|6|printer", "link_label": "Printer", "link_port": "631",
                                                "link_path": "/"})
    check("link a record from the landing page -> listed with its port", loc == "/dns/zones?view=landing"
          and "https://printer.home.arpa:631/" in page and "linked from the landing page" in flash(page), loc)
    for form, why in (({"record": "A|6|printer", "link_port": "70000"}, "link port must be"),
                      ({"record": ""}, "pick a record"), ({"record": "MX|12|@"}, "only A, AAAA and CNAME"),
                      ({"record": "A|5|nas"}, "record changed")):
        st, loc, page = post("/bind9/landing/add", form)
        check(f"link refused ({why}), saying why", why in flash(page), flash(page))
    st, loc, page = post("/bind9/landing/remove", {"type": "A", "index": "6", "name": "printer"})
    check("stop linking a record -> gone from the landing page's list", "printer.home.arpa:631" not in page)
    page = get("/dns/zones?zone=dynamic_zone_var")
    check("DNS · Zones: New zone form with 'Hide the public name'; no Remove on the site's own zone",
          'action="/bind9/zones/new"' in page and 'name="hide_public"' in page
          and "/bind9/zones/dynamic_zone_var/remove" not in page)
    page = get("/dns/zones?zone=iot.home.arpa")
    check("DNS · Zones: Remove zone on another zone, its record count shown, the name asked for again",
          'action="/bind9/zones/iot.home.arpa/remove"' in page and "3 record(s)" in page and 'name="confirm"' in page)
    st, loc, page = post("/bind9/zones/new", {"name": "Lab.LAN"})
    # covers: web:post.bind9.zones.new +
    check("New zone: added (normalised) and opened", "zone=lab.lan" in loc and "Zone lab.lan added" in flash(page),
          (loc, flash(page)))
    for form, why in (({"name": "nodots"}, "two labels"), ({"name": "lab.lan"}, "already a zone"),
                      ({"name": "shop.example.com"}, "Hide the public name")):
        st, loc, page = post("/bind9/zones/new", form)
        # covers: web:post.bind9.zones.new -
        check(f"New zone refused ({why}), saying why", why in flash(page), flash(page))
    st, loc, page = post("/bind9/zones/new", {"name": "shop.example.com", "hide_public": "on"})
    check("New zone: a public name with the tick is added", "added" in flash(page), flash(page))
    st, loc, page = post("/bind9/zones/lab.lan/remove", {"confirm": "lab.la"})
    # covers: web:post.bind9.zones.*.remove -
    check("Remove zone refused when the name is typed wrong", "type the zone's name" in flash(page), flash(page))
    st, loc, page = post("/bind9/zones/dynamic_zone_var/remove", {"confirm": "home.arpa"})
    check("Remove zone refused for the site's own zone", "cannot be removed" in flash(page), flash(page))
    st, loc, page = post("/bind9/zones/lab.lan/remove", {"confirm": "lab.lan"})
    # covers: web:post.bind9.zones.*.remove +
    check("Remove zone: removed once its name is typed again", "removed" in flash(page)
          and "zone=lab.lan" not in page, flash(page))
    st, _, _, page = req("POST", "/apply", {"csrf": "dev"})
    check("apply is a no-op that says so", st == 200 and "nothing was rendered or reloaded" in page)
    page = get("/audit")
    check("Overview · Audit log shows the preview's actions", "DNS_ADD" in page and "in memory" in page
          and '<a href="/audit" class="active" aria-current="page">Audit log</a>' in page)
    page = get("/settings/sign-in")
    check("Settings · Sign-in security: each layer, its raises, a lowering shown with who did it, no lower button",
          'action="/security/raise"' in page and "lowered from any" in page
          and "fabricctl security lower" in page and "Lower</button>" not in page and "Turn off" in page)
    page = get("/settings")
    check("Settings · Setup wizard: its first step, the console-only settings read only, its navigation page",
          "Optional parts" in page and "sudo fabricctl setup (a new install)" in page
          and '<a href="/settings" class="active" aria-current="page">Setup wizard</a>' in page, page[:2000])
    st, _, _, page = req("POST", "/settings/step", {"csrf": "dev", "go": "memory", "host_ram_capacity": "6"})
    check("the wizard's Next keeps what was typed", st == 200 and 'value="6"' in page and "today: 8" in page)
    st, _, _, page = req("POST", "/settings/plan", {"csrf": "dev", "host_ram_capacity": "6"})
    check("the wizard's plan: old -> new, the memory plan, what was ignored, Apply",
          st == 200 and "The memory plan" in page and 'action="/settings/apply"' in page)
    st, loc, page = post("/settings/apply", {"plan": "dev-plan"})
    check("the wizard's Apply: a job page saying what was applied", st == 303 and "Settings · apply" in page
          and "Applied (in memory)" in page, (st, loc))
    page = get("/settings/sign-in?signed_in=1&msg=evil")
    check("a step-up sign-in's note is the server's own text, never the query's",
          "Signed in again" in flash(page) and "evil" not in page)
    pages = [get(f"/pki?view={v}") for v in ("ca", "sign", "issue", "inspect", "convert", "issued")]
    check("every PKI · Certificates menu page renders, ACME not among its sub-menu", "Fabric Root CA" in pages[0]
          and "switch-core.home.arpa" in pages[5]
          and "ACME" not in pages[0].split('class="subtabs"')[1].split("</nav>")[0])
    st, _, _, page = req("POST", "/stepca/issue", {"csrf": "dev", "cn": "x"})
    check("generate shows sample downloads and the one-time key warning",
          st == 200 and 'download="device.home.arpa.key"' in page and "only copy of the private key" in page)
    page = get("/")
    tiles = page.split("<section class=\"tiles\">")[1].split("</section>")[0]
    check("Health: one status light per service, each linked to its page", tiles.count('class="light ok"') == 9
          and "pill" not in tiles and 'href="/dns/zones"' in tiles and 'href="/secrets"' in tiles)
    page = get("/overview/doctor")
    check("Overview · Doctor: the Run doctor button", 'action="/overview/doctor"' in page)
    page = get("/overview/updates")
    check("Overview · Updates: the update and roll-back forms",
          'action="/overview/images/postgres/update"' in page and 'action="/overview/images/nginx/rollback"' in page
          and 'action="/overview/images/nginx/update"' not in page)
    st, loc, page = post("/overview/doctor", {})
    check("run doctor -> its job page: each check with its result, Doctor marked in the navigation",
          loc.startswith("/jobs/") and "3 of 4 checks passed" in page and "a sample failure" in page
          and '<a href="/overview/doctor" class="active"' in page, (st, loc))
    st, loc, page = post("/overview/images/postgres/update", {})
    check("update an image -> its job page says what moved", "updated postgres" in page, (st, loc))
    check("refused: a job that is not yours or does not exist", req("GET", "/jobs/no-such-job")[0] == 400)
    page = get("/pki/acme")
    check("PKI · ACME (2.1.5.8): the directory, the enrolled machines, withdraw and enroll forms",
          "acme/acme/directory" in page and "nas.home.arpa" in page and "/bind9/tsig/acme-nas/delete" in page
          and 'action="/stepca/acme/enroll"' in page)
    st, _, _, page = req("POST", "/stepca/acme/enroll", {"csrf": "dev", "host": "printer", "domain": "home.arpa"})
    check("enroll a machine for DNS-01 -> its key, shown once", st == 200 and "acme-printer" in page)
    page = get("/")
    check("Health lists the host changes: a declined one with what it leaves unmanaged",
          "Host changes" in page and "Host trust store" in page and "declined" in page
          and "does not trust fabric&#39;s CA" in page and "not asked" in page, page[-800:])
    page = get("/dns/zones?view=reverse")
    check("reverse zones generated from forward A/AAAA records",
          "1.168.192.in-addr.arpa" in page and "20.168.192.in-addr.arpa" in page
          and "cam-front.iot.home.arpa." in page and ".ip6.arpa" in page)
    check("public address listed without a reverse record", "203.0.113.7" in page and "public address" in page)
    check("forward records show their automatic PTR", "40.1.168.192.in-addr.arpa" in get("/dns/zones"))
    page = get("/dns/zones?view=tsig")
    check("TSIG view lists sample keys", "npm-certbot" in page and "New TSIG key for a zone" in page)
    st, _, _, page = req("POST", "/bind9/tsig/create", {"csrf": "dev", "name": "preview-key", "zone": "home.arpa"})
    check("creating a TSIG key shows its secret and rfc2136.ini once",
          st == 200 and "dns_rfc2136_name = preview-key" in page and 'class="secret"' in page)
    st, loc, page = post("/bind9/tsig/preview-key/delete", {})
    check("deleting a TSIG key -> back on TSIG keys, said", loc == "/dns/zones?view=tsig"
          and "TSIG key preview-key removed" in flash(page), loc)
    page = get("/8021x/devices")
    check("802.1X · Devices: devices with status lights, roles and access",
          "jims-laptop" in page and "VLAN 10" in page and 'class="light bad"' in page
          and 'href="/8021x/devices/jims-laptop"' in page)
    page = get("/8021x/devices/jims-laptop")
    check("a device's page: effective permissions, linked certificate, its key links (with pki:issue / pki:sign)",
          "Join the network with its certificate" in page and "AB:AB:AB" in page and "Generate key + certificate" in page
          and 'href="/pki?view=issue&amp;device=jims-laptop"' in page)
    st, loc, page = post("/directory/devices/_new", {"name": "nas", "type": "server", "macs": "AA-BB-CC-00-00-01",
                                                     "role_trusted": "1", "enabled": "1"})
    check("adding a device (in memory, real validation): MAC normalised, role applied, its page opened",
          loc == "/8021x/devices/nas" and "aa:bb:cc:00:00:01" in page and "VLAN" in page, (st, loc))
    st, loc, page = post("/directory/devices/_new", {"name": "dup", "macs": "aa:bb:cc:00:00:01"})
    check("a MAC already in use is refused with the reason", "already belongs" in flash(page), flash(page))
    st, loc, page = post("/directory/devices/jims-laptop/certs/anything", {"sha256": ":".join(["AB"] * 32)})
    check("unlinking a certificate answers only its exact route (1.8.6.7): another path under certs/ is 404",
          st == 404 and "AB:AB:AB" in get("/8021x/devices/jims-laptop"), st)
    st, loc, page = post("/directory/devices/jims-laptop/certs/unlink", {"sha256": ":".join(["AB"] * 32)})
    check("unlink a certificate by its route", "Certificate unlinked" in flash(page) and "AB:AB:AB" not in page,
          flash(page))
    st, loc, page = post("/directory/roles/iot/delete", {})
    check("a role that still has devices cannot be deleted", "still has" in flash(page), flash(page))
    page = get("/8021x/roles")
    check("802.1X · Device roles lists roles with their grants", "quarantine" in page and "network:mab" in page)
    page = get("/directory/people")
    check("Directory · People (admin): people, add form, reset buttons, Keycloak link for fabric groups",
          "jim@home.arpa" in page and "Keycloak admin console" in page and "/directory/people/_new" in page
          and "Reset sign-in" in page)
    check("Directory · People (admin): disable buttons, the group form and the remove form (2.1.6.30)",
          "/directory/people/sam/disable" in page and "/directory/people/_form/groups" in page
          and "/directory/people/_form/delete" in page)
    st, loc, page = post("/directory/people/sam/disable", {})
    check("disable a person -> listed locked, an enable button instead", "disabled" in flash(page)
          and "/directory/people/sam/enable" in page, loc)
    st, loc, page = post("/directory/people/sam/enable", {})
    check("enable them again", "enabled" in flash(page) and "/directory/people/sam/disable" in page, loc)
    st, loc, page = post("/directory/people/_form/groups", {"uid": "sam", "group": "directory-admins",
                                                            "action": "add"})
    check("put a person in a group (the form picks them)", "added to directory-admins" in flash(page), flash(page))
    st, loc, page = post("/directory/people/_form/delete", {"uid": "sam", "confirm": "sma"})
    check("refused: a removal without the user name typed back", "type the user name" in flash(page), flash(page))
    st, loc, page = post("/directory/people/_form/delete", {"uid": "sam", "confirm": "sam"})
    check("remove a person with the user name typed back -> gone from the list",
          "removed" in flash(page) and "sam@home.arpa" not in page, flash(page))
    page = get("/directory/domain")
    check("Directory · Domain: the domain, its controller running, the password policy",
          "ad.home.arpa" in page and "pi-core.ad.home.arpa" in page and "Minimum length" in page)
    check("Directory · Domain: the roles named plainly, no role's DN (2.1.2.22)",
          "This controller holds all five roles" in page and "NTDS Settings" not in page)
    check("Directory · Domain (admin): the password policy form",
          'action="/directory/domain/password-policy"' in page and 'name="lockout_window_minutes"' in page
          and 'name="complexity"' in page)
    st, loc, page = post("/directory/domain/password-policy",
                         {"minimum_length": "16", "history": "24", "minimum_age_days": "0", "maximum_age_days": "0",
                          "lockout_threshold": "5", "lockout_minutes": "15", "lockout_window_minutes": "15",
                          "complexity": "on"})
    check("password policy saved -> shown, said", "Password policy saved" in flash(page)
          and 'name="minimum_length" required inputmode="numeric" pattern="[0-9]+" value="16"' in page, flash(page))
    for form, why in (({"lockout_minutes": "5", "lockout_window_minutes": "15"}, "at least as long"),
                      ({"minimum_length": "99"}, "from 0 to 64"), ({"history": "lots"}, "whole number")):
        st, loc, page = post("/directory/domain/password-policy", form)
        check(f"password policy refused ({why}), saying why, nothing changed", why in flash(page)
              and 'name="minimum_length" required inputmode="numeric" pattern="[0-9]+" value="16"' in page,
              flash(page))
    page = get("/dns-filter?view=lists&fresh=1")
    check("DNS filter, first fetch running: the page refreshes itself (a meta refresh, no script) and says so",
          '<meta http-equiv="refresh" content="10;url=/dns-filter?view=lists&amp;wait=1">' in page
          and "still being fetched" in page and "<script" not in page, page[:800])
    page = get("/dns-filter?view=lists&fresh=1&wait=30")
    check("DNS filter: after 30 refreshes it stops and says what to do", 'http-equiv="refresh"' not in page
          and "Fetch every list now" in page and "after five minutes" in page)
    page = get("/dns-filter?view=lists")
    check("DNS filter: every ticked list has a copy and the catalogue is read -> no refresh",
          'http-equiv="refresh"' not in page and "still being fetched" not in page)
    page = get("/directory/machines")
    check("Directory · Machines (admin): machines with state, disable/enable and remove, the add form",
          "host-1" in page and "/directory/machines/host-1/disable" in page
          and "/directory/machines/ws2404/enable" in page and "/directory/machines/_new" in page)
    check("Directory · Machines (admin): no per-OU log-on editor (retired in D1, 2.3.6.17)",
          "Who may sign in" not in page and "/directory/logon/" not in page)
    check("Directory · Machines (admin): host groups with their machines and a remove form, the membership and "
          "new-group forms; sudo rules with who made each, remove only for fabric's, the add form (1.6.11.7)",
          "hosts-web" in page and "lan-hosts-web" not in page
          and 'action="/directory/hostgroups/web/delete"' in page
          and 'action="/directory/hostgroups/_form/members"' in page and 'action="/directory/hostgroups/_new"' in page
          and 'action="/directory/sudo/web-restart/delete"' in page and "/directory/sudo/backup/delete" not in page
          and "the site's default" not in page and 'action="/directory/sudo/_new"' in page
          and "/usr/bin/systemctl restart nginx" in page and "read-only" in page)
    st, loc, page = post("/directory/machines/host-1/disable", {})
    check("disable a machine -> back on Machines, said", loc == "/directory/machines" and "host-1 disabled" in
          flash(page), loc)
    page = get("/directory/gpo?match=example")
    check("Directory · Group Policy (admin): what is set, a search with a set form per policy",
          "ExampleText" in page and "/directory/gpo/set" in page and "Example setting" in page
          and 'action="/directory/gpo"' in page)
    check("...the site's enforced controls listed apart, and a policy may be set as a control (2.1.6.20)",
          "fabric: lan controls" in page and "ExampleLocked" in page and 'name="control"' in page)
    page = get("/federation")
    check("Federation: sites with their DC type, replication with a failing neighbour, conflicts, limits, plan",
          "lab.home.arpa" in page and "read-only" in page and "WERR_BADFILE" in page and "CNF:" in page
          and "192.168.20.0/24" in page and "fabric-agent-&lt;dc&gt;" in page)
    page = get("/pki?view=issue&device=printer")
    check("PKI generate form offers devices, prefilled from the device page",
          "<option selected>printer</option>" in page and 'value="printer.home.arpa"' in page)
    page = get("/secrets")
    check("Secrets · Status: unsealed, static seal, engines, a link to fabric's secrets", "Unsealed" in page
          and "static" in page and "fabric/" in page and 'href="/secrets/secrets"' in page)
    page = get("/secrets/disk")
    check("Secrets · Disk encryption: LUKS with the same YubiKey (FIDO2) or USB stick, untested note",
          "systemd-cryptenroll --fido2-device=auto" in page and "/luks.key:UUID=" in page and "Untested" in page)
    page = get("/secrets/secrets")
    check("secrets: fabric's own entry, OpenBao UI link (OIDC), break glass", "fabric/secrets" in page
          and "ui/vault/auth?with=oidc" in page and "break-glass" in page)
    page = get("/secrets/unlock")
    check("Secrets · Unlock methods: slots, kill-switch state, the key-file warning", "Kill switch off" in page
          and "YubiKey 5 Nano" in page and "Remove the key file" in page
          and 'href="/secrets/remove?slot=local"' in page)
    page = get("/secrets/add-security-key")
    check("add security key: PKCS#11 tokens, enrolled one disabled, untested-hardware note; Unlock methods marked",
          "23456799" in page and "already an unlock method" in page and 'name="pin"' in page and "untested" in page
          and 'value="/usr/lib/aarch64-linux-gnu/libykcs11.so.2|23456799"' in page
          and '<a href="/secrets/unlock" class="active"' in page)
    token = "/usr/lib/aarch64-linux-gnu/libykcs11.so.2|23456799"
    st, loc, page = post("/openbao/slots/add-security-key", {"token": token, "pin": "x", "label": "safe key",
                                                             "confirm": "wrong"})
    check("vault changes need the host name typed", loc == "/secrets/unlock" and "to confirm" in flash(page), loc)
    post("/openbao/slots/add-security-key", {"token": token, "pin": "x", "label": "safe key", "confirm": "pi-core"})
    post("/openbao/slots/local/remove", {"confirm": "pi-core"})
    page = get("/secrets/unlock")
    check("add a second key, remove the key file: kill switch armed", "safe key" in page and "Kill switch armed" in page
          and "/etc/fabric/openbao/unseal.key" not in page)
    post("/openbao/rotate", {"confirm": "pi-core"})
    check("rotate: new key version on every present method", "fabric-2" in get("/secrets/unlock"))
    # covers: web:get.8021x.devices.* web:get.8021x.roles.* web:get.secrets.* -
    check("a page per name refuses a name that is not there: a device, a role (the agent's 404), a Secrets page",
          [req("GET", p)[0] for p in ("/8021x/devices/ghost", "/8021x/roles/ghost", "/secrets/nowhere")]
          == [404, 404, 404], [req("GET", p)[0] for p in ("/8021x/devices/ghost", "/8021x/roles/ghost",
                                                            "/secrets/nowhere")])
    # covers: web:get.8021x.devices.* web:get.8021x.roles.* web:get.secrets.* +
    check("...and opens one that is", [req("GET", p)[0] for p in ("/8021x/devices/printer", "/8021x/roles/iot",
                                                                   "/secrets/unlock")] == [200, 200, 200])
    st, _, _, page = req("GET", "/preview/denied")
    check("preview of a refused sign-in", st == 403 and "Your account" in page)

# every navigation page, opened with its permission and refused without it, per bundle (manual 1.8.6.9):
# covers: web:get.overview.doctor web:get.overview.updates web:get.audit web:get.dns.zones web:get.dns-filter +-
# covers: web:get.kea web:get.pki web:get.pki.acme web:get.directory.people web:get.directory.domain +-
# covers: web:get.directory.machines web:get.directory.gpo web:get.8021x web:get.8021x.decisions +-
# covers: web:get.8021x.guides web:get.8021x.devices web:get.8021x.roles web:get.secrets web:get.federation +-
# covers: web:get.settings web:get.settings.sign-in +-
for bundle, entries in ENTRIES.items():
    with serve(None if bundle == "admin" else bundle):
        shown = [label for _, label in nav(get("/" if bundle != "fabric-pki-operator" else "/pki"))]
        check(f"--as {bundle}: the navigation shows exactly its entries ({', '.join(entries)})", shown == entries,
              shown)
        perms, wrong = set(BUNDLES[bundle]), []
        for entry, label, pages in views.NAV:
            for href, plabel, need in pages:
                may = not need or bool(perms & set(need))
                st = req("GET", href)[0]
                if may != (st == 200):
                    wrong.append((href, st))
        check(f"--as {bundle}: every page opens with its permission and is refused (403) without it", not wrong,
              wrong)

with serve("fabric-helpdesk"):
    page = get("/directory/people")
    check("helpdesk: add form and reset buttons", "/directory/people/_new" in page and "Reset sign-in" in page)
    st, _, _, page = req("POST", "/directory/people/_new", {"csrf": "dev", "uid": "dana", "first": "Dana",
                                                            "last": "Lee", "email": "dana@home.arpa"})
    check("helpdesk: add a person -> one-time password shown once", st == 200 and "shown only now" in page
          and "dana" in page)
    st, _, _, page = req("POST", "/directory/people/sam/reset", {"csrf": "dev"})
    check("helpdesk: reset a plain user's sign-in", st == 200 and "sign-in reset" in page)
    st, loc, page = post("/directory/people/jim/reset", {})
    check("helpdesk: an admin's sign-in cannot be reset", "only an admin" in flash(page), flash(page))
    page = get("/directory/people")
    check("helpdesk: disable buttons, but no group or remove form (people:groups, people:remove are admins')",
          "/directory/people/sam/disable" in page and "/directory/people/_form/groups" not in page
          and "/directory/people/_form/delete" not in page)
    st, loc, page = post("/directory/people/sam/disable", {})
    check("helpdesk: disable a plain user", "disabled" in flash(page), flash(page))
    st, loc, page = post("/directory/people/jim/disable", {})
    check("helpdesk: refused: disabling an admin", "only an admin" in flash(page), flash(page))
    page = get("/8021x/devices/jims-laptop")
    check("helpdesk: a device's page without the key and certificate links (no pki:issue or pki:sign, 1.8.6.7)",
          "jims-laptop" in page and "/pki?view=issue" not in page and "/pki?view=sign" not in page)

with serve("fabric-auditor"):
    page = get("/dns/zones")
    check("--as fabric-auditor: records shown, no add form", "nas" in page and "/add" not in page
          and "dev-fabric-auditor" in page)
    page = get("/dns/zones?view=landing")
    check("--as fabric-auditor: the landing page's links shown, no add or remove form",
          "https://nas.home.arpa:5001/" in page and "/bind9/landing/" not in page)
    page = get("/directory/domain")
    check("--as fabric-auditor: the password policy shown, no form (domain:admin)",
          "minimum length" in page and "/directory/domain/password-policy" not in page)
    st, _, _, _ = req("POST", "/directory/domain/password-policy", {"csrf": "dev", "minimum_length": "4"})
    check("--as fabric-auditor: refused: changing the password policy (403, domain:admin)", st == 403, st)
    page = get("/directory/people")
    check("--as fabric-auditor: people listed, no add form or reset buttons",
          "jim@home.arpa" in page and "/directory/people/_new" not in page and "Reset sign-in" not in page
          and "/disable" not in page and "/directory/people/_form/" not in page)
    page = get("/overview/updates")
    check("--as fabric-auditor: the Updates table, but no update or roll-back forms",
          "postgres" in page and "/overview/images/" not in page)
    st, _, _, _ = req("POST", "/overview/images/postgres/update", {"csrf": "dev"})
    check("--as fabric-auditor: refused: an image update (403, images:update)", st == 403, st)
    page = get("/pki/acme")
    check("--as fabric-auditor: the ACME view without enroll or withdraw", "nas.home.arpa" in page
          and "/stepca/acme/enroll" not in page and "/delete" not in page)

prod = views.overview({"user": "u", "csrf": "x", "version": {"version": "1", "build": ""}}, [])
check("production pages never show the banner", "DEV PREVIEW" not in prod)
# every production file of the server: src/webui/ but the preview's folder, and its entry point src/ux/web/server.py
prod_files = [os.path.join(d, f) for d, _, fs in os.walk(WEBUI) for f in fs if f.endswith(".py")
              and "devpreview" not in d and "__pycache__" not in d] + [os.path.join(UX_WEB, "server.py")]
src = "".join(open(p).read() for p in prod_files)
check(f"the production server has no dev switch ({len(prod_files)} files): never imports the preview",
      len(prod_files) > 30 and "import devserver" not in src and "webui.devpreview" not in src
      and "devpreview import" not in src and '"dev"' not in src and "DEV" not in src)
check("dev server listens on 127.0.0.1 unless told otherwise",
      'default="127.0.0.1"' in open(os.path.join(UX_WEB, "devserver.py")).read())
sys.exit(1 if FAILED else 0)
