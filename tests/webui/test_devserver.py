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


def change_ids(page):
    """The ids of the changes a Review lists, in order."""
    return re.findall(r'action="/changes/[a-z]+/drop">.*?name="id" value="([^"]+)"', page, re.S)


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
         "/pki/acme", "/directory", "/directory/people", "/directory/groups", "/directory/computers", "/directory/policies",
         "/directory/policies/gpo", "/directory/policies/sudo",
         "/8021x", "/8021x/decisions", "/8021x/guides", "/8021x/devices", "/8021x/roles", "/secrets", "/secrets/unlock",
         "/secrets/disk", "/federation", "/settings", "/settings/sign-in", "/account", "/account/groups"]
# 1.8.6.4's moved addresses -> where each answers now
MOVED = {"/bind9": "/dns/zones", "/bind9?zone=iot.home.arpa&msg=x": "/dns/zones?zone=iot.home.arpa",
         "/bind9?view=tsig": "/dns/zones?view=tsig", "/stepca": "/pki", "/stepca?view=sign": "/pki?view=sign",
         "/stepca?view=acme": "/pki/acme", "/openbao": "/secrets", "/openbao?view=unlock": "/secrets/unlock",
         "/openbao?view=disk&err=hello": "/secrets/disk", "/freeradius": "/8021x",
         "/freeradius?view=windows": "/8021x/guides?view=windows", "/security": "/settings/sign-in",
         "/directory?view=devices": "/8021x/devices", "/directory?view=nonsense": "/directory",
         "/directory?view=device&name=jims-laptop": "/8021x/devices/jims-laptop",
         "/directory?view=roles": "/8021x/roles", "/directory?view=role&name=iot": "/8021x/roles/iot",
         "/directory?view=people": "/directory/people", "/directory?view=domain": "/directory/policies",
         "/directory?view=machines": "/directory/computers", "/directory/machines": "/directory/computers", "/directory?view=gpo&match=ex": "/directory/policies/gpo?match=ex",
         "/directory/domain": "/directory/policies", "/directory/gpo?match=ex": "/directory/policies/gpo?match=ex",
         "/directory/devices/jims-laptop": "/8021x/devices/jims-laptop", "/directory/roles/iot": "/8021x/roles/iot"}
# each bundle's navigation entries (1.8.2.1.1's bundles against 1.8.6.4's table), written out as the oracle
ENTRIES = {
    "admin": ["Overview", "My account", "DNS", "DHCP", "PKI", "Directory", "802.1X", "Secrets", "Federation",
              "Settings"],
    "fabric-auditor": ["Overview", "My account", "DNS", "DHCP", "PKI", "Directory", "802.1X", "Secrets", "Federation"],
    "fabric-network-operator": ["Overview", "My account", "DNS", "DHCP", "PKI", "Secrets"],
    "fabric-equipment-operator": ["Overview", "My account", "DNS", "PKI", "Directory", "802.1X"],
    "fabric-pki-operator": ["Overview", "My account", "PKI", "802.1X"],
    "fabric-helpdesk": ["Overview", "My account", "DNS", "PKI", "Directory", "802.1X"],
    "none": ["My account"],                    # a person of the domain with no fabric role (2.1.8.11)
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
    detail = PAGES + ["/8021x/devices/jims-laptop", "/8021x/roles/iot", "/secrets/secrets", "/dns/zones?view=tsig",
                      "/directory/people/jim", "/directory/people/lee", "/directory/people/_new",
                      "/directory/groups/lab-users", "/directory/groups/directory-admins", "/directory/groups/_new"]
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
          and "fabricctl security lower" in page and "Lower</button>" not in page and "Turn off" not in page
          and 'href="/directory/kerberos"' in page)
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
    check("802.1X · Devices: devices with status lights, owners and roles linked, access; Add device in the actions "
          "bar, no form on the list", "jims-laptop" in page and "VLAN 10" in page and 'class="light bad"' in page
          and 'href="/8021x/devices/jims-laptop"' in page and 'href="/8021x/devices/_new"' in page
          and 'href="/directory/people/jim"' in page and 'href="/8021x/roles/trusted"' in page
          and 'method="post"' not in page.split("<main", 1)[1], page[-3000:])
    page = get("/8021x/devices/jims-laptop")
    check("a device's page: effective permissions, linked certificate, its key links (with pki:issue / pki:sign) in "
          "the actions bar; the owner chosen from People; Unlink as its own form, never in a table cell",
          "Join the network with its certificate" in page and "AB:AB:AB" in page and "Generate key + certificate" in page
          and 'href="/pki?view=issue&amp;device=jims-laptop"' in page and '<select name="owner">' in page
          and "<option selected>jim</option>" in page and 'action="/directory/devices/jims-laptop/certs/unlink"' in page
          and "<td" not in page.split("Certificates", 1)[1].split("</section>", 1)[0], page[-4000:])
    page = get("/8021x/devices/_new")
    # covers: web:get.8021x.devices.* +
    check("Add device: its own page, the owner a choice of People", 'action="/directory/devices/_new"' in page
          and '<select name="owner">' in page and "<option>sam</option>" in page)
    st, loc, page = post("/directory/devices/_new", {"name": "nas", "type": "server", "macs": "AA-BB-CC-00-00-01",
                                                     "role_trusted": "1", "enabled": "1", "owner": "jim"})
    check("Add device: held on Devices until its Apply", loc == "/8021x/devices"
          and "Add device nas" in flash(page) and "/8021x/devices/nas" not in page, (st, loc, flash(page)))
    post("/changes/devices/apply", {})
    page = get("/8021x/devices/nas")
    check("...applied (in memory, real validation): MAC normalised, role applied", "aa:bb:cc:00:00:01" in page
          and "VLAN" in page, page[-3000:])
    post("/directory/devices/_new", {"name": "dup", "macs": "aa:bb:cc:00:00:01"})
    st, loc, page = post("/changes/devices/apply", {})
    check("a MAC already in use is refused at Apply with the reason", "already belongs" in page, page[-1500:])
    post("/changes/devices/discard", {})
    st, loc, page = post("/directory/devices/jims-laptop/certs/anything", {"sha256": ":".join(["AB"] * 32)})
    check("unlinking a certificate answers only its exact route (1.8.6.7): another path under certs/ is 404",
          st == 404 and "AB:AB:AB" in get("/8021x/devices/jims-laptop"), st)
    st, loc, page = post("/directory/devices/jims-laptop/certs/unlink", {"sha256": ":".join(["AB"] * 32)})
    check("unlink a certificate: held, back on the device", loc == "/8021x/devices/jims-laptop"
          and "Unlink a certificate from device jims-laptop" in flash(page), (loc, flash(page)))
    post("/changes/devices/apply", {})
    check("...applied: the certificate is gone", "AB:AB:AB" not in get("/8021x/devices/jims-laptop"))
    st, loc, page = post("/directory/devices/nas", {"type": "server", "macs": "aa:bb:cc:00:00:01", "enabled": "1"})
    check("Save the device: held, back on it", loc == "/8021x/devices/nas" and "Change device nas" in flash(page),
          (loc, flash(page)))
    post("/directory/devices/nas/delete", {})
    page = get("/changes/devices")
    check("the Review: the change with its old and new fields, then the removal", "Change device nas" in page
          and "Remove device nas" in page and "trusted" in page, page[-3000:])
    post("/changes/devices/apply", {})
    check("...applied: nas removed", req("GET", "/8021x/devices/nas")[0] == 404)
    page = get("/8021x/roles")
    check("802.1X · Device roles lists roles with their grants; Add device role in the actions bar",
          "quarantine" in page and "network:mab" in page and 'href="/8021x/roles/_new"' in page)
    page = get("/8021x/roles/trusted")
    check("a device role's page: what it grants, its devices linked, Edit and Remove",
          'href="/8021x/devices/jims-laptop"' in page and 'action="/directory/roles/trusted"' in page
          and 'action="/directory/roles/trusted/delete"' in page, page[-3000:])
    page = get("/8021x/roles/_new")
    # covers: web:get.8021x.roles.* +
    check("Add device role: its own page", 'action="/directory/roles/_new"' in page and 'name="perm_' in page)
    st, loc, page = post("/directory/roles/_new", {"name": "cams", "priority": "50", "vlan": "40"})
    check("Add device role: held on Device roles", loc == "/8021x/roles" and "Add device role cams" in flash(page),
          (loc, flash(page)))
    post("/changes/roles/apply", {})
    check("...applied: the role is there", "VLAN" in get("/8021x/roles/cams") and req("GET", "/8021x/roles/cams")[0] == 200)
    post("/directory/roles/iot/delete", {})
    st, loc, page = post("/changes/roles/apply", {})
    check("a role that still has devices cannot be removed: refused at Apply with why", "still has" in page,
          page[-1500:])
    post("/changes/roles/discard", {})
    check("refused: an unknown device form (404)",
          req("POST", "/directory/devices/jims-laptop/frob", {"csrf": "dev"})[0] == 404)
    page = get("/directory")
    # covers: web:get.directory +
    check("Directory · Overview: the domain, its functional level, its DCs writable or read-only, the roles named "
          "plainly, replication, the sites and the counts linking to their pages",
          "ad.home.arpa" in page and "Windows Server 2008 R2" in page and "pi-edge" in page and "read-only" in page
          and "holds all five roles" in page and "1 link replicating" in page and "edge, lan" in page
          and 'href="/directory/people">People</a>' in page and "NTDS Settings" not in page, page[-3000:])
    page = get("/directory/people")
    check("Directory · People (admin): each person's name linking to their page, user name, e-mail, state light and "
          "last sign-in; Add person; no action inside a row (1.8.6.3)",
          'href="/directory/people/jim"' in page and "jim@home.arpa" in page and 'aria-label="locked"' in page
          and "2026-10-22 08:40" in page and "never" in page and 'href="/directory/people/_new"' in page
          and "<form method=\"post\"" not in page.split("<tbody>", 1)[1].split("</tbody>", 1)[0], page[-3000:])
    page = get("/directory/people?q=LOCKED")
    check("search by any column (the state here, any case): only lee", "lee@home.arpa" in page
          and "jim@home.arpa" not in page and 'value="locked"' in page, page[-2000:])
    check("a search nobody matches says so", "Nobody matches" in get("/directory/people?q=zzz"))
    many = {"users": [{"uid": f"u{i:03}", "name": f"User {i:03}", "mail": "", "locked": False, "state": "active",
                       "last_logon": ""} for i in range(120)], "groups": []}
    pages = [views.people({"user": "u", "csrf": "x", "perms": ["people:read"]}, "list", people=many,
                          query={"page": n}) for n in ("1", "3", "9", "x")]
    check("paged 50 to a page: page 1 holds u000-u049 and a Next link; page 3 the last 20 and a Previous; a page "
          "past the end or not a number shows the last or the first",
          "u049" in pages[0] and "u050" not in pages[0] and "page=2" in pages[0] and "Page 1 of 3" in pages[0]
          and "u119" in pages[1] and "u099" not in pages[1] and "page=2" in pages[1] and "Page 3 of 3" in pages[2]
          and "Page 1 of 3" in pages[3])
    page = get("/directory/people/jim")
    check("a person's page: their details (the 15 fields' filled ones), state and last sign-in, sites, groups, the "
          "certificates fabric issued them and their devices, linked to 802.1X",
          "Engineer" in page and "2026-10-22 08:40" in page and "directory-admins" in page and "CN=jim" in page
          and 'href="/8021x/devices/jims-laptop"' in page and 'aria-label="active"' in page, page[-3000:])
    check("...the actions bar: Reset password and Disable (no Unlock: not locked out); the Edit form with every field "
          "filled from the domain; Groups; Remove with the user name typed back",
          "Reset password" in page and "/directory/people/jim/disable" in page and "/unlock" not in page
          and 'name="employee_id"' in page and 'name="title" value="Engineer"' in page
          and 'action="/directory/people/jim/groups"' in page and 'action="/directory/people/jim/delete"' in page
          and 'name="confirm"' in page)
    check("...a locked-out person's page offers Unlock", "/directory/people/lee/unlock" in get("/directory/people/lee"))
    page = get("/directory/people/nobody")
    # covers: web:get.directory.people -
    check("a person who is not there: fabric-agent's refusal said on the page, no form",
          "no person nobody" in page and "/directory/people/nobody/" not in page, page[-1500:])
    check("refused: an address past a person's page (404)", req("GET", "/directory/people/jim/more")[0] == 404)
    page = get("/directory/people/_new")
    check("Add person on its own page: user name, e-mail, first and last names",
          'action="/directory/people/_new"' in page and 'name="uid"' in page and 'name="first"' in page)
    # Apply per page (manual 1.8.6.5): every change waits on its page until that page's Apply
    st, loc, page = post("/directory/people/sam/disable", {})
    # covers: web:post.directory.people.*.* +
    check("disable a person: held for People's Apply, back on their page, said; nothing changed yet",
          loc == "/directory/people/sam" and "Waiting for Apply: Disable sam" in flash(page)
          and "/directory/people/sam/disable" in page, flash(page))
    check("the top bar: 1 change pending, Review, Apply and Discard; the navigation marks People",
          "<strong>1 change pending</strong>" in page and 'action="/changes/people/apply"' in page
          and 'action="/changes/people/discard"' in page and 'href="/changes/people">Review</a>' in page
          and re.search(r'href="/directory/people"[^>]*>People <span class="count"[^>]*>1</span>', page), page[:2500])
    check("another page's top bar shows none of People's changes", "change pending" not in get("/directory/computers"))
    page = get("/changes/people")
    # covers: web:get.changes.* +
    check("Review: the change in a sentence, was and becomes (enabled: yes, then no), Drop, Apply and Discard all",
          "Disable sam" in page and len(change_ids(page)) == 1 and "Apply 1 change" in page
          and ">enabled: yes<" in page and ">enabled: no<" in page
          and 'action="/changes/people/discard"' in page
          and '<a href="/directory/people" class="active" aria-current="page">' in page, page[-2500:])
    st, loc, page = post("/changes/people/apply", {})
    # covers: web:post.changes.*.apply +
    check("Apply: one job, its queue on the Review (Disable sam done), nothing left pending",
          loc == "/changes/people" and "Applying" in flash(page) and "Disable sam" in page
          and "done" in page and "Nothing waits on this page" in page, page[-2500:])
    page = get("/directory/people/sam")
    check("...sam is disabled now (Enable instead), the bar gone", "/directory/people/sam/enable" in page
          and 'aria-label="disabled"' in page and "change pending" not in page)
    st, loc, page = post("/directory/people/sam/edit", {"first": "Sam", "last": "Reed", "title": "Technician",
                                                         "country": "gb", "manager": "jim", "email": "sam@home.arpa"})
    # covers: web:post.directory.people.*.edit +
    check("Edit: only the changed fields held (title, country), back on the page", loc == "/directory/people/sam"
          and "Waiting for Apply: Edit sam" in flash(page), flash(page))
    st, loc, page = post("/directory/people/sam/edit", {"first": "Sam", "title": ""})
    # covers: web:post.directory.people.*.edit -
    check("refused: an Edit that changes nothing (the title not yet applied), said; nothing more pending",
          "nothing changed" in flash(page) and "<strong>1 change pending</strong>" in page, flash(page))
    st, loc, page = post("/directory/people/lee/unlock", {})
    # covers: web:post.directory.people.*.unlock +
    check("Unlock: held, back on lee's page", loc == "/directory/people/lee" and "Waiting for Apply: Unlock lee"
          in flash(page), flash(page))
    post("/directory/people/sam/enable", {})
    st, loc, page = post("/directory/people/sam/groups", {"group": "directory-admins", "action": "add"})
    # covers: web:post.directory.people.*.groups +
    check("Groups: add sam to a group, held", "Waiting for Apply: Add sam to group directory-admins" in flash(page),
          flash(page))
    st, loc, page = post("/directory/people/sam/delete", {"confirm": "sma"})
    # covers: web:post.directory.people.*.delete -
    check("Remove: held from the person's page, back to People (the typed name checked at Apply)",
          loc == "/directory/people" and "Waiting for Apply: Remove sam" in flash(page), flash(page))
    page = get("/changes/people")
    check("five changes held, in the order made; only the changed fields shown, old and new",
          [m for m in re.findall(r'data-label="Change">([^<]+)', page)][:5]
          == ["Edit sam", "Unlock lee", "Enable sam", "Add sam to group directory-admins", "Remove sam"]
          and "title: Technician" in page and "country: GB" not in page and "country: gb" in page
          and "first:" not in page and "group: directory-admins" in page,
          re.findall(r'data-label="Change">([^<]+)', page))
    st, loc, page = post("/changes/people/apply", {})
    # covers: web:post.changes.*.apply -
    check("Apply stops at the first failure and says which: the removal without its name typed back; the rest done",
          "type the user name" in page and page.count("— failed") + page.count("failed — ") >= 1
          and len(change_ids(page)) == 1 and "Remove sam" in page, page[-3000:])
    page = get("/directory/people/sam")
    check("...applied: sam's title and country changed, enabled, in directory-admins; lee unlocked",
          "Technician" in page and ">GB<" in page and 'aria-label="active"' in page and "directory-admins" in page
          and 'aria-label="active"' in get("/directory/people/lee"), page[-3000:])
    post("/changes/people/discard", {})                # the failed removal
    st, loc, page = post("/directory/people/sam/edit", {"country": "Germany"})
    st, loc, page = post("/changes/people/apply", {})
    check("refused at Apply: a country that is not two letters, said", "two-letter" in page, page[-2000:])
    post("/changes/people/discard", {})
    st, loc, page = post("/directory/people/sam/groups", {"group": "directory-admins", "action": "remove"})
    check("Groups: take sam out of a group, held", "Remove sam from group directory-admins" in flash(page),
          flash(page))
    post("/changes/people/discard", {})
    st, loc, page = post("/changes/people/drop", {"id": "no-such-change"})
    # covers: web:post.changes.*.drop -
    check("refused: dropping a change that is not there", "no such change" in flash(page), flash(page))
    post("/directory/people/sam/delete", {"confirm": "sam"})
    st, loc, page = post("/changes/people/drop", {"id": change_ids(get("/changes/people"))[0]})
    # covers: web:post.changes.*.drop +
    check("Drop the one change: nothing pending", "0 still pending" in flash(page) and not change_ids(page),
          flash(page))
    post("/directory/people/sam/delete", {"confirm": "sam"})
    st, loc, page = post("/changes/people/discard", {})
    # covers: web:post.changes.*.discard +
    check("Discard: every pending change of the page dropped, back on the page", loc == "/directory/people"
          and "Discarded 1 pending change" in flash(page) and "change pending" not in page
          and "sam@home.arpa" in page, flash(page))
    st, loc, page = post("/changes/people/apply", {})
    check("refused: Apply with nothing pending, said", "nothing is pending" in flash(page), flash(page))
    st, loc, page = post("/changes/people/discard", {})
    # covers: web:post.changes.*.discard -
    check("Discard with nothing pending: says nothing was dropped", "Discarded 0" in flash(page), flash(page))
    # covers: web:get.changes.* -
    check("refused: a Review of a page that has none (404)", req("GET", "/changes/nowhere")[0] == 404)
    for path in ("/directory/people/_form/delete", "/directory/people/sam/rename", "/directory/people/sam/x/edit"):
        st, *_ = req("POST", path, {"csrf": "dev", "uid": "sam", "confirm": "sam"})
        check(f"refused: {path} (404: not a form of People)", st == 404, st)
    post("/directory/people/sam/delete", {"confirm": "sam"})
    st, loc, page = post("/changes/people/apply", {})
    # covers: web:post.directory.people.*.delete +
    check("remove a person with the user name typed back, applied -> gone from the list",
          "sam@home.arpa" not in get("/directory/people"), page[-1500:])
    page = get("/directory/groups")
    # covers: web:get.directory.groups +
    check("Directory · Groups: each group with its kind, members and description, linking to its page; Create group",
          'href="/directory/groups/lab-users"' in page and "the site&#39;s" in page and "a tier&#39;s" in page
          and "AD&#39;s own" in page and 'href="/directory/groups/_new"' in page, page[-3000:])
    page = get("/directory/groups?q=tier")
    check("...searched by kind: a tier's group alone", "directory-admins" in page and "lab-users" not in page)
    page = get("/directory/groups/lab-users")
    check("a group's two levels: what it grants (a sudo rule, 802.1X's VLAN), its managers and their controls, its "
          "members linked to their pages; Delete group (the site's own), the managers' form, the member forms",
          "lab-restart" in page and "VLAN 30" in page and "dev may add and remove members" in page
          and 'href="/directory/people/sam"' in page and 'action="/directory/groups/lab-users/delete"' in page
          and 'action="/directory/groups/lab-users/managers"' in page and 'name="member"' in page, page[-3000:])
    page = get("/directory/groups/Domain%20Admins")
    check("an AD group: why it is not changed here, no form at all", "left as AD has them" in page
          and 'method="post"' not in page.split("<main", 1)[1].split("</main>", 1)[0], page[-2000:])
    page = get("/directory/groups/directory-admins")
    check("a tier's group: shown, but not deleted here", "only the tier above it" in page
          and "/directory/groups/directory-admins/delete" not in page)
    page = get("/directory/groups/nope")
    # covers: web:get.directory.groups -
    check("a group that is not there: the refusal said on the page", "no group nope" in page)
    st, loc, page = post("/directory/groups/_new", {"name": "ops", "description": "Operations"})
    # covers: web:post.directory.groups._new +
    check("Create group: held for the Groups page's Apply, back to Groups", loc == "/directory/groups"
          and "Waiting for Apply: Add group ops" in flash(page), flash(page))
    st, loc, page = post("/directory/groups/lab-users/members", {"action": "add", "member": "lee"})
    # covers: web:post.directory.groups.*.members +
    check("a member added: held, back on the group's page", loc == "/directory/groups/lab-users"
          and "Add lee to group lab-users" in flash(page), flash(page))
    st, loc, page = post("/directory/groups/lab-users/managers", {"managers": "dev, jim", "add": "yes",
                                                                  "only_from": "site-lan"})
    # covers: web:post.directory.groups.*.managers +
    check("its managers set: held", "Change the managers of lab-users" in flash(page), flash(page))
    st, loc, page = post("/changes/groups/apply", {})
    check("Apply on Groups: all three done, nothing left pending", "Nothing waits on this page" in page, page[-2500:])
    page = get("/directory/groups/lab-users")
    check("...lee a member, dev and jim managers who may add only, people of site-lan only",
          'href="/directory/people/lee"' in page and "dev, jim may add members, people of site-lan only" in page,
          page[-2500:])
    check("...ops listed", 'href="/directory/groups/ops"' in get("/directory/groups"))
    st, loc, page = post("/directory/groups/lab-users/delete", {})
    st, loc, page = post("/changes/groups/apply", {})
    # covers: web:post.directory.groups.*.delete -
    check("refused at Apply: deleting a group still in use, naming where (a sudo rule, 802.1X)",
          "is in use" in page and "sudo rule lab-restart" in page, page[-2000:])
    post("/changes/groups/discard", {})
    st, loc, page = post("/directory/groups/ops/delete", {})
    st, loc, page = post("/changes/groups/apply", {})
    # covers: web:post.directory.groups.*.delete +
    check("delete a group in use nowhere: gone", 'href="/directory/groups/ops"' not in get("/directory/groups"),
          page[-1500:])
    st, loc, page = post("/directory/groups/_new", {"name": "Bad Name", "description": ""})
    st, loc, page = post("/changes/groups/apply", {})
    # covers: web:post.directory.groups._new -
    check("refused at Apply: a group's name that is not one, said", "2-64 of a-z" in page, page[-1500:])
    post("/changes/groups/discard", {})
    st, loc, page = post("/directory/groups/nope/members", {"action": "add", "member": "lee"})
    # covers: web:post.directory.groups.*.members -
    check("refused when held: a member of a group that is not there, said, nothing pending",
          "no group nope" in flash(page) and "change pending" not in page, flash(page))
    for path in ("/directory/groups/a/b/members", "/directory/groups/lab-users/rename"):
        check(f"refused: {path} (404)", req("POST", path, {"csrf": "dev"})[0] == 404)
    page = get("/directory/policies")
    # covers: web:get.directory.policies +
    check("Directory · Policies: the three kinds as tabs (Password policy shown), the password policy",
          'href="/directory/policies/gpo"' in page and 'href="/directory/policies/sudo"' in page
          and "Minimum length" in page and '<a href="/directory/policies" class="active"' in page, page[-3000:])
    check("Directory · Policies (admin): the password policy form",
          'action="/directory/domain/password-policy"' in page and 'name="lockout_window_minutes"' in page
          and 'name="complexity"' in page)
    st, loc, page = post("/directory/domain/password-policy",
                         {"minimum_length": "16", "history": "24", "minimum_age_days": "0", "maximum_age_days": "0",
                          "lockout_threshold": "5", "lockout_minutes": "15", "lockout_window_minutes": "15",
                          "complexity": "on"})
    check("password policy: held for Policies' Apply", "Waiting for Apply: Change the password policy"
          in flash(page) and "<strong>1 change pending</strong>" in page, flash(page))
    st, loc, page = post("/changes/policies/apply", {})
    check("...applied: the policy, then written into the domain (restarting only what changed), both done; shown",
          "Change the password policy" in page and "Write the policy into the domain" in page
          and "failed" not in page.split("<h2>Queue</h2>")[-1]
          and 'name="minimum_length" required inputmode="numeric" pattern="[0-9]+" value="16"'
          in get("/directory/policies"), page[-2500:])
    for form, why in (({"lockout_minutes": "5", "lockout_window_minutes": "15"}, "at least as long"),
                      ({"minimum_length": "99"}, "from 0 to 64"), ({"history": "lots"}, "whole number")):
        post("/directory/domain/password-policy", form)
        st, loc, page = post("/changes/policies/apply", {})
        check(f"password policy refused at Apply ({why}), saying why; the change still pending, nothing changed",
              why in page and len(change_ids(page)) == 1
              and 'name="minimum_length" required inputmode="numeric" pattern="[0-9]+" value="16"'
              in get("/directory/policies"), page[-2000:])
        post("/changes/policies/discard", {})
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
    page = get("/directory/computers")
    # covers: web:get.directory.computers +
    check("Directory · Computers (admin): each computer with its state, type, sites, OS, folder, machine groups and "
          "last sign-in, linking to its page; the search with its type and site filters; Add computer",
          'href="/directory/computers/host-1"' in page and "machines/servers" in page and "Windows 11 Pro" in page
          and "hosts-web" in page and "2026-10-05 08:12" in page and 'name="type"' in page and 'name="site"' in page
          and 'href="/directory/computers/_new"' in page and 'aria-label="disabled"' in page, page[-3000:])
    check("Directory · Computers: no per-OU log-on editor (retired in D1, 2.3.6.17), no sudo rules (Policies)",
          "Who may sign in" not in page and "/directory/logon/" not in page and "/directory/sudo/" not in page)
    page = get("/directory/computers?type=server")
    check("...filtered by type: the server alone", "host-1" in page and "jims-laptop" not in page)
    page = get("/directory/computers?site=edge&q=laptop")
    check("...by site and a search: the laptop in site edge alone", "jims-laptop" in page
          and 'href="/directory/computers/host-1"' not in page and '<option selected>edge</option>' in page)
    page = get("/directory/computers?type=toaster&site=mars")
    check("...a filter value that is not a choice is dropped, not refused: every computer",
          "host-1" in page and "jims-laptop" in page)
    page = get("/directory/computers/host-1")
    check("a computer's page: its state, facts (type, sites, OS, folder, machine groups), the grants that reach it "
          "and what each gives there",
          "<dt>Folder</dt><dd>machines/servers</dd>" in page and "<dt>Machine groups</dt><dd>hosts-web</dd>" in page
          and "server-administrators" in page and "sign-in: keyboard, remote; local administrator; sudo: ALL" in page
          and 'aria-label="enabled"' in page, page[-4000:])
    check("...its actions: Disable, Change type, Sites, Move to folder, Machine groups, Add a service, Remove",
          all(f'action="/directory/machines/host-1/{op}"' in page
              for op in ("disable", "type", "sites", "move", "groups", "keytab", "delete")), page[-4000:])
    page = get("/directory/computers/jims-laptop")
    check("...the 802.1X device of the same name, linked; a disabled computer offers Enable",
          'href="/8021x/devices/jims-laptop"' in page and 'action="/directory/machines/jims-laptop/enable"' in page)
    page = get("/directory/computers/nope")
    # covers: web:get.directory.computers -
    check("a computer that is not there: fabric-agent's refusal said on the page, no form",
          "no machine nope in the domain" in page and "/directory/machines/nope/" not in page, page[-1500:])
    check("refused: an address past a computer's page (404)", req("GET", "/directory/computers/host-1/x")[0] == 404)
    page = get("/directory/computers/_new")
    check("Add computer on its own page: host name, type, managed",
          'action="/directory/machines/_new"' in page and 'name="name"' in page and 'name="managed"' in page)
    page = get("/directory/computers/_groups")
    check("the Machine groups tab: each group with its computers linked, delete, the membership and new-group forms",
          'href="/directory/computers/host-1"' in page and 'action="/directory/hostgroups/web/delete"' in page
          and 'action="/directory/hostgroups/_form/members"' in page and 'action="/directory/hostgroups/_new"' in page
          and 'class="section active"' in page, page[-3000:])
    st, loc, page = post("/directory/hostgroups/_new", {"name": "db"})
    check("a new machine group: held on Computers, back on its tab", loc == "/directory/computers/_groups"
          and "Waiting for Apply: Add machine group db" in flash(page), (loc, flash(page)))
    post("/changes/machines/discard", {})
    st, loc, page = post("/directory/machines/host-1/type", {"type": "desktop", "move": "yes"})
    # covers: web:post.directory.machines.*.type +
    check("Change type: held, back on the computer's page", loc == "/directory/computers/host-1"
          and "Waiting for Apply: Set the type of host-1" in flash(page), (loc, flash(page)))
    st, loc, page = post("/directory/machines/host-1/sites", {"action": "add", "site": "edge"})
    # covers: web:post.directory.machines.*.sites +
    check("Sites: held, back on its page", "Change the sites of host-1" in flash(page), flash(page))
    st, loc, page = post("/directory/machines/host-1/move", {"path": "machines/servers/web"})
    # covers: web:post.directory.machines.*.move +
    check("Move to folder: held", "Waiting for Apply: Move host-1" in flash(page), flash(page))
    st, loc, page = post("/directory/machines/host-1/groups", {"action": "remove", "group": "hosts-web"})
    # covers: web:post.directory.machines.*.groups +
    check("Machine groups: taking it out of one held as the group's member change", loc == "/directory/computers/host-1"
          and "Remove host-1 from machine group hosts-web" in flash(page), flash(page))
    st, loc, page = post("/changes/machines/apply", {})
    check("...the four applied on one Review: its type, sites, folder and machine groups changed",
          page.count(">done<") >= 4 and "Nothing waits" in page, page[-2500:])
    page = get("/directory/computers/host-1")
    check("...and its page says so", "<dt>Type</dt><dd>Desktop</dd>" in page and "edge, lan" in page
          and "<dt>Folder</dt><dd>machines/servers/web</dd>" in page and "<dt>Machine groups</dt><dd>none</dd>" in page,
          page[-4000:])
    post("/directory/machines/host-1/type", {"type": "toaster"})
    st, loc, page = post("/changes/machines/apply", {})
    # covers: web:post.directory.machines.*.type -
    check("refused at Apply: a type that is not one, why shown", "type: one of" in page, page[-1500:])
    post("/changes/machines/discard", {})
    post("/directory/machines/host-1/move", {"path": "people"})
    st, loc, page = post("/changes/machines/apply", {})
    # covers: web:post.directory.machines.*.move -
    check("refused at Apply: a folder outside OU=machines", "only to a folder under OU=machines" in page, page[-1500:])
    post("/changes/machines/discard", {})
    post("/directory/machines/host-1/sites", {"action": "add", "site": "mars"})
    st, loc, page = post("/changes/machines/apply", {})
    # covers: web:post.directory.machines.*.sites -
    check("refused at Apply: a site that is not there", "no site mars" in page, page[-1500:])
    post("/changes/machines/discard", {})
    post("/directory/machines/host-1/groups", {"action": "add", "group": "hosts-nope"})
    st, loc, page = post("/changes/machines/apply", {})
    # covers: web:post.directory.machines.*.groups -
    check("refused at Apply: a machine group that is not there", "no host group hosts-nope" in page, page[-1500:])
    post("/changes/machines/discard", {})
    st, loc, page = post("/directory/machines/host-1/keytab", {"service": "HTTP", "user": "www-data"})
    # covers: web:post.directory.machines.*.keytab +
    check("Add a service: the one command shown at once (200, not held, nothing pending), its SPNs named",
          st == 200 and "sudo fabric-keytab --machine host-1 --service HTTP --user www-data" in page
          and "HTTP/HOST-1" in page and "change pending" not in page, page[-2000:])
    st, loc, page = post("/directory/machines/host-1/keytab", {"service": "cifs", "user": "www-data"})
    # covers: web:post.directory.machines.*.keytab -
    check("...refused: the machine's own service class, why said on its page", loc == "/directory/computers/host-1"
          and "not the machine" in flash(page), (loc, flash(page)))
    st, loc, page = post("/directory/machines/_new", {"name": "ws9", "type": "desktop", "managed": "yes"})
    # covers: web:post.directory.machines._new +
    check("Add computer: held, back to Computers", loc == "/directory/computers"
          and "Waiting for Apply: Add machine ws9" in flash(page), (loc, flash(page)))
    st, loc, page = post("/changes/machines/apply", {})
    check("...applied: its one-time join password shown once, on the Review", "Shown only now" in page
          and "Add machine ws9" in page, page[-2500:])
    check("...a desktop of this site, in the desktops' folder", "machines/desktops" in get("/directory/computers/ws9"))
    post("/directory/machines/_new", {"name": "host-1"})
    st, loc, page = post("/changes/machines/apply", {})
    # covers: web:post.directory.machines._new -
    check("refused at Apply: a name that is taken, why shown", "already taken" in page, page[-1500:])
    post("/changes/machines/discard", {})
    st, loc, page = post("/directory/machines/ws9/delete", {})
    # covers: web:post.directory.machines.*.delete +
    check("Remove computer: held, back to Computers; applied, gone", loc == "/directory/computers"
          and "Waiting for Apply: Remove ws9" in flash(page) and "Remove ws9" in post("/changes/machines/apply", {})[2]
          and 'href="/directory/computers/ws9"' not in get("/directory/computers"), (loc, flash(page)))
    page = get("/directory/ous")
    # covers: web:get.directory.ous +
    check("Directory · OUs: the tree by path (the leaf strong, its parents before it), who keeps each, what each "
          "holds; Create OU offering only where the site's own go",
          '<span class="muted">machines/servers/</span><strong>web</strong>' in page and ">fabric<" in page
          and ">the site<" in page and 'action="/directory/ous/_new"' in page
          and '<option>people/staff</option>' in page and '<option>machines</option>' not in page, page[-4000:])
    page = get("/directory/ous?ou=people/staff")
    check("an OU of the site's own: what it holds, Rename and Delete",
          "<dt>People</dt><dd>1</dd>" in page and 'action="/directory/ous/_form/rename"' in page
          and 'action="/directory/ous/_form/delete"' in page and 'value="people/staff"' in page, page[-3000:])
    page = get("/directory/ous?ou=machines/servers")
    check("one of fabric's: what it holds (its computers linked to Computers, searched by folder), the OUs in it, no "
          "form", 'href="/directory/computers?q=machines%2Fservers"' in page and ">web</a>" in page
          and "/directory/ous/_form/" not in page and "fabric&#39;s fixed folders" in page, page[-3000:])
    st, _, _, page = req("GET", "/directory/ous?ou=nowhere")
    # covers: web:get.directory.ous -
    check("an OU that is not there: said, no form, a 404 (2.1.8.16)", st == 404 and "No OU nowhere in the domain" in page
          and "/directory/ous/_form/" not in page)
    st, loc, page = post("/directory/ous/_new", {"parent": "people", "name": "contractors"})
    # covers: web:post.directory.ous._new +
    check("Create OU: held for the OUs page's Apply, back to the tree", loc == "/directory/ous"
          and "Waiting for Apply: Add OU contractors" in flash(page), (loc, flash(page)))
    st, loc, page = post("/directory/ous/_form/rename", {"ou": "people/staff", "name": "team"})
    # covers: web:post.directory.ous._form.rename +
    check("Rename: held, back on the OU's page", loc == "/directory/ous?ou=people%2Fstaff"
          and "Rename OU people/staff" in flash(page), (loc, flash(page)))
    st, loc, page = post("/directory/ous/_form/delete", {"ou": "machines/servers/web"})
    # covers: web:post.directory.ous._form.delete +
    check("Delete: held, back to the tree", loc == "/directory/ous" and "Remove OU machines/servers/web" in flash(page),
          (loc, flash(page)))
    st, loc, page = post("/changes/ous/apply", {})
    page = get("/directory/ous")
    check("...the three applied on one Review (one thing, the tree: none refuses the next)",
          ">contractors<" in page and ">team<" in page and "servers/</span><strong>web" not in page
          and "change pending" not in page, page[-3000:])
    for form, words in (({"parent": "people", "name": "people"}, "choose another"),
                        ({"parent": "machines", "name": "x"}, "takes no admin")):
        post("/directory/ous/_new", form)
        st, loc, page = post("/changes/ous/apply", {})
        # covers: web:post.directory.ous._new -
        check(f"Create OU refused at Apply, why shown ({words})", words in page, page[-1500:])
        post("/changes/ous/discard", {})
    post("/directory/ous/_form/rename", {"ou": "people", "name": "folks"})
    st, loc, page = post("/changes/ous/apply", {})
    # covers: web:post.directory.ous._form.rename -
    check("Rename refused at Apply: one of fabric's folders", "managed by fabric" in page, page[-1500:])
    post("/changes/ous/discard", {})
    post("/directory/ous/_form/delete", {"ou": "people/team"})
    st, loc, page = post("/changes/ous/apply", {})
    # covers: web:post.directory.ous._form.delete -
    check("Delete refused at Apply while it holds anything, saying so", "is not empty" in page, page[-1500:])
    post("/changes/ous/discard", {})
    check("refused: an unknown OU form (404)", req("POST", "/directory/ous/_form/frob", {"csrf": "dev"})[0] == 404)
    page = get("/directory/kerberos")
    # covers: web:get.directory.kerberos +
    check("Directory · Kerberos: domain sign-in on with its switch, the realm and KDCs, the ticket policy's form, the "
          "SPNs with the duplicate flagged and a computer's linked", "Now <strong>on</strong>" in page
          and 'action="/security/kerberos"' in page and "AD.HOME.ARPA" in page and "pi-core, pi-edge" in page
          and 'action="/directory/domain/kerberos/policy"' in page and 'name="skew_minutes"' in page
          and 'value="10"' in page and "Held by two accounts" in page and "HTTP/wiki.home.arpa" in page
          and 'href="/directory/computers/host-1"' in page, page[-4000:])
    check("refused: an address past Kerberos (404)", req("GET", "/directory/kerberos/x")[0] == 404)
    # covers: web:get.directory.kerberos -
    st, loc, page = post("/directory/domain/kerberos/policy", {"ticket_hours": "8", "renew_days": "5",
                                                                "skew_minutes": "4"})
    # covers: web:post.directory.domain.kerberos.policy +
    check("the ticket policy: held on Kerberos' page until its Apply", loc == "/directory/kerberos"
          and "Change the Kerberos ticket policy" in flash(page), (loc, flash(page)))
    post("/changes/kerberos/apply", {})
    page = get("/directory/kerberos")
    check("...applied: the form shows the new policy, nothing pending", 'value="8"' in page and 'value="4"' in page
          and "change pending" not in page, page[-3000:])
    for form, words in (({"skew_minutes": "30"}, "1 to 15 minutes"), ({"ticket_hours": "200"}, "over the renewal age"),
                        ({"renew_days": "x"}, "whole number")):
        post("/directory/domain/kerberos/policy", form)
        st, loc, page = post("/changes/kerberos/apply", {})
        # covers: web:post.directory.domain.kerberos.policy -
        check(f"the ticket policy refused at Apply, why shown ({words})", words in page, page[-1500:])
        post("/changes/kerberos/discard", {})
    check("refused: an unknown Kerberos form (404)",
          req("POST", "/directory/domain/kerberos/frob", {"csrf": "dev"})[0] == 404)
    st, loc, page = post("/security/kerberos", {"value": "off"})
    # covers: web:post.security.kerberos +
    check("domain sign-in turned off from Kerberos, back on Kerberos saying so", loc == "/directory/kerberos"
          and "kerberos: on → off" in flash(page) and "Now <strong>off</strong>" in page, (loc, flash(page)))
    post("/security/kerberos", {"value": "on"})
    # covers: web:post.security.kerberos -
    check("refused: an address past the sign-in switch (404)",
          req("POST", "/security/kerberos/x", {"csrf": "dev", "value": "on"})[0] == 404)
    page = get("/directory/sites")
    # covers: web:get.directory.sites +
    check("Directory · Sites: each site with its people and machines (counts, linked to its group and to Computers by "
          "site), its DCs, the grants scoped to it; the domain's DCs as counts; replication",
          'href="/directory/sites/lan"' in page and 'href="/directory/groups/site-lan"' in page
          and 'href="/directory/computers?site=edge"' in page and 'href="/directory/access/lan-helpdesk"' in page
          and "2 DCs used, 1997 can be added" in page and "pi-edge" in page, page[-4000:])
    page = get("/directory/sites/lan")
    check("a site's page: its people and machines linked, where its members change (its group), its grants, its AD "
          "site read-only (DCs, subnets, site links); no form", 'href="/directory/people/jim"' in page
          and 'href="/directory/computers/host-1"' in page and 'href="/directory/groups/site-lan"' in page
          and "192.168.1.0/24" in page and "lan-edge (edge and lan; cost 100, every 15 minutes)" in page
          and 'method="post"' not in page.split("<main", 1)[1].split("</main>", 1)[0], page[-3000:])
    st, _, _, page = req("GET", "/directory/sites/mars")
    # covers: web:get.directory.sites -
    check("a site that is not there: said, a 404 (2.1.8.16)", st == 404 and "No site mars in the domain" in page)
    check("refused: an address past a site's page (404)", req("GET", "/directory/sites/lan/x")[0] == 404)
    page = get("/directory/access")
    # covers: web:get.directory.access +
    check("Directory · Access: each grant with its who, where, what it gives and whom it reaches (one marked as "
          "reaching nobody), linked to its page; the search; Add grant",
          'href="/directory/access/server-administrators"' in page
          and "sign-in: keyboard, remote; sudo: ALL; local administrator" in page and "1 people, 1 machines" in page
          and 'aria-label="reaches nobody"' in page and 'href="/directory/access/_new"' in page, page[-4000:])
    page = get("/directory/access?q=site-lan")
    check("...searched by a where group: the help desk's grant alone", "lan-helpdesk" in page
          and "/directory/access/desktops" not in page)
    page = get("/directory/access/lan-helpdesk")
    check("a grant's page: who, where, what it gives, its groups; the people it reaches and what is where, linked; "
          "Change (its fields filled) and Remove", "people: edit, reset, unlock" in page
          and 'href="/directory/people/sam"' in page and 'href="/directory/computers/host-1"' in page
          and "grant-lan-helpdesk-who" in page and 'action="/directory/grants/lan-helpdesk"' in page
          and 'name="people_reset" value="yes" checked' in page and 'value="site-lan"' in page
          and 'action="/directory/grants/lan-helpdesk/delete"' in page, page[-4000:])
    page = get("/directory/access/nope")
    # covers: web:get.directory.access -
    check("a grant that is not there: said, no form", "no grant nope" in page
          and "/directory/grants/nope" not in page)
    page = get("/directory/access/_new?template=helpdesk")
    # covers: web:get.directory.access._new +
    check("Add grant from a template: its rights switched on, the template carried", 'value="helpdesk" selected' in page
          and 'name="people_unlock" value="yes" checked' in page and 'name="template" value="helpdesk"' in page)
    page = get("/directory/access/_new?template=nonsense")
    # covers: web:get.directory.access._new -
    check("...a template that is not one: an empty grant, nothing carried", 'name="template" value=""' in page
          and ' checked' not in page.split('action="/directory/grants/_new"', 1)[1].split("</form>", 1)[0])
    page = get("/directory/people/lee")
    check("a person's page: the grants that reach them and what each gives, linked to Access (lee: the desktops)",
          'href="/directory/access/desktops"' in page and "/directory/access/lan-helpdesk" not in page
          and "sign-in: keyboard" in page and "server-administrators" not in page, page[-4000:])
    st, loc, page = post("/directory/grants/_new", {"name": "web-ops", "kind": "allow", "who": "lab-users",
                                                    "where": "hosts-web", "signin_remote": "yes",
                                                    "sudo": "/usr/bin/systemctl restart nginx"})
    # covers: web:post.directory.grants._new +
    check("Add grant: held for the Access page's Apply, back to Access", loc == "/directory/access"
          and "Waiting for Apply: Add grant web-ops" in flash(page), (loc, flash(page)))
    st, loc, page = post("/directory/grants/lan-helpdesk", {"who": "helpdesk", "where": "site-lan",
                                                            "people_edit": "yes", "people_reset": "yes"})
    # covers: web:post.directory.grants.* +
    check("Change: held, back on the grant's page", loc == "/directory/access/lan-helpdesk"
          and "Change grant lan-helpdesk" in flash(page), (loc, flash(page)))
    st, loc, page = post("/directory/grants/network-administrators/delete", {})
    # covers: web:post.directory.grants.*.delete +
    check("Remove: held, back to Access", loc == "/directory/access"
          and "Remove grant network-administrators" in flash(page), (loc, flash(page)))
    post("/changes/access/apply", {})
    page = get("/directory/access")
    check("...the three applied on one Review: web-ops listed (remote sign-in, its sudo command), the help desk "
          "without unlock, the network administrators gone",
          "sign-in: remote; sudo: /usr/bin/systemctl restart nginx" in page and "people: edit, reset<" in page
          and "network-administrators" not in page and "change pending" not in page, page[-4000:])
    for form, words in (({"name": "x", "who": "a", "where": "b"}, "a grant&#39;s name"),
                        ({"name": "bad-one", "who": "directory-admins", "where": "site-lan", "people_edit": "yes"},
                         "tiers&#39; groups"),
                        ({"name": "all-root", "who": "Domain Users", "where": "machines-servers", "sudo_all": "yes"},
                         "every command for everyone")):
        post("/directory/grants/_new", form)
        st, loc, page = post("/changes/access/apply", {})
        # covers: web:post.directory.grants._new -
        check(f"Add grant refused at Apply, why shown ({words})", words in page, page[-1500:])
        post("/changes/access/discard", {})
    post("/directory/grants/lan-helpdesk", {"who": "", "where": "site-lan"})
    st, loc, page = post("/changes/access/apply", {})
    # covers: web:post.directory.grants.* -
    check("Change refused at Apply: a who with no group", "who: at least one group" in page, page[-1500:])
    post("/changes/access/discard", {})
    post("/directory/grants/nope/delete", {})
    st, loc, page = post("/changes/access/apply", {})
    # covers: web:post.directory.grants.*.delete -
    check("Remove refused: a grant that is not there", "no grant nope" in page, page[-1500:])
    post("/changes/access/discard", {})
    page = get("/directory/policies/sudo")
    # covers: web:get.directory.policies.sudo +
    check("Policies · Sudo rules (admin): who made each, remove only for fabric's, the add form aiming at a host group",
          'action="/directory/sudo/web-restart/delete"' in page and "/directory/sudo/backup/delete" not in page
          and 'action="/directory/sudo/_new"' in page and '<option value="hosts-web">' in page
          and "/usr/bin/systemctl restart nginx" in page and "read-only" in page, page[-3000:])
    st, loc, page = post("/directory/sudo/web-restart/delete", {})
    check("a sudo rule's removal: held on Policies, back on its tab", loc == "/directory/policies/sudo"
          and "Waiting for Apply: Remove web-restart" in flash(page) and "<strong>1 change pending</strong>" in page,
          (loc, flash(page)))
    post("/directory/domain/password-policy", {"minimum_length": "17"})
    page = get("/changes/policies")
    check("...the password policy joins it on the same Apply (one Review for the three kinds)",
          re.findall(r'data-label="Change">([^<]+)', page)[:2] == ["Remove web-restart", "Change the password policy"],
          re.findall(r'data-label="Change">([^<]+)', page))
    post("/changes/policies/discard", {})
    st, loc, page = post("/directory/machines/host-1/disable", {})
    # covers: web:post.directory.machines.*.* +
    check("disable a computer: held on Computers, back on its page", loc == "/directory/computers/host-1"
          and "Waiting for Apply: Disable host-1" in flash(page), loc)
    st, loc, page = post("/changes/machines/apply", {})
    check("...applied: done in the queue", "Disable host-1" in page and "Nothing waits" in page, page[-1500:])
    page = get("/directory/policies/gpo?match=example")
    # covers: web:get.directory.policies.gpo +
    check("Policies · Group Policy (admin): what is set, a search with a set form per policy",
          "ExampleText" in page and "/directory/gpo/set" in page and "Example setting" in page
          and 'action="/directory/policies/gpo"' in page)
    st, loc, held_page = post("/directory/gpo/clear", {"policy": "ExampleText"})
    check("a Group Policy change: held on Policies, back on its tab", loc == "/directory/policies/gpo"
          and "Waiting for Apply: Clear policy ExampleText" in flash(held_page), (loc, flash(held_page)))
    post("/changes/policies/discard", {})
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
# covers: web:get.kea web:get.pki web:get.pki.acme web:get.directory.people web:get.directory.policies +-
# covers: web:get.directory.computers web:get.directory.policies.gpo web:get.directory.policies.sudo +-
# covers: web:get.8021x web:get.8021x.decisions +-
# covers: web:get.8021x.guides web:get.8021x.devices web:get.8021x.roles web:get.secrets web:get.federation +-
# covers: web:get.settings web:get.settings.sign-in +-
# covers: web:get.account web:get.account.groups +
for bundle, entries in ENTRIES.items():
    with serve(None if bundle == "admin" else bundle):
        shown = [label for _, label in nav(get({"fabric-pki-operator": "/pki", "none": "/account"}.get(bundle, "/")))]
        check(f"--as {bundle}: the navigation shows exactly its entries ({', '.join(entries)})", shown == entries,
              shown)
        perms, wrong = set(BUNDLES.get(bundle, ())), []
        for entry, label, pages in views.NAV:
            for href, plabel, need in pages:
                may = not need or bool(perms & set(need))
                st = req("GET", href)[0]
                if may != (st == 200):
                    wrong.append((href, st))
        check(f"--as {bundle}: every page opens with its permission and is refused (403) without it", not wrong,
              wrong)

with serve("fabric-helpdesk"):
    page = get("/directory/people/sam")
    check("helpdesk: Add person, Reset password and Edit (people:edit)", "/directory/people/_new"
          in get("/directory/people") and "Reset password" in page and 'action="/directory/people/sam/edit"' in page)
    post("/directory/people/_new", {"uid": "dana", "first": "Dana", "last": "Lee", "email": "dana@home.arpa"})
    post("/directory/people/sam/reset", {})
    st, loc, page = post("/changes/people/apply", {})
    secrets_shown = re.findall(r'<code class="secret">([^<]+)</code>', page)
    check("helpdesk: add a person and reset one, applied -> each one-time password shown once, on the Review",
          "Shown only now" in page and "Add person dana" in page and "Reset the sign-in of sam" in page
          and len(secrets_shown) == 2, page[-2500:])
    page = get("/changes/people")
    check("...and not again: a second look shows no password", "Shown only now" not in page
          and not any(x in page for x in secrets_shown))
    check("...never in an address or the queue: no password in the job's result or a link",
          not any(x in get("/directory/people") for x in secrets_shown))
    post("/directory/people/jim/reset", {})
    st, loc, page = post("/changes/people/apply", {})
    check("helpdesk: an admin's sign-in cannot be reset (refused at Apply, why shown)", "only an admin" in page,
          page[-1500:])
    post("/changes/people/discard", {})
    page = get("/directory/people/sam")
    check("helpdesk: Disable, but no group or remove form (people:groups, people:remove are admins')",
          "/directory/people/sam/disable" in page and "/directory/people/sam/groups" not in page
          and "/directory/people/sam/delete" not in page)
    post("/directory/people/sam/disable", {})
    st, loc, page = post("/changes/people/apply", {})
    check("helpdesk: disable a plain user", "Disable sam" in page and "Nothing waits" in page, page[-1500:])
    post("/directory/people/jim/disable", {})
    st, loc, page = post("/changes/people/apply", {})
    check("helpdesk: refused: disabling an admin", "only an admin" in page, page[-1500:])
    post("/changes/people/discard", {})
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
    page = get("/directory/policies")
    check("--as fabric-auditor: the password policy shown, no form (domain:admin)",
          "minimum length" in page and "/directory/domain/password-policy" not in page)
    st, loc, page = post("/directory/domain/password-policy", {"minimum_length": "4"})
    check("--as fabric-auditor: refused: holding a password policy change, the permission named (domain:admin); "
          "nothing pending", "you need the permission domain:admin" in flash(page)
          and "change pending" not in page, flash(page))
    page = get("/directory/groups/lab-users")
    check("--as fabric-auditor: a group's page without Delete, the managers' or the members' forms (groups:admin; "
          "not a manager)", "lab-restart" in page and 'method="post"' not in page.split("<main", 1)[1]
          .split("</main>", 1)[0] and req("GET", "/directory/groups/_new")[0] == 403, page[-2000:])
    st, loc, page = post("/directory/groups/lab-users/managers", {"managers": "x"})
    # covers: web:post.directory.groups.*.managers -
    check("--as fabric-auditor: refused: holding a managers change, the permission named (groups:admin)",
          "groups:admin" in flash(page) and "change pending" not in page, flash(page))
    page = get("/directory/computers/host-1")
    check("--as fabric-auditor: a computer's page, its grants, without a single action or form (machines:admin)",
          "server-administrators" in page and 'method="post"' not in page.split("<main", 1)[1]
          .split("</main>", 1)[0] and req("GET", "/directory/computers/_new")[0] == 403, page[-2000:])
    for op, form in (("disable", {}), ("delete", {}), ("type", {"type": "server"}),
                     ("sites", {"action": "add", "site": "lan"}), ("move", {"path": "machines"})):
        st, loc, page = post(f"/directory/machines/host-1/{op}", form)
        # covers: web:post.directory.machines.*.* web:post.directory.machines.*.delete -
        check(f"--as fabric-auditor: refused: holding a computer's {op}, the permission named (machines:admin)",
              "machines:admin" in flash(page) and "change pending" not in page, flash(page))
    page = get("/directory/access/lan-helpdesk")
    check("--as fabric-auditor: a grant's page without Change or Remove, and no Add grant (groups:admin)",
          "people: edit, reset, unlock" in page and "/directory/grants/" not in page
          and req("GET", "/directory/access/_new")[0] == 403, page[-2000:])
    st, loc, page = post("/directory/grants/lan-helpdesk/delete", {})
    check("--as fabric-auditor: refused: holding a grant's removal, the permission named (groups:admin)",
          "groups:admin" in flash(page) and "change pending" not in page, flash(page))
    page = get("/directory/ous?ou=people/staff")
    check("--as fabric-auditor: an OU of the site's without Rename or Delete (ous:admin), and no Create OU",
          "<dt>People</dt><dd>1</dd>" in page and "/directory/ous/_form/" not in page
          and "/directory/ous/_new" not in get("/directory/ous"), page[-2000:])
    st, loc, page = post("/directory/ous/_new", {"parent": "people", "name": "x"})
    check("--as fabric-auditor: refused: holding Create OU, the permission named (ous:admin)",
          "ous:admin" in flash(page) and "change pending" not in page, flash(page))
    page = get("/directory/people")
    check("--as fabric-auditor: people listed, no Add person", "jim@home.arpa" in page
          and "/directory/people/_new" not in page)
    page = get("/directory/people/sam")
    check("--as fabric-auditor: a person's page without a single action or form",
          "sam@home.arpa" in page and 'method="post"' not in page.split("<main", 1)[1].split("</main>", 1)[0]
          and "Reset password" not in page, page[-2000:])
    check("--as fabric-auditor: refused: Add person's page (403, people:create)",
          req("GET", "/directory/people/_new")[0] == 403)
    st, loc, page = post("/directory/people/sam/unlock", {})
    # covers: web:post.directory.people.*.unlock -
    check("--as fabric-auditor: refused: holding an Unlock, the permission named (people:reset)",
          "people:reset" in flash(page) and "change pending" not in page, flash(page))
    st, loc, page = post("/directory/people/sam/groups", {"group": "users", "action": "remove"})
    # covers: web:post.directory.people.*.groups -
    check("--as fabric-auditor: refused: a group change, the permission named (people:groups)",
          "people:groups" in flash(page), flash(page))
    page = get("/overview/updates")
    check("--as fabric-auditor: the Updates table, but no update or roll-back forms",
          "postgres" in page and "/overview/images/" not in page)
    st, _, _, _ = req("POST", "/overview/images/postgres/update", {"csrf": "dev"})
    check("--as fabric-auditor: refused: an image update (403, images:update)", st == 403, st)
    page = get("/pki/acme")
    check("--as fabric-auditor: the ACME view without enroll or withdraw", "nas.home.arpa" in page
          and "/stepca/acme/enroll" not in page and "/delete" not in page)

# My account (manual 1.8.6.6): a person with no fabric role signs in to it alone, and so does everyone else
with serve("none"):
    st, loc, _, _ = req("GET", "/")
    check("--as none: / goes to My account (the Overview is not theirs)", st == 303 and loc == "/account", (st, loc))
    page = get("/account")
    check("--as none: My account shows their details (read-only), the password form, the sign-in factors, their "
          "certificates and devices; no form changes the details", "My details" in page and "Engineer" in page
          and 'action="/account/password"' in page and "Sign-in factors" in page and "CN=dev-none" in page
          and "jims-laptop" in page and "/directory/people" not in page, page[-3000:])
    check("--as none: the password fields are never filled in, and say what they are for the browser",
          'autocomplete="current-password"' in page and page.count('autocomplete="new-password"') == 2
          and 'type="password" name="current" autocomplete="current-password" required>' in page)
    for form, why in (({"current": "nope", "new": "abcdefgh1", "again": "abcdefgh1"}, "the current password is wrong"),
                      ({"current": "current", "new": "abcdefgh1", "again": "other"}, "repeat differ"),
                      ({"current": "", "new": "abcdefgh1", "again": "abcdefgh1"}, "Type your current password"),
                      ({"current": "current", "new": "short", "again": "short"}, "policy refuses")):
        st, loc, page = post("/account/password", form)
        # covers: web:post.account.password -
        check(f"--as none: the password refused ({why}), said, nothing changed; no password in the address",
              loc == "/account" and why in flash(page) and "abcdefgh1" not in loc, (loc, flash(page)))
    st, loc, page = post("/account/password", {"current": "current", "new": "abcdefgh1", "again": "abcdefgh1"})
    # covers: web:post.account.password +
    check("--as none: the password changed at once (never pending), their other sessions signed out, said",
          loc == "/account" and "Your password is changed" in flash(page) and "change pending" not in page,
          flash(page))
    page = get("/account/groups")
    check("--as none: Groups I manage: each group, its members, the forms its controls allow (visitors: add only)",
          "lab-users" in page and "visitors" in page and page.count('value="remove"') == 1, page[-2500:])
    st, loc, page = post("/account/groups/lab-users/members", {"action": "add", "member": "dana"})
    # covers: web:post.account.groups.*.members +
    check("--as none: a member added: held for My account's Apply, said, the top bar counts it",
          loc == "/account/groups" and "Waiting for Apply: Add dana to group lab-users" in flash(page)
          and "<strong>1 change pending</strong>" in page and "dana" not in page.split("<h2>lab-users", 1)[1][:400],
          flash(page))
    st, loc, page = post("/changes/account/apply", {})
    check("--as none: Apply on My account: done, in their own queue; dana is a member",
          loc == "/changes/account" and "Add dana to group lab-users" in page and "done" in page
          and "dana" in get("/account/groups"), page[-2000:])
    st, loc, page = post("/account/groups/visitors/members", {"action": "remove", "member": "sam"})
    st, loc, page = post("/changes/account/apply", {})
    # covers: web:post.account.groups.*.members -
    check("--as none: a removal its controls do not allow: refused at Apply, said in the queue, still pending",
          "lets its managers add only" in page and "Apply 1 change" in page, page[-2000:])
    post("/changes/account/discard", {})
    st, loc, page = post("/account/groups/nosuch/members", {"action": "add", "member": "dana"})
    check("--as none: a group that is not there: refused when held, said, nothing pending",
          "change pending" not in page and "no group nosuch" in flash(page), flash(page))
    for path in ("/dns/zones", "/directory/people", "/directory/people/jim", "/directory/people/_new", "/directory",
                 "/audit", "/overview/doctor", "/changes/people"):
        # covers: web:get.directory -
        check(f"--as none: {path} refused (403)", req("GET", path)[0] == 403)

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
