#!/usr/bin/env python3
"""The web UI dev preview: real pages with sample data, edits in memory only,
and no way to switch it on in the production server."""
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

PORT = 18765
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


proc = subprocess.Popen([sys.executable, os.path.join(UX_WEB, "devserver.py"), "--port", str(PORT)],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    for _ in range(50):
        try:
            req("GET", "/static/app.css")
            break
        except OSError:
            time.sleep(0.1)
    st, _, csp, page = req("GET", "/")
    check("overview renders with the DEV PREVIEW banner", st == 200 and "DEV PREVIEW" in page and "services healthy" in page, st)
    tabs_ok = all(req("GET", f"/{t}")[0] == 200 for t in ("", "bind9", "kea", "stepca", "directory", "freeradius",
                                                          "openbao"))
    page = req("GET", "/freeradius")[3]
    check("FreeRADIUS tab: server, RADIUS clients, recent decisions, add form",
          "radius.home.arpa" in page and "switch1" in page and "not required" in page and "jims-laptop" in page
          and "device disabled" in page and 'action="/freeradius/clients"' in page)
    st, _, _, page = req("POST", "/freeradius/clients", {"csrf": "dev", "name": "switch2", "address": "192.168.1.9",
                                                         "message_authenticator": "1"})
    check("FreeRADIUS tab: add client -> secret shown once, then listed",
          st == 200 and "shown only now" in page and "switch2" in req("GET", "/freeradius")[3], st)
    page = req("GET", "/freeradius?view=switches")[3]
    check("FreeRADIUS tab: Connect a switch — this server's IP, ports, UniFi steps, keep uplinks open",
          "192.168.1.2" in page and "1812" in page and "UniFi" in page and "Force Authorized" in page
          and 'class="section active"' in page)
    page = req("GET", "/freeradius?view=windows")[3]
    check("FreeRADIUS tab: Connect Windows — both scripts downloadable, groups listed plainly",
          'download="fabric-8021x-tls.ps1"' in page and 'download="fabric-8021x-ttls.ps1"' in page
          and "&lt;/code&gt;" not in page and "<code>staff</code>" in page)
    st, _, _, _ = req("POST", "/freeradius/people", {"csrf": "dev", "group": "contractors", "vlan": "70"})
    page = req("GET", "/freeradius")[3]
    check("FreeRADIUS tab: people section (mapped groups), map a group -> listed; a person's login in the log",
          st == 303 and "contractors" in page and "staff" in page and 'action="/freeradius/people"' in page
          and "alice" in page, st)
    page = req("GET", "/kea")[3]
    check("Kea tab: subnets, reservations, leases, reserve form", "192.168.1.0/24" in page and "printer" in page
          and "laptop1.dhcp.home.arpa" in page and 'action="/kea/reservations"' in page)
    check("Kea tab: DHCP named a preview until 0.8.0 (2.1.1.49, manual 1.10.3.9); no other tab says so",
          "DHCP is a preview in this release" in page and "0.8.0" in page
          and "a preview in this release" not in req("GET", "/freeradius")[3])
    st, loc, _, _ = req("POST", "/kea/reservations", {"csrf": "dev", "mac": "02:00:00:00:00:99", "ip": "192.168.1.30",
                                                      "hostname": "nas"})
    check("Kea tab: reserve -> listed", st == 303 and "192.168.1.30" in req("GET", "/kea")[3], loc)
    # the DHCP options page (2.1.10.23, 2.1.10.25, manual 1.10.4.24.6)
    st, _, _, page = req("GET", "/kea/options")
    check("DHCP options page: the organisation's and the site's sets, subnets with netboot forms, the editors at the "
          "top, linked from the Kea tab", st == 200 and "The organisation (every site)" in page
          and "Site home (every subnet here)" in page and 'action="/kea/options/netboot"' in page
          and 'action="/kea/options/option-editors"' in page and "parents" in page
          and 'href="/kea/options"' in req("GET", "/kea")[3], st)
    check("DHCP options page: links to the Networks tab, whose subnet view links back to it with that subnet chosen",
          'href="/networks"' in page and 'href="/kea/options?site=lan&amp;target=subnet:iot"'
          in req("GET", "/networks?subnet=iot")[3])
    page = req("GET", "/kea/options?target=subnet:lab")[3]
    check("DHCP options page: a target's effective options with their sources",
          "What a client gets: subnet lab" in page and "the subnet&#39;s gateway" in page, page[-300:])
    st, loc, _, _ = req("POST", "/kea/options/options/org", {"csrf": "dev", "action": "set", "scope": "org",
                                                             "option": "ntp-servers", "data": "10.1.10.1"})
    check("DHCP options page: a change -> back to the page with a message (dev preview: nothing saved)",
          st == 303 and (loc or "").startswith("/kea/options?msg="), loc)
    page = req("GET", "/dns-filter")[3]
    check("DNS filter tab: statistics, the most blocked names, its sections",
          "Last 24 hours" in page and "browser.events.data.msn.com" in page and "?view=querylog" in page)
    st, loc, _, _ = req("POST", "/dns-filter/rules", {"csrf": "dev", "kind": "block", "name": "www.wikipedia.org",
                                                      "back": "querylog"})
    check("DNS filter tab: Block from the query log -> back there, listed in the rules",
          st == 303 and "view=querylog" in (loc or "")
          and "www.wikipedia.org" in req("GET", "/dns-filter?view=rules")[3], loc)
    check("every service tab renders", tabs_ok)
    # the Networks tab (manual 1.10.4.21) over the sample plan
    # covers: web:get.networks +
    st, _, _, page = req("GET", "/networks")
    check("Networks tab: the sites with their numbers, the site's VLANs, each subnet's bar map, the add form",
          st == 200 and "parents" in page and "below this site" in page and "10.1.20.0/24" in page
          and 'class="netbar' in page and 'action="/networks/lan/vlans"' in page
          and 'href="/networks"' in req("GET", "/")[3], st)
    page = req("GET", "/networks?subnet=iot")[3]
    check("Networks tab: a subnet's ranges, address table (recorded, the lease beside a reservation, an unrecorded "
          "lease, free runs) and its options with their sources and fabric's marker",
          "nas" in page and "cam1" in page and "lease · unrecorded" in page and "10.1.20.120" in page
          and "free" in page and "provided by fabric" in page and "over fabric" in page
          and "replaces fabric's" in page and "overridden by subnet iot" in page
          and "boot-file-name" in page and "Record 10.1.20.120" in page, page[:300])
    page = req("GET", "/networks")[3]
    check("Networks tab: a VLAN has no options of its own; its row opens its subnets' (2.3.10.5.7)",
          "Options its subnets' clients get" in page and "organisation" in page, page[:300])
    page = req("GET", "/networks?q=aa:bb:cc")[3]
    check("Networks tab: a search by part of a MAC finds the reservation", "cam1" in page and "Matching" in page)
    page = req("GET", "/networks?q=nothing-here")[3]
    check("Networks tab: a search that finds nothing says so", "Nothing in lan" in page)
    st, _, _, page = req("GET", "/networks?site=parents")
    check("Networks tab: the house below, without this site's leases", st == 200 and "10.2.20.0/24" in page
          and "leases are shown at their own site" in page, st)
    # covers: web:get.networks -
    st, _, _, page = req("GET", "/networks?site=upstairs")
    check("Networks tab refused: a site that is not this one or below it (400, saying why)",
          st == 400 and "not this site or one below it" in page, st)
    # covers: web:get.networks +
    st, _, _, page = req("GET", "/networks/export")
    check("Networks tab: the CSV export", st == 200 and page.startswith("site,vlan") and "10.1.20.150" in page, st)
    # covers: web:post.networks.*.vlans +
    st, loc, _, _ = req("POST", "/networks/lan/vlans", {"csrf": "dev", "id": "40", "name": "lab"})
    check("Networks tab: add a VLAN -> its suggested subnet and split listed",
          st == 303 and "msg=" in (loc or "") and "10.1.40.0/24" in req("GET", "/networks")[3], loc)
    # covers: web:post.networks.*.vlans -
    for form, why in (({"id": "abc", "name": "x"}, "1 to 4094"), ({"id": "40", "name": "again"}, "already")):
        st, loc, _, _ = req("POST", "/networks/lan/vlans", {"csrf": "dev", **form})
        check(f"Networks tab refused: a VLAN ({why}), saying why", st == 303 and "err=" in (loc or "")
              and why in urllib.parse.unquote_plus(loc or ""), loc)
    # covers: web:post.networks.*.addresses +
    st, loc, _, _ = req("POST", "/networks/lan/addresses", {"csrf": "dev", "ip": "10.1.20.11", "vlan": "20",
                                                             "kind": "static", "name": "printer", "back": "iot"})
    check("Networks tab: record an address -> back on its subnet, listed", st == 303 and "subnet=iot" in (loc or "")
          and "printer" in req("GET", "/networks?subnet=iot")[3], loc)
    # covers: web:post.networks.*.addresses -
    st, loc, _, _ = req("POST", "/networks/lan/addresses", {"csrf": "dev", "ip": "10.1.20.11", "vlan": "20",
                                                             "kind": "static"})
    check("Networks tab refused: an address claimed twice", st == 303 and "already+claimed" in (loc or ""), loc)
    # a reservation's device role (1.11.1.7, 1.10.4.21.3)
    page = req("GET", "/networks?subnet=iot")[3]
    check("Networks tab: the address forms have a device role field; a reservation's role shown beside its kind",
          page.count('name="role"') >= 2 and 'name="role" value="iot"' in page and 'from this reservation">iot<' in page, page[:300])
    # covers: web:post.networks.*.addresses web:post.networks.*.addresses.* +
    st, loc, _, _ = req("POST", "/networks/lan/addresses", {"csrf": "dev", "ip": "10.1.20.152", "vlan": "20",
                                                             "kind": "reservation", "mac": "aa:bb:cc:dd:ee:03",
                                                             "name": "cam3", "role": "cameras", "back": "iot"})
    st2, loc2, _, _ = req("POST", "/networks/lan/addresses/10.1.20.150", {"csrf": "dev", "role": "", "back": "iot"})
    page = req("GET", "/networks?subnet=iot")[3]
    check("Networks tab: record a reservation with a role, and take a role off with an empty field",
          st == 303 and "msg=" in (loc or "") and st2 == 303 and "msg=" in (loc2 or "")
          and 'from this reservation">cameras<' in page and 'from this reservation">iot<' not in page, (loc, loc2))
    # covers: web:post.networks.*.addresses web:post.networks.*.addresses.* -
    st, loc, _, _ = req("POST", "/networks/lan/addresses", {"csrf": "dev", "ip": "10.1.20.12", "vlan": "20",
                                                             "kind": "static", "role": "iot"})
    st2, loc2, _, _ = req("POST", "/networks/lan/addresses/10.1.20.10", {"csrf": "dev", "role": "iot"})
    check("Networks tab refused: a device role on a static address, new or changed, saying why",
          st == 303 and st2 == 303 and all("only+a+reservation" in (x or "") for x in (loc, loc2))
          and "Change 10.1.20.12" not in req("GET", "/networks?subnet=iot")[3], (loc, loc2))
    st, loc, _, _ = req("POST", "/networks/upstairs/vlans", {"csrf": "dev", "id": "50", "name": "x"})
    check("Networks tab refused: a change to a site this console does not show", st == 303 and "err=" in (loc or ""),
          loc)
    page = req("GET", "/networks?subnet=iot")[3]
    st, _, _, scan = req("GET", "/networks/scan?subnet=10.1.20.0%2F24")
    # covers: web:get.networks.scan +
    check("Networks tab: a served subnet links its scan; the scan page opens with that subnet chosen (1.10.4.22)",
          'href="/networks/scan?subnet=10.1.20.0/24"' in page and st == 200
          and '<option value="10.1.20.0/24" selected>' in scan and 'action="/networks/scan"' in scan
          and 'class="tab active"' in scan and 'href="/networks"' in scan, (st, scan[:300]))
    page = req("GET", "/networks?site=parents&subnet=iot")[3]
    check("Networks tab: another site's subnet has no scan link (a scan covers only this site's)",
          "/networks/scan" not in page)
    page = req("GET", "/kea?plan=1")[3]
    check("Kea tab with the subnets in the plan: links to Networks, no subnet or reservation forms (1.10.4.21)",
          'href="/networks' in page and 'action="/kea/subnets"' not in page
          and 'action="/kea/reservations"' not in page and "/kea/subnets/update" not in page)
    check("strict Content-Security-Policy, like production", csp and "default-src 'none'" in csp, csp)
    st, _, _, page = req("GET", "/bind9?zone=dynamic_zone_var")
    check("BIND9 tab shows records and the add form", st == 200 and "nas" in page and "192.168.1.10" in page, st)
    st, loc, _, _ = req("POST", "/bind9/zone/dynamic_zone_var/add", {"type": "A", "name": "preview", "ip": "192.168.1.99", "csrf": "dev"})
    st2, _, _, page = req("GET", "/bind9?zone=dynamic_zone_var")
    check("adding a record works (in memory)", st == 303 and "192.168.1.99" in page, (st, loc))
    idx = re.search(r'name="index" value="(\d+)"><input type="hidden" name="name" value="preview"', page)
    req("POST", "/bind9/zone/dynamic_zone_var/delete", {"type": "A", "index": idx.group(1) if idx else "-1", "name": "preview"})
    st, _, _, page = req("GET", "/bind9?zone=dynamic_zone_var")
    check("deleting a record works (in memory)", "192.168.1.99" not in page)
    # 2.1.2.22: the record form asks type, name, value; priority for MX, weight and port for SRV (the stylesheet
    # shows them only for those types, no script); fabric's own names marked and their delete refused
    form = page.split('/bind9/zone/dynamic_zone_var/add"')[1].split("</form>")[0]
    css = req("GET", "/static/app.css")[3]
    check("record form: type, name, value; priority, weight, port only for MX/SRV; no landing-page fields",
          'name="value"' in form and 'class="f-prio"' in form and form.count('class="f-srv"') == 2
          and 'name="ip"' not in form and 'name="link"' not in form and '<option value="SRV">' in form
          and 'option[value="SRV"]:checked' in css and ".f-srv{display:none}" in css, form)
    st, loc, _, _ = req("POST", "/bind9/zone/dynamic_zone_var/add", {"csrf": "dev", "type": "MX", "name": "@",
                                                                    "value": "mail2", "priority": "20"})
    check("record form: an MX record from value and priority", st == 303 and "10 mail" in req(
        "GET", "/bind9?zone=dynamic_zone_var")[3] and "20 mail2" in req("GET", "/bind9?zone=dynamic_zone_var")[3], loc)
    st, loc, _, _ = req("POST", "/bind9/zone/dynamic_zone_var/add", {"csrf": "dev", "type": "SRV", "name": "_sip._tcp",
                                                                    "value": "pbx", "priority": "0", "weight": "5"})
    check("record form refused: an SRV record without its port, saying why",
          st == 303 and "port must be a number" in urllib.parse.unquote(loc or ""), loc)
    page = req("GET", "/bind9?zone=dynamic_zone_var")[3]
    rows = page.split("<tr>")
    ca_row = [row.split("</tr>")[0] for row in rows if ">ca " in row][0]
    info_rows = [row.split("</tr>")[0] for row in rows if ">info<" in row]
    check("fabric's own names marked 'provided by fabric', with the setting instead of a Delete button; the landing "
          "page's info is the admin's since 0.7.1 (2.1.4.6), with its Delete button",
          "provided by fabric" in ca_row and "cname_ca" in ca_row and "Delete</button>" not in ca_row
          and info_rows and all("provided by fabric" not in r and "Delete</button>" in r for r in info_rows),
          (info_rows, ca_row))
    st, loc, _, _ = req("POST", "/bind9/zone/dynamic_zone_var/delete", {"csrf": "dev", "type": "CNAME", "index": "3",
                                                                       "name": "ca"})
    check("deleting fabric's own name (ca) is refused, naming its setting",
          st == 303 and "provided by fabric" in urllib.parse.unquote(loc or "")
          and "cname_ca" in urllib.parse.unquote(loc or "")
          and ">ca " in req("GET", "/bind9?zone=dynamic_zone_var")[3], loc)
    st, loc, _, _ = req("POST", "/bind9/zone/dynamic_zone_var/delete", {"csrf": "dev", "type": "CNAME", "index": "10",
                                                                       "name": "info"})
    after = [row for row in req("GET", "/bind9?zone=dynamic_zone_var")[3].split("<tr>") if ">info<" in row]
    check("deleting an info record works (the admin's since 0.7.1)",
          st == 303 and "Record deleted" in urllib.parse.unquote(loc or "") and len(after) == len(info_rows) - 1, loc)
    # 2.1.2.22 item 4: the landing page's links in a section of their own
    page = req("GET", "/bind9?view=landing")[3]
    check("Landing page section: what the page is, its links (label, address), the add form with the zone's records",
          "Landing page" in page and "fabric's start page" in page and "https://nas.home.arpa:5001/" in page
          and 'action="/bind9/landing/add"' in page and 'value="A|6|printer"' in page
          and 'action="/bind9/landing/remove"' in page, page[-1500:])
    st, loc, _, _ = req("POST", "/bind9/landing/add", {"csrf": "dev", "record": "A|6|printer", "link_label": "Printer",
                                                       "link_port": "631", "link_path": "/"})
    check("link a record from the landing page -> listed with its port", st == 303 and "msg=" in (loc or "")
          and "https://printer.home.arpa:631/" in req("GET", "/bind9?view=landing")[3], loc)
    for form, why in (({"record": "A|6|printer", "link_port": "70000"}, "link port must be"),
                      ({"record": ""}, "pick a record"), ({"record": "MX|12|@"}, "only A, AAAA and CNAME"),
                      ({"record": "A|5|nas"}, "record changed")):
        st, loc, _, _ = req("POST", "/bind9/landing/add", {"csrf": "dev", **form})
        check(f"link refused ({why}), saying why", st == 303 and why in urllib.parse.unquote(loc or ""), loc)
    st, loc, _, _ = req("POST", "/bind9/landing/remove", {"csrf": "dev", "type": "A", "index": "6", "name": "printer"})
    check("stop linking a record -> gone from the landing page's list", st == 303
          and "printer.home.arpa:631" not in req("GET", "/bind9?view=landing")[3], loc)
    page = req("GET", "/bind9?zone=dynamic_zone_var")[3]
    # zones (manual 1.4.1.3): the New zone form everywhere, Remove zone on every zone but the site's own
    check("BIND9 tab: New zone form with 'Hide the public name'; no Remove on the site's own zone",
          'action="/bind9/zones/new"' in page and 'name="hide_public"' in page
          and "/bind9/zones/dynamic_zone_var/remove" not in page)
    page = req("GET", "/bind9?zone=iot.home.arpa")[3]
    check("BIND9 tab: Remove zone on another zone, its record count shown, the name asked for again",
          'action="/bind9/zones/iot.home.arpa/remove"' in page and "3 record(s)" in page and 'name="confirm"' in page)
    st, loc, _, _ = req("POST", "/bind9/zones/new", {"csrf": "dev", "name": "Lab.LAN"})
    page = req("GET", loc or "/bind9")[3]
    # covers: web:post.bind9.zones.new +
    check("New zone: added (normalised) and opened", st == 303 and "zone=lab.lan" in (loc or "")
          and "Zone lab.lan added" in page and "lab.lan" in page, (st, loc))
    for form, why in (({"name": "nodots"}, "two labels"), ({"name": "lab.lan"}, "already a zone"),
                      ({"name": "shop.example.com"}, "Hide the public name")):
        st, loc, _, _ = req("POST", "/bind9/zones/new", {"csrf": "dev", **form})
        # covers: web:post.bind9.zones.new -
        check(f"New zone refused ({why}), saying why", st == 303 and "err=" in (loc or "")
              and why in urllib.parse.unquote(loc or ""), loc)
    st, loc, _, _ = req("POST", "/bind9/zones/new", {"csrf": "dev", "name": "shop.example.com", "hide_public": "on"})
    check("New zone: a public name with the tick is added", st == 303 and "msg=" in (loc or ""), loc)
    st, loc, _, _ = req("POST", "/bind9/zones/lab.lan/remove", {"csrf": "dev", "confirm": "lab.la"})
    # covers: web:post.bind9.zones.*.remove -
    check("Remove zone refused when the name is typed wrong", st == 303 and "err=" in (loc or ""), loc)
    st, loc, _, _ = req("POST", "/bind9/zones/dynamic_zone_var/remove", {"csrf": "dev", "confirm": "home.arpa"})
    check("Remove zone refused for the site's own zone", st == 303 and "cannot be removed" in
          urllib.parse.unquote(loc or ""), loc)
    st, loc, _, _ = req("POST", "/bind9/zones/lab.lan/remove", {"csrf": "dev", "confirm": "lab.lan"})
    # covers: web:post.bind9.zones.*.remove +
    check("Remove zone: removed once its name is typed again", st == 303 and "msg=" in (loc or "")
          and "zone=lab.lan" not in req("GET", "/bind9")[3], loc)
    st, _, _, page = req("POST", "/apply", {"csrf": "dev"})
    check("apply is a no-op that says so", st == 200 and "nothing was rendered or reloaded" in page)
    st, _, _, page = req("GET", "/audit")
    check("audit log shows the preview's actions", "DNS_ADD" in page and "in memory" in page)
    st, _, _, page = req("GET", "/security")
    check("the Security page: each layer, its raises, a lowering shown with who did it, no lower button",
          st == 200 and 'action="/security/raise"' in page and "lowered from any" in page
          and "fabricctl security lower" in page and "Lower</button>" not in page and "Turn off" in page)
    pages = [req("GET", f"/stepca?view={v}") for v in ("ca", "sign", "issue", "inspect", "convert", "issued")]
    check("every Step-CA menu page renders", all(p[0] == 200 for p in pages) and "Fabric Root CA" in pages[0][3]
          and "switch-core.home.arpa" in pages[5][3])
    # device enrolment and SSH certificates (0.9; written, not run yet: notes 2.3.5.4, 2.3.7.3)
    st, _, _, page = req("GET", "/stepca?view=enrol")
    check("Enrol a device: the Apple and the .p12 forms, the open profile with Withdraw, the certificates with Revoke",
          st == 200 and 'action="/stepca/enrol/apple"' in page and 'action="/stepca/enrol/p12"' in page
          and 'action="/stepca/enrol/c0ffee12/withdraw"' in page and "jims-pixel" in page and "not linked" in page)
    st, _, _, page = req("POST", "/stepca/enrol/p12", {"csrf": "dev", "name": "Jims-Pixel", "legacy": "on"})
    # covers: web:post.stepca.enrol.p12 +
    check(".p12: the result page with the file, its password once, the warning to copy it, the legacy note",
          st == 200 and 'download="jims-pixel.p12"' in page and "shown once" in page and "not stored anywhere" in page
          and "Android 11 and older" in page and "only copy of the private key" not in page)
    st, _, _, page = req("POST", "/stepca/enrol/p12", {"csrf": "dev", "name": "bad name!"})
    check(".p12 refused for a bad name, saying why (400)", st == 400 and "letters, digits and dashes" in page)
    st, _, _, page = req("POST", "/stepca/enrol/c0ffee12/withdraw", {"csrf": "dev"})
    check("withdraw the sample profile: gone from the list", st == 200 and "c0ffee12" not in page)
    st, _, _, page = req("GET", "/ssh")
    check("the SSH page: on, the CA's fingerprint, the toggle and the form to sign",
          st == 200 and 'action="/ssh/off"' in page and 'action="/ssh/sign"' in page and "SHA256:" in page)
    # covers: web:get.ssh +
    check("the SSH page's host certificates: the host CA's fingerprint and each machine's state, until when, names",
          "Host certificates" in page and "SHA256:HOSTCA" in page and "<th>Machine</th>" in page
          and "(fabric host)" in page and "renewing" in page and "not published" in page
          and "ws2404.ad.lan.test" in page)
    st, _, _, page = req("POST", "/ssh/sign", {"csrf": "dev", "public_key": "ssh-ed25519 AAAAC3Nza dev@laptop"})
    # covers: web:post.ssh.sign +
    check("sign a public key: the certificate shown once, as a download", st == 200
          and 'download="id-cert.pub"' in page and "ssh-ed25519-cert-v01@openssh.com" in page)
    st, _, _, page = req("POST", "/ssh/sign", {"csrf": "dev", "public_key": "-----BEGIN OPENSSH PRIVATE KEY-----"})
    check("a private key pasted is refused, saying why (400)", st == 400 and "one public key" in page)
    st, loc, _, _ = req("POST", "/ssh/off", {"csrf": "dev"})
    page = req("GET", loc or "/ssh")[3]
    # covers: web:post.ssh.* +
    check("turn SSH certificates off: said, the toggle offers on, no form to sign",
          st == 303 and "are off" in page and 'action="/ssh/on"' in page and 'action="/ssh/sign"' not in page)
    st, loc, _, _ = req("POST", "/ssh/on", {"csrf": "dev"})
    check("...and on again", st == 303 and 'action="/ssh/sign"' in req("GET", loc or "/ssh")[3])
    st, _, _, page = req("POST", "/stepca/issue", {"csrf": "dev", "cn": "x"})
    check("generate shows sample downloads and the one-time key warning",
          st == 200 and 'download="device.home.arpa.key"' in page and "only copy of the private key" in page)
    page = req("GET", "/")[3]
    tiles = page.split("<section class=\"tiles\">")[1].split("</section>")[0]
    check("overview shows one status light per service", tiles.count('class="light ok"') == 9 and "pill" not in tiles)
    check("overview (2.1.8.3): a Run doctor button and the Updates section with update and roll-back forms",
          'action="/overview/doctor"' in page and "<h2>Updates</h2>" in page
          and 'action="/overview/images/postgres/update"' in page and 'action="/overview/images/nginx/rollback"' in page
          and 'action="/overview/images/nginx/update"' not in page)
    st, loc, _, _ = req("POST", "/overview/doctor", {"csrf": "dev"})
    job = req("GET", loc)[3] if loc else ""
    check("run doctor -> its job page: each check with its result", st == 303 and loc.startswith("/jobs/")
          and "3 of 4 checks passed" in job and "a sample failure" in job, (st, loc))
    st, loc, _, _ = req("POST", "/overview/images/postgres/update", {"csrf": "dev"})
    job = req("GET", loc)[3] if loc else ""
    check("update an image -> its job page says what moved", st == 303 and "updated postgres" in job, (st, loc))
    st, _, _, _ = req("GET", "/jobs/no-such-job")
    check("refused: a job that is not yours or does not exist", st == 400)
    page = req("GET", "/stepca?view=acme")[3]
    check("Step-CA ACME (2.1.5.8): the directory, the enrolled machines, withdraw and enroll forms",
          "acme/acme/directory" in page and "nas.home.arpa" in page and "/bind9/tsig/acme-nas/delete" in page
          and 'action="/stepca/acme/enroll"' in page)
    st, _, _, page = req("POST", "/stepca/acme/enroll", {"csrf": "dev", "host": "printer", "domain": "home.arpa"})
    check("enroll a machine for DNS-01 -> its key, shown once", st == 200 and "acme-printer" in page)
    page = req("GET", "/")[3]
    check("overview lists the host changes: a declined one with what it leaves unmanaged",
          "Host changes" in page and "Host trust store" in page and "declined" in page
          and "does not trust fabric&#39;s CA" in page and "not asked" in page, page[-800:])
    st, _, _, page = req("GET", "/bind9?view=reverse")
    check("reverse zones generated from forward A/AAAA records",
          st == 200 and "1.168.192.in-addr.arpa" in page and "20.168.192.in-addr.arpa" in page
          and "cam-front.iot.home.arpa." in page and ".ip6.arpa" in page, page[:300])
    check("public address listed without a reverse record", "203.0.113.7" in page and "public address" in page)
    st, _, _, page = req("GET", "/bind9?zone=dynamic_zone_var")
    check("forward records show their automatic PTR", "40.1.168.192.in-addr.arpa" in page)
    st, _, _, page = req("GET", "/bind9?view=tsig")
    check("TSIG view lists sample keys", st == 200 and "npm-certbot" in page and "New TSIG key for a zone" in page)
    st, _, _, page = req("POST", "/bind9/tsig/create", {"csrf": "dev", "name": "preview-key", "zone": "home.arpa"})
    check("creating a TSIG key shows its secret and rfc2136.ini once",
          st == 200 and "dns_rfc2136_name = preview-key" in page and 'class="secret"' in page)
    st, _, _, page = req("GET", "/directory")
    check("Directory devices page: devices with status lights, roles and access",
          st == 200 and "jims-laptop" in page and "VLAN 10" in page and 'class="light bad"' in page)
    st, _, _, page = req("GET", "/directory?view=device&name=jims-laptop")
    check("device page: effective permissions and linked certificate",
          "Join the network with its certificate" in page and "AB:AB:AB" in page and "Generate key + certificate" in page)
    st, loc, _, _ = req("POST", "/directory/devices/_new", {"csrf": "dev", "name": "nas", "type": "server",
                                                         "macs": "AA-BB-CC-00-00-01", "role_trusted": "1", "enabled": "1"})
    page = req("GET", "/directory?view=device&name=nas")[3]
    check("adding a device (in memory, real validation): MAC normalised, role applied",
          st == 303 and "aa:bb:cc:00:00:01" in page and "VLAN" in page, (st, loc))
    st, loc, _, _ = req("POST", "/directory/devices/_new", {"csrf": "dev", "name": "dup", "macs": "aa:bb:cc:00:00:01"})
    check("a MAC already in use is refused with the reason", "already+belongs" in (loc or "") or "already%20belongs" in (loc or ""), loc)
    st, loc, _, _ = req("POST", "/directory/roles/iot/delete", {"csrf": "dev"})
    check("a role that still has devices cannot be deleted", "still+has" in (loc or ""), loc)
    page = req("GET", "/directory?view=roles")[3]
    check("roles page lists roles with their grants", "quarantine" in page and "network:mab" in page)
    page = req("GET", "/directory?view=people")[3]
    check("people page (admin): people, add form, reset buttons, Keycloak link for fabric groups",
          "jim@home.arpa" in page and "Keycloak admin console" in page and "/directory/people/_new" in page
          and "Reset sign-in" in page)
    check("people page (admin): disable buttons, the group form and the remove form (2.1.6.30)",
          "/directory/people/sam/disable" in page and "/directory/people/_form/groups" in page
          and "/directory/people/_form/delete" in page, page[-800:])
    st, loc, _, _ = req("POST", "/directory/people/sam/disable", {"csrf": "dev"})
    page = req("GET", "/directory?view=people")[3]
    check("disable a person -> listed locked, an enable button instead", st == 303 and "disabled" in (loc or "")
          and "/directory/people/sam/enable" in page, loc)
    st, loc, _, _ = req("POST", "/directory/people/sam/enable", {"csrf": "dev"})
    check("enable them again", st == 303 and "enabled" in (loc or "")
          and "/directory/people/sam/disable" in req("GET", "/directory?view=people")[3], loc)
    st, loc, _, _ = req("POST", "/directory/people/_form/groups", {"csrf": "dev", "uid": "sam", "group": "admins",
                                                                   "action": "add"})
    check("put a person in a group (the form picks them)", st == 303 and "added+to+admins" in (loc or ""), loc)
    st, loc, _, _ = req("POST", "/directory/people/_form/delete", {"csrf": "dev", "uid": "sam", "confirm": "sma"})
    check("refused: a removal without the user name typed back", st == 303 and "type+the+user+name" in (loc or ""),
          loc)
    st, loc, _, _ = req("POST", "/directory/people/_form/delete", {"csrf": "dev", "uid": "sam", "confirm": "sam"})
    check("remove a person with the user name typed back -> gone from the list", st == 303
          and "removed" in (loc or "") and "sam@home.arpa" not in req("GET", "/directory?view=people")[3], loc)
    page = req("GET", "/directory?view=domain")[3]
    check("domain section: the domain, its controller running, the password policy",
          "ad.home.arpa" in page and "pi-core.ad.home.arpa" in page and "Minimum length" in page, page[-600:])
    check("domain section: the roles named plainly, no role's DN (2.1.2.22)",
          "This controller holds all five roles" in page and "NTDS Settings" not in page, page[-1500:])
    check("domain section (admin): the password policy form and Apply (2.1.2.22)",
          'action="/directory/domain/password-policy"' in page and 'name="lockout_window_minutes"' in page
          and 'name="complexity"' in page and 'action="/apply"' in page)
    st, loc, _, _ = req("POST", "/directory/domain/password-policy",
                        {"csrf": "dev", "minimum_length": "16", "history": "24", "minimum_age_days": "0",
                         "maximum_age_days": "0", "lockout_threshold": "5", "lockout_minutes": "15",
                         "lockout_window_minutes": "15", "complexity": "on"})
    check("password policy saved -> shown", st == 303 and "msg=" in (loc or "")
          and 'name="minimum_length" required inputmode="numeric" pattern="[0-9]+" value="16"' in req(
                  "GET", "/directory?view=domain")[3], loc)
    for form, why in (({"lockout_minutes": "5", "lockout_window_minutes": "15"}, "at least as long"),
                      ({"minimum_length": "99"}, "from 0 to 64"), ({"history": "lots"}, "whole number")):
        st, loc, _, _ = req("POST", "/directory/domain/password-policy", {"csrf": "dev", **form})
        check(f"password policy refused ({why}), saying why, nothing changed",
              st == 303 and why in urllib.parse.unquote_plus(loc or "")
              and 'name="minimum_length" required inputmode="numeric" pattern="[0-9]+" value="16"' in req(
                  "GET", "/directory?view=domain")[3], loc)
    # 2.1.2.22 item 1: while a fresh install's first fetch runs the tab refreshes itself, then stops
    page = req("GET", "/dns-filter?view=lists&fresh=1")[3]
    check("DNS filter, first fetch running: the page refreshes itself (a meta refresh, no script) and says so",
          '<meta http-equiv="refresh" content="10;url=/dns-filter?view=lists&amp;wait=1">' in page
          and "still being fetched" in page and "<script" not in page, page[:800])
    page = req("GET", "/dns-filter?view=lists&fresh=1&wait=30")[3]
    check("DNS filter: after 30 refreshes it stops and says what to do", 'http-equiv="refresh"' not in page
          and "Fetch every list now" in page and "after five minutes" in page)
    page = req("GET", "/dns-filter?view=lists")[3]
    check("DNS filter: every ticked list has a copy and the catalogue is read -> no refresh",
          'http-equiv="refresh"' not in page and "still being fetched" not in page)
    page = req("GET", "/directory?view=machines")[3]
    check("machines section (admin): machines with state, disable/enable and remove, the add form",
          "host-1" in page and "/directory/machines/host-1/disable" in page and "/directory/machines/ws2404/enable" in page
          and "/directory/machines/_new" in page)
    check("machines section (admin): who may sign in per OU, each with a clear form, and the set form (1.6.11.4)",
          "Who may sign in" in page and "machines/linux" in page and "lan-machine-admins" in page
          and 'action="/directory/logon/clear"' in page and 'action="/directory/logon/set"' in page
          and "fabric-break-glass" in page)
    check("machines section (admin): host groups with their machines and a remove form, the membership and new-group "
          "forms; sudo rules with who made each, remove only for fabric's, the add form (1.6.11.7)",
          "lan-hosts-web" in page and 'action="/directory/hostgroups/web/delete"' in page
          and 'action="/directory/hostgroups/_form/members"' in page and 'action="/directory/hostgroups/_new"' in page
          and 'action="/directory/sudo/web-restart/delete"' in page and "/directory/sudo/backup/delete" not in page
          and "/directory/sudo/lan-fabric-admins/delete" not in page and 'action="/directory/sudo/_new"' in page
          and "/usr/bin/systemctl restart nginx" in page and "read-only" in page)
    page = req("GET", "/directory?view=gpo&match=example")[3]
    check("Group Policy section (admin): what is set, a search with a set form per policy",
          "ExampleText" in page and "/directory/gpo/set" in page and "Example setting" in page)
    check("...the site's enforced controls listed apart, and a policy may be set as a control (2.1.6.20)",
          "fabric: lan controls" in page and "ExampleLocked" in page and 'name="control"' in page)
    page = req("GET", "/federation")[3]
    check("Federation tab: sites with their DC type, replication with a failing neighbour, conflicts, limits, plan",
          "lab.home.arpa" in page and "read-only" in page and "WERR_BADFILE" in page and "CNF:" in page
          and "192.168.20.0/24" in page and "fabric-agent-&lt;site&gt;" in page, page[-800:])
    page = req("GET", "/stepca?view=issue&device=printer")[3]
    check("Step-CA generate form offers devices, prefilled from the device page",
          "<option selected>printer</option>" in page and 'value="printer.home.arpa"' in page)
    page = req("GET", "/openbao")[3]
    check("OpenBao tab: unsealed, static seal, engines", "Unsealed" in page and "static" in page and "fabric/" in page)
    page = req("GET", "/openbao?view=disk")[3]
    check("disk encryption guide: LUKS with the same YubiKey (FIDO2) or USB stick, untested note",
          "systemd-cryptenroll --fido2-device=auto" in page and "/luks.key:UUID=" in page and "Untested" in page
          and "Disk encryption" in page)
    page = req("GET", "/openbao?view=secrets")[3]
    check("secrets: fabric's own entry, OpenBao UI link (OIDC), break glass", "fabric/secrets" in page
          and "ui/vault/auth?with=oidc" in page and "break-glass" in page)
    page = req("GET", "/openbao?view=unlock")[3]
    check("unlock methods: slots, kill-switch state, the key-file warning", "Kill switch off" in page
          and "YubiKey 5 Nano" in page and "Remove the key file" in page)
    page = req("GET", "/openbao?view=add-security-key")[3]
    check("add security key: PKCS#11 tokens, enrolled one disabled, untested-hardware note", "23456799" in page
          and "already an unlock method" in page and 'name="pin"' in page and "untested" in page
          and 'value="/usr/lib/aarch64-linux-gnu/libykcs11.so.2|23456799"' in page)
    st, loc, _, _ = req("POST", "/openbao/slots/add-security-key", {"csrf": "dev", "token": "/usr/lib/aarch64-linux-gnu/libykcs11.so.2|23456799", "pin": "x",
                                                                    "label": "safe key", "confirm": "wrong"})
    check("vault changes need the host name typed", "confirm" in (loc or ""), loc)
    req("POST", "/openbao/slots/add-security-key", {"csrf": "dev", "token": "/usr/lib/aarch64-linux-gnu/libykcs11.so.2|23456799", "pin": "x", "label": "safe key",
                                                    "confirm": "pi-core"})
    req("POST", "/openbao/slots/local/remove", {"csrf": "dev", "confirm": "pi-core"})
    page = req("GET", "/openbao?view=unlock")[3]
    check("add a second key, remove the key file: kill switch armed", "safe key" in page and "Kill switch armed" in page
          and "/etc/fabric/openbao/unseal.key" not in page)
    st, loc, _, _ = req("POST", "/openbao/rotate", {"csrf": "dev", "confirm": "pi-core"})
    check("rotate: new key version on every present method", "fabric-2" in req("GET", "/openbao?view=unlock")[3])
    st, _, _, page = req("GET", "/preview/denied")
    check("preview of a refused sign-in", st == 403 and "fabric-console-admin" in page)
finally:
    proc.terminate()
    proc.wait(timeout=5)

PORT += 1                                   # people: the helpdesk bundle
proc = subprocess.Popen([sys.executable, os.path.join(UX_WEB, "devserver.py"), "--port", str(PORT),
                         "--as", "fabric-helpdesk"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    for _ in range(50):
        try:
            req("GET", "/")
            break
        except OSError:
            time.sleep(0.2)
    page = req("GET", "/directory?view=people")[3]
    check("helpdesk: add form and reset buttons", "/directory/people/_new" in page and "Reset sign-in" in page)
    st, _, _, page = req("POST", "/directory/people/_new", {"csrf": "dev", "uid": "dana", "first": "Dana", "last": "Lee",
                                                         "email": "dana@home.arpa"})
    check("helpdesk: add a person -> one-time password shown once", st == 200 and "shown only now" in page and "dana" in page)
    st, _, _, page = req("POST", "/directory/people/sam/reset", {"csrf": "dev"})
    check("helpdesk: reset a plain user's sign-in", st == 200 and "sign-in reset" in page)
    st, loc, _, _ = req("POST", "/directory/people/jim/reset", {"csrf": "dev"})
    check("helpdesk: an admin's sign-in cannot be reset", st == 303 and "only%20an%20admin" in (loc or ""), loc)
    page = req("GET", "/directory?view=people")[3]
    check("helpdesk: disable buttons, but no group or remove form (people:groups, people:remove are admins')",
          "/directory/people/sam/disable" in page and "/directory/people/_form/groups" not in page
          and "/directory/people/_form/delete" not in page)
    st, loc, _, _ = req("POST", "/directory/people/sam/disable", {"csrf": "dev"})
    check("helpdesk: disable a plain user", st == 303 and "disabled" in (loc or ""), loc)
    st, loc, _, _ = req("POST", "/directory/people/jim/disable", {"csrf": "dev"})
    check("helpdesk: refused: disabling an admin", st == 303 and "only+an+admin" in (loc or ""), loc)
finally:
    proc.terminate()
    proc.wait(timeout=5)

PORT += 1                                   # the preview as a role bundle sees it
proc = subprocess.Popen([sys.executable, os.path.join(UX_WEB, "devserver.py"), "--port", str(PORT),
                         "--as", "fabric-auditor"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    for _ in range(50):
        try:
            req("GET", "/")
            break
        except OSError:
            time.sleep(0.2)
    page = req("GET", "/bind9")[3]
    check("--as fabric-auditor: records shown, no add form", "nas" in page and "/add" not in page and "as fabric-auditor" in page)
    page = req("GET", "/bind9?view=landing")[3]
    check("--as fabric-auditor: the landing page's links shown, no add or remove form",
          "https://nas.home.arpa:5001/" in page and "/bind9/landing/" not in page)
    page = req("GET", "/directory?view=domain")[3]
    check("--as fabric-auditor: the password policy shown, no form (domain:admin)",
          "minimum length" in page and "/directory/domain/password-policy" not in page)
    st, _, _, _ = req("POST", "/directory/domain/password-policy", {"csrf": "dev", "minimum_length": "4"})
    check("--as fabric-auditor: refused: changing the password policy (403, domain:admin)", st == 403)
    page = req("GET", "/directory?view=people")[3]
    check("--as fabric-auditor: people listed, no add form or reset buttons",
          "jim@home.arpa" in page and "/directory/people/_new" not in page and "Reset sign-in" not in page
          and "/disable" not in page and "/directory/people/_form/" not in page)
    page = req("GET", "/")[3]
    check("--as fabric-auditor: Run doctor and the Updates table, but no update or roll-back forms",
          'action="/overview/doctor"' in page and "<h2>Updates</h2>" in page and "/overview/images/" not in page)
    st, _, _, _ = req("POST", "/overview/images/postgres/update", {"csrf": "dev"})
    check("--as fabric-auditor: refused: an image update (403, images:update)", st == 403)
    page = req("GET", "/networks?subnet=iot")[3]
    check("--as fabric-auditor: the Networks tab and a subnet's table, without a single change form",
          "cam1" in page and "/networks/lan/" not in page and "Add a VLAN" not in page)
    page = req("GET", "/stepca?view=acme")[3]
    check("--as fabric-auditor: the ACME view without enroll or withdraw", "nas.home.arpa" in page
          and "/stepca/acme/enroll" not in page and "/delete" not in page)
finally:
    proc.terminate()
    proc.wait(timeout=5)

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
