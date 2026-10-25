#!/usr/bin/env python3
"""The address manager's console pages in the dev preview (manual 1.10.4.40): DHCP · Networks, a VLAN's, a subnet's
and an address's page, Add VLAN and the site's number, the search and the export, Sync now, the scan page, and DHCP
options; every change held for its page's Apply and applied, the at-once actions done at once, a thing not there
answering 404, the forms hidden without dhcp:write and the pages refused without dhcp:read. The real agent's side is
tests/ipam/pending_networks.py (the grant at hold and at Apply) and tests/webui/test_container.py.

    python3 tests/webui/test_networks.py
"""
import contextlib
import http.client
import os
import re
import subprocess
import sys
import time
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UX_WEB = os.path.join(REPO, "src", "ux", "web")
PORT = int(os.environ.get("WEBUI_DEV_PORT", "18865"))
START_WAIT = 15
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def req(method, path, form=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=20)
    body = urllib.parse.urlencode(form) if form is not None else None
    c.request(method, path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {})
    r = c.getresponse()
    return r.status, r.getheader("Location"), r.getheader("Content-Type"), r.read().decode()


def get(path):
    return req("GET", path)[3]


def post(path, form):
    """POST a form as a browser does, following a 303: (status, location, the page shown after it)."""
    st, loc, _, page = req("POST", path, {"csrf": "dev", **form})
    if st == 303 and loc:
        page = get(loc)
    return st, loc or "", page


def refused_at(path, form, then):
    """POST a form whose page is not there (its site refused), then the message shown on another page."""
    req("POST", path, {"csrf": "dev", **form})
    return get(then)


def flash(page):
    m = re.search(r'<p class="flash (ok|bad)" role="(?:status|alert)">(.*?)</p>', page, re.S)
    return (m.group(1) + ": " + m.group(2).replace("&#39;", "'")) if m else ""


def main(page):
    return page.split("<main", 1)[1] if "<main" in page else page


def apply(page_id):
    """Apply a page's held changes; the Review after the (preview's at-once) job."""
    post(f"/changes/{page_id}/apply", {})
    return get(f"/changes/{page_id}")


@contextlib.contextmanager
def serve(bundle=None, extra=()):
    global PORT
    PORT += 1
    args = [sys.executable, os.path.join(UX_WEB, "devserver.py"), "--port", str(PORT), *extra]
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


PAGES = ["/networks", "/networks?site=parents", "/networks?site=lan&vlan=20", "/networks?site=lan&subnet=iot",
         "/networks?site=lan&subnet=iot&address=10.1.20.150", "/networks?site=lan&subnet=iot&address=10.1.20.120",
         "/networks?site=lan&view=new-vlan", "/networks?site=lan&view=number", "/networks?site=lan&q=cam",
         "/networks/scan", "/networks/options", "/networks/options?site=lan&target=subnet:iot",
         "/networks/options?site=lan&target=address:10.1.20.150", "/networks/options?site=lan&target=site"]

with serve():
    print("--- the pages")
    # covers: web:get.networks web:get.networks.options web:get.networks.scan +
    bad = [(p, s) for p, s in ((p, req("GET", p)[0]) for p in PAGES) if s != 200]
    check(f"every page renders ({len(PAGES)})", not bad, bad)
    check("no page carries a script or inline style (the strict CSP)",
          not [p for p in PAGES if re.search(r"<script|style=|\son[a-z]+=", get(p))])
    check("no form inside a table cell (the page pattern, 1.8.6.3)",
          not [p for p in PAGES if re.search(r"<td[^>]*>(?:(?!</td>).)*<form", get(p), re.S)])
    page = get("/networks")
    check("DHCP's entry lists Networks, DHCP options and Kea; Networks is the page shown",
          'href="/networks" class="active" aria-current="page">Networks' in page
          and 'href="/networks/options"' in page and 'href="/kea"' in page)
    check("Networks lists the sites, Sync now, the scans requested, the VLANs with each subnet's bar",
          all(w in main(page) for w in (">lan</a>", ">parents</a>", "Sync now", "Scans requested at lan",
                                        'href="/networks?site=lan&amp;vlan=20"', 'class="netbar"',
                                        "DNS waits for an apply or Sync now")))
    check("its actions bar: Add VLAN, Set site number, Scan a subnet, DHCP options, Export",
          all(w in page for w in ("view=new-vlan", "view=number", 'href="/networks/scan"',
                                  'href="/networks/options?site=lan"', 'href="/networks/export?site=lan"')))
    page = get("/networks?site=parents")
    check("another site: its plan, the scans asked there with their answers, no Sync now, no Scan a subnet",
          "VLANs at parents" in page and "10.2.20.77" in page and "In use, unrecorded" in page
          and 'action="/networks/sync"' not in page and 'href="/networks/scan"' not in page)
    page = get("/networks?site=lan&subnet=iot")
    check("a subnet's page: its facts, bar, ranges, address table linked, options with sources, its forms in sections",
          all(w in page for w in ("Subnet iot", "10.1.20.0/24", 'class="netbar tall"', "Ranges", "lease · unrecorded",
                                  "address=10.1.20.150", "provided by fabric", "Change subnet", "Add range",
                                  "Remove a range", "Record an address", "Remove subnet", "Scan this subnet")),
          page[:300])
    page = get("/networks?site=parents&subnet=iot")
    check("another site's subnet: Scan at parents (a request), not Scan this subnet",
          'action="/networks/scan/request"' in page and "Scan at parents" in page and "Scan this subnet" not in page)
    page = get("/networks?site=lan&subnet=iot&address=10.1.20.150")
    check("a reservation's page: its facts, Change and Remove",
          "cam1" in page and "aa:bb:cc:dd:ee:01" in page and "Change 10.1.20.150" in page
          and 'action="/networks/plan/lan/addresses/10.1.20.150/delete"' in page)
    page = get("/networks?site=lan&subnet=iot&address=10.1.20.120")
    check("a lease nobody recorded: Record it", "Record 10.1.20.120" in page and "laptop1" in page)
    page = get("/networks?site=lan&q=cam")
    check("search: the matching rows, each linked to its address", "Matching cam" in page
          and "address=10.1.20.150" in page)
    st, _, ctype, body = req("GET", "/networks/export?site=lan")
    # covers: web:get.networks.export +
    check("export: the address table as CSV", st == 200 and ctype.startswith("text/csv") and "10.1.20.150" in body,
          (st, ctype, body[:200]))

    print("--- a thing not there answers 404 (2.1.8.16)")
    for path in ("/networks?site=nowhere", "/networks?site=lan&vlan=99", "/networks?site=lan&subnet=nosuch",
                 "/networks?site=lan&subnet=iot&address=10.1.20.77", "/networks/export?site=nowhere",
                 "/networks/options?site=nowhere", "/networks/options?site=lan&target=subnet:nosuch"):
        # covers: web:get.networks web:get.networks.export web:get.networks.options -
        st = req("GET", path)[0]
        check(f"{path}: 404", st == 404, st)
    st = req("GET", "/networks/options?site=lan&target=bogus")[0]
    check("a target that is not one: refused (400)", st == 400, st)

    print("--- the plan's changes, held for Networks' Apply (1.10.4.40.2)")
    # covers: web:post.networks.plan.*.vlans +
    st, loc, page = post("/networks/plan/lan/vlans", {"id": "40", "name": "cams", "subnet": "", "split": "on"})
    check("Add VLAN: held, back on the site's list, saying so; not in the plan yet",
          loc == "/networks?site=lan" and "Waiting for Apply: Add VLAN 40 (cams) at lan" in flash(page)
          and 'vlan=40"' not in page and "1 change pending" in page, (loc, flash(page), "1 change pending" in page))
    review = apply("networks")
    check("...applied: the finish brings this site's plan in line, the VLAN listed",
          "plan to Kea and the firewall" in review and 'vlan=40"' in get("/networks"),
          main(review)[:1500])
    # covers: web:post.networks.plan.*.vlans -
    st, loc, page = post("/networks/plan/lan/vlans", {"id": "40", "name": "again"})
    check("Add VLAN with an ID taken: held, then refused at Apply with why, left pending",
          "Waiting for Apply" in flash(page))
    review = apply("networks")
    check("...refused at Apply, saying why", "VLAN 40 is already in lan&#39;s plan" in review
          or "VLAN 40 is already in lan's plan" in review, main(review)[:1500])
    post("/changes/networks/discard", {})
    # a location without a DC inside the site (2.1.10.49, manual 1.10.4.46)
    form = get("/networks?site=lan&view=new-vlan")
    check("Add VLAN offers a Location (empty: this DC's own)", 'name="location"' in form, main(form)[:600])
    st, loc, page = post("/networks/plan/lan/vlans", {"id": "20", "name": "iot", "location": "branch",
                                                      "subnet": "10.9.20.0/24", "split": "on"})
    check("Add VLAN 20 at branch beside the site's own VLAN 20: held in its words",
          "Waiting for Apply: Add VLAN 20@branch (iot) at lan" in flash(page), flash(page))
    review = apply("networks")
    page = get("/networks?site=lan&vlan=20%40branch")
    check("...applied: listed at branch, its page titled VLAN 20 at branch with its subnet branch-iot",
          "at branch" in get("/networks") and "VLAN 20 at branch" in page and "branch-iot" in page
          and 'name="to_location" value="branch"' in page, main(page)[:800])
    st, loc, page = post("/networks/plan/lan/vlans", {"id": "30", "name": "cams", "location": "branch"})
    review = apply("networks")
    check("Add VLAN at a location with no subnet given: refused at Apply, saying why",
          "give --subnet: a location" in review.replace("&#39;", "'"), main(review)[:800])
    post("/changes/networks/discard", {})
    CHANGES = [("/networks/plan/lan/block", {"number": "7"}, "Set the site's number to 7 at lan",
                "web:post.networks.plan.*.block"),
               ("/networks/plan/lan/vlans/30", {"name": "guests", "back_vlan": "30"}, "Change VLAN 30 at lan",
                "web:post.networks.plan.*.vlans.*"),
               ("/networks/plan/lan/vlans/30/delete", {}, "Remove VLAN 30 at lan",
                "web:post.networks.plan.*.vlans.*.delete"),
               ("/networks/plan/lan/subnets", {"vlan": "20", "cidr": "10.1.21.0/24", "back_vlan": "20"},
                "Add subnet 10.1.21.0/24 to VLAN 20 at lan", "web:post.networks.plan.*.subnets"),
               ("/networks/plan/lan/subnets/iot", {"gateway": "10.1.20.1", "back_subnet": "iot"},
                "Change subnet iot at lan", "web:post.networks.plan.*.subnets.*"),
               ("/networks/plan/lan/subnets/guest/delete", {}, "Remove subnet guest at lan",
                "web:post.networks.plan.*.subnets.*.delete"),
               ("/networks/plan/lan/ranges", {"vlan": "20", "kind": "static", "first": "10.1.20.2",
                                              "last": "10.1.20.9", "back_subnet": "iot"},
                "Add static range 10.1.20.2 - 10.1.20.9 at lan", "web:post.networks.plan.*.ranges"),
               ("/networks/plan/lan/ranges/delete", {"vlan": "20", "first": "10.1.20.250", "back_subnet": "iot"},
                "Remove the range from 10.1.20.250 in VLAN 20 at lan", "web:post.networks.plan.*.ranges.delete"),
               ("/networks/plan/lan/addresses", {"ip": "10.1.20.33", "kind": "static", "vlan": "20",
                                                 "back_subnet": "iot"},
                "Record 10.1.20.33 as static at lan", "web:post.networks.plan.*.addresses"),
               ("/networks/plan/lan/addresses/10.1.20.10", {"name": "nas2", "back_subnet": "iot"},
                "Change 10.1.20.10 at lan", "web:post.networks.plan.*.addresses.*"),
               ("/networks/plan/lan/addresses/10.1.20.10/delete", {"back_subnet": "iot"},
                "Remove 10.1.20.10 at lan", "web:post.networks.plan.*.addresses.*.delete")]
    for path, form, said, eid in CHANGES:
        # covers: web:post.networks.plan.*.block web:post.networks.plan.*.vlans.* +
        # covers: web:post.networks.plan.*.vlans.*.delete web:post.networks.plan.*.subnets +
        # covers: web:post.networks.plan.*.subnets.* web:post.networks.plan.*.subnets.*.delete +
        # covers: web:post.networks.plan.*.ranges web:post.networks.plan.*.ranges.delete +
        # covers: web:post.networks.plan.*.addresses web:post.networks.plan.*.addresses.* +
        # covers: web:post.networks.plan.*.addresses.*.delete +
        st, loc, page = post(path, form)
        check(f"{eid}: held, saying {said!r}", f"Waiting for Apply: {said}" in flash(page), flash(page))
    back = [post(p, f)[1] for p, f in (("/networks/plan/lan/subnets/iot", {"back_subnet": "iot"}),
                                         ("/networks/plan/lan/vlans/20", {"back_vlan": "20"}),
                                         ("/networks/plan/lan/subnets/iot/delete", {"back_subnet": "iot"}))]
    check("back on the subnet's or the VLAN's page; on the site's list after a subnet's removal",
          back == ["/networks?site=lan&subnet=iot", "/networks?site=lan&vlan=20", "/networks?site=lan"], back)
    review = get("/changes/networks")
    check("the Review lists each held change in its words", "Remove VLAN 30 at lan" in review
          and "Record 10.1.20.33 as static at lan" in review)
    review = apply("networks")
    check("...applied in order, then the finish", "plan to Kea and the firewall" in review, main(review)[:600])
    check("...the sample changed: VLAN 30 gone, 10.1.20.33 recorded, 10.1.20.10 removed",
          'vlan=30"' not in get("/networks") and "address=10.1.20.33" in get("/networks?site=lan&subnet=iot")
          and "address=10.1.20.10&" not in get("/networks?site=lan&subnet=iot") + "&")
    # covers: web:post.networks.plan.*.block web:post.networks.plan.*.vlans.* -
    # covers: web:post.networks.plan.*.vlans.*.delete web:post.networks.plan.*.subnets -
    # covers: web:post.networks.plan.*.subnets.* web:post.networks.plan.*.subnets.*.delete -
    # covers: web:post.networks.plan.*.ranges web:post.networks.plan.*.ranges.delete -
    # covers: web:post.networks.plan.*.addresses web:post.networks.plan.*.addresses.* -
    # covers: web:post.networks.plan.*.addresses.*.delete -
    for path, form in (("/networks/plan/nowhere/block", {"number": "3"}),
                       ("/networks/plan/nowhere/vlans/20", {"name": "x"}),
                       ("/networks/plan/nowhere/vlans/20/delete", {}),
                       ("/networks/plan/nowhere/subnets", {"vlan": "20"}),
                       ("/networks/plan/nowhere/subnets/iot", {}), ("/networks/plan/nowhere/subnets/iot/delete", {}),
                       ("/networks/plan/nowhere/ranges", {}), ("/networks/plan/nowhere/ranges/delete", {}),
                       ("/networks/plan/nowhere/addresses", {"ip": "10.9.9.9"}),
                       ("/networks/plan/nowhere/addresses/10.9.9.9", {}),
                       ("/networks/plan/nowhere/addresses/10.9.9.9/delete", {})):
        page = refused_at(path, form, "/networks")
        check(f"{path}: a site that is not the domain's refused when held, nothing pending",
              "no such site: nowhere" in flash(page) and "change pending" not in page, flash(page))
    for path in ("/networks/plan/lan/vlans/20/rename", "/networks/plan/lan", "/networks/plan//vlans",
                 "/networks/lan/vlans", "/networks/options/option-editors", "/networks/scan/local"):
        st = req("POST", path, {"csrf": "dev"})[0]
        check(f"{path}: not a form (404)", st == 404, st)
    st, loc, page = post("/networks/plan/lan/block", {"number": "0"})
    apply_page = apply("networks")
    check("a bad site number: refused at Apply with why, nothing changed", "a whole number from 1 to 255"
          in apply_page, main(apply_page)[:800])
    post("/changes/networks/discard", {})

    print("--- done at once: Sync now, Scan now, Scan at <site>")
    # covers: web:post.networks.sync +
    st, loc, page = post("/networks/sync", {})
    check("Sync now: done at once, saying what it did, nothing held",
          loc == "/networks" and "Synced: Kea updated" in flash(page) and "change pending" not in page, flash(page))
    page = get("/networks/scan?noscan=1")
    check("the scan page without the grant to scan here: says why, no Scan now",
          "you may not scan here" in page and "no grant gives you networks scan at lan" in page
          and 'action="/networks/scan"' not in page)
    # covers: web:post.networks.scan +
    st, _, _, page = req("POST", "/networks/scan", {"csrf": "dev", "subnet": "10.1.20.0/24"})
    check("Scan now: done at once, what answered shown, Record a find offered for the unrecorded",
          st == 200 and "10.1.20.77" in page and "Record a find" in page and 'value="10.1.20.88|"' in page, page[:300])
    # covers: web:post.networks.scan.record +
    st, loc, page = post("/networks/scan/record", {"find": "10.1.20.77|aa:bb:cc:00:00:77", "kind": "reservation",
                                                   "name": "cam4"})
    check("Record a find: held on Networks", loc == "/networks/scan"
          and "Waiting for Apply: Record 10.1.20.77 (found by a scan) as a reservation at lan" in flash(page)
          and "1 change pending" in page, flash(page))
    st, loc, page = post("/networks/scan/record", {"find": "10.1.20.88|", "kind": "reservation",
                                                   "mac": "aa:bb:cc:00:00:88"})
    check("a find with no MAC, its MAC typed: held as a reservation (2.1.10.50)",
          "as a reservation at lan" in flash(page) and "2 changes pending" in page, flash(page))
    st, loc, page = post("/networks/scan/record", {"find": "10.1.20.99|", "kind": "static"})
    check("a find with no MAC as a static address: held", "as a static at lan" in flash(page), flash(page))
    review = apply("networks")
    check("...applied: all three recorded", "address=10.1.20.77" in get("/networks?site=lan&subnet=iot")
          and "address=10.1.20.88" in get("/networks?site=lan&subnet=iot")
          and "address=10.1.20.99" in get("/networks?site=lan&subnet=iot"), main(review)[:800])
    # covers: web:post.networks.scan.record -
    st, loc, page = post("/networks/scan/record", {"find": "10.1.20.66|", "kind": "reservation"})
    check("a reservation for a find with no MAC and none typed: refused, saying why, nothing held",
          loc == "/networks/scan" and "a reservation needs its MAC" in flash(page) and "change pending" not in page,
          flash(page))
    st, loc, page = post("/networks/scan/record", {"find": "10.1.20.77|aa:bb:cc:00:00:77"})
    review = apply("networks")
    check("recording a find already claimed: refused at Apply with why", "already claimed" in review,
          main(review)[:800])
    post("/changes/networks/discard", {})
    # covers: web:post.networks.scan.request +
    st, loc, page = post("/networks/scan/request", {"site": "parents", "subnet": "iot", "cidr": "10.2.20.0/24"})
    check("Scan at parents: done at once, back on its subnet saying where the answer shows",
          loc == "/networks?site=parents&subnet=iot" and "requested at parents" in flash(page), (loc, flash(page)))
    # covers: web:post.networks.scan.request -
    page = refused_at("/networks/scan/request", {"site": "nowhere", "subnet": "iot"}, "/networks")
    check("Scan at a site that is not there: refused, said", "no such site: nowhere" in flash(page), flash(page))

    print("--- DHCP options, held for its own Apply")
    OPTS = [("/networks/options/options", {"action": "set", "where": "site", "option": "ntp-servers",
                                           "data": "10.1.10.4", "site": "lan"}, "Set option ntp-servers at lan"),
            ("/networks/options/options", {"action": "set", "where": "domain", "option": "domain-search",
                                           "data": "home.arpa", "site": "lan"},
             "Set option domain-search in the domain's set"),
            ("/networks/options/options", {"action": "set", "where": "class:site:uefi", "option": "67",
                                           "data": "ipxe.efi", "site": "lan"}, "Set option 67 on class uefi at lan"),
            ("/networks/options/options", {"action": "remove", "picked": "class:site:uefi|ntp-servers",
                                           "site": "lan"}, "Remove option ntp-servers on class uefi at lan"),
            ("/networks/options/options", {"action": "set", "where": "subnet:iot", "option": "67", "data": "x.efi",
                                           "site": "lan", "view_target": "subnet:iot"},
             "Set option 67 on subnet iot at lan"),
            ("/networks/options/classes", {"action": "add", "scope": "site", "name": "bios", "test": "x",
                                           "site": "lan"}, "Add client class bios at lan"),
            ("/networks/options/classes", {"action": "remove", "picked": "site|uefi", "site": "lan"},
             "Remove client class uefi at lan"),
            ("/networks/options/option-defs", {"action": "define", "scope": "site", "name": "ztp", "code": "240",
                                               "type": "string", "site": "lan"}, "Define option ztp at lan"),
            ("/networks/options/option-defs", {"action": "undefine", "picked": "site|ztp-url", "site": "lan"},
             "Undefine option ztp-url at lan"),
            ("/networks/options/netboot", {"action": "on", "target": "iot", "server": "10.1.10.5", "site": "lan",
                                           "view_target": "subnet:iot"}, "Switch network boot on for iot at lan")]
    for path, form, said in OPTS:
        # covers: web:post.networks.options.options web:post.networks.options.classes +
        # covers: web:post.networks.options.option-defs web:post.networks.options.netboot +
        st, loc, page = post(path, form)
        check(f"{path} ({form['action']}): held, saying {said!r}", f"Waiting for Apply: {said}" in flash(page)
              and loc.startswith("/networks/options?site=lan"), (loc, flash(page)))
    review = apply("options")
    check("...applied on the DHCP options page's own Apply, then the finish", "Apply this site" in review
          and "change pending" not in get("/networks/options"), main(review)[:800])
    # covers: web:post.networks.options.options web:post.networks.options.classes -
    # covers: web:post.networks.options.option-defs web:post.networks.options.netboot -
    for path in ("/networks/options/options", "/networks/options/classes", "/networks/options/option-defs",
                 "/networks/options/netboot"):
        page = refused_at(path, {"action": "set", "site": "nowhere", "where": "site", "option": "x"},
                          "/networks/options")
        check(f"{path}: a site that is not there refused when held, nothing pending",
              "no such site: nowhere" in flash(page) and "change pending" not in page, flash(page))

with serve("fabric-auditor"):
    print("--- without dhcp:write (an auditor): the pages, no forms; changes refused")
    page = get("/networks?site=lan&subnet=iot") + get("/networks") + get("/networks/options?target=subnet:iot")
    check("no form that changes anything is shown",
          not re.search(r'action="/networks/(plan|sync|options/|scan/)', page), re.findall(r'action="[^"]+"', page))
    # covers: web:post.networks.sync -
    st, loc, page = post("/networks/sync", {})
    check("Sync now refused: the permission", "dhcp:write" in (flash(page) + page), flash(page))
    # covers: web:post.networks.scan -
    st, loc, _, page = req("POST", "/networks/scan", {"csrf": "dev", "subnet": "10.1.20.0/24"})
    check("a scan refused: the permission", st == 403 or "dhcp:write" in page, st)
    st, loc, page = post("/networks/plan/lan/vlans", {"id": "41", "name": "x"})
    check("a plan change refused when held: the permission, nothing pending",
          "dhcp:write" in flash(page) and "change pending" not in page, flash(page))

with serve("none"):
    print("--- without dhcp:read: refused")
    for path in ("/networks", "/networks/scan", "/networks/options", "/networks/export"):
        # covers: web:get.networks.scan -
        st = req("GET", path)[0]
        check(f"{path} refused (403)", st == 403, st)

sys.exit(1 if FAILED else 0)
