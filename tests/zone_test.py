"""The `zone` suite: the deploy engine's zone deployment (fabriclib/dns: find_changed_zones, reload_zone)
with rndc stubbed out. No Docker, no BIND."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from fabriclib.dns import reload_zone as reload_zone_module  # noqa: E402
from fabriclib.dns.find_changed_zones import find_changed_zones  # noqa: E402
from fabriclib.dns.reload_zone import file_serial, reload_zone  # noqa: E402

calls = []
FREEZE_OK = {"lan.test"}          # dynamic zone: freeze/thaw succeed


class R:
    def __init__(self, rc, out=""):
        self.returncode, self.stdout, self.stderr = rc, out, ""


DST = {}                          # set below: the deployed zone folder
RACE = {"lan.test": True}         # BIND's own write lands after ours, once


def fake_rndc(args, timeout=15):
    """rndc as BIND answers it. zonestatus reports the serial of the zone
    file BIND loaded; the first thaw of lan.test puts the old file back, as
    BIND's freeze-time write did in the sandbox (the race reload_zone must
    detect and repeat)."""
    calls.append(" ".join(args))
    verb, zone = args[0], args[-1]
    path = os.path.join(DST.get("dir", ""), f"db.{zone}")
    if verb == "thaw" and RACE.pop(zone, False):
        with open(path, "w") as f:
            f.write(DST["old"])
    if verb in ("freeze", "thaw"):
        return R(0 if zone in FREEZE_OK else 1)
    if verb == "zonestatus":
        serial = file_serial(path) if os.path.exists(path) else None
        return R(0, f"name: {zone}\nserial: {serial}\n")
    return R(0)


reload_zone_module.rndc = fake_rndc
uid, gid = os.getuid(), os.getgid()
ZONE = """$ORIGIN lan.test.
@ IN SOA ns.lan.test. hostmaster.lan.test. (
                        {serial} ; Serial (Epoch timestamp offset)
                        3600 )
{records}
"""
ok = True
with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dst:
    def write(d, name, serial, records):
        with open(os.path.join(d, name), "w") as f:
            f.write(ZONE.format(serial=serial, records=records))

    # deployed: old records + a journal; rendered: same records, new serial
    write(dst, "db.lan.test", 100, "www A 1.1.1.1")
    DST.update(dir=dst, old=open(os.path.join(dst, "db.lan.test")).read())
    open(os.path.join(dst, "db.lan.test.jnl"), "w").write("journal")
    write(src, "db.lan.test", 200, "www A 1.1.1.1")
    changed = find_changed_zones(src, dst)
    print("unchanged records ignored despite new serial:", changed == [])
    ok &= changed == []

    # now a real change (the shelfmark case)
    write(src, "db.lan.test", 300, "www A 1.1.1.1\nshelfmark CNAME nas25-apps")
    write(src, "db.7.168.192.in-addr.arpa", 300, "53 PTR pi-core.lan.test.")
    changed = find_changed_zones(src, dst)
    names = [z for z, _, _ in changed]
    print("changed zones detected:", names)
    ok &= sorted(names) == ["7.168.192.in-addr.arpa", "lan.test"]
    for zone, s, d in changed:
        os.utime(s, (1, 1))              # a rendered file older than anything BIND loaded
        reload_zone(zone, s, d, uid, gid)
    fresh = time.time() - os.path.getmtime(os.path.join(dst, "db.lan.test")) < 60
    print("installed zone file has a fresh mtime (BIND reloads only newer files):", fresh)
    ok &= fresh
    print("rndc calls:", calls)
    swaps = [c for c in calls if c in ("freeze lan.test", "thaw lan.test")]
    print("BIND's late write detected and the swap repeated:", swaps == ["freeze lan.test", "thaw lan.test"] * 2)
    ok &= swaps == ["freeze lan.test", "thaw lan.test"] * 2
    ok &= "reload 7.168.192.in-addr.arpa" in calls
    deployed = open(os.path.join(dst, "db.lan.test")).read()
    print("new record deployed:", "shelfmark" in deployed)
    ok &= "shelfmark" in deployed
    print("stale journal removed:", not os.path.exists(os.path.join(dst, "db.lan.test.jnl")))
    ok &= not os.path.exists(os.path.join(dst, "db.lan.test.jnl"))

# DHCP's PTRs survive a regenerated reverse zone (2.1.10.7): BIND's frozen file, as BIND writes it ($ORIGIN, relative
# owners, a DHCID under the same owner), merged into fabric's new file; fabric's own PTR wins on a shared owner
from fabriclib.dns.install_zone_file import install_zone_file  # noqa: E402
from fabriclib.dns.merge_dynamic_records import merge_dynamic_records  # noqa: E402
from fabriclib.dns.zone_content_changed import zone_content_changed as find_changed_zones_one  # noqa: E402
rev = "0.20.10.in-addr.arpa"
fabric_new = f"""$TTL 86400
$ORIGIN {rev}.
@       IN      SOA     ns.lan.test. hostmaster.lan.test. (
                        2000000002 3600 1800 604800 86400 )
@       IN      NS      ns.lan.test.
5                       PTR     printer.lan.test.
"""
bind_old = f"""$ORIGIN .
$TTL 86400\t; 1 day
{rev}\t\tIN SOA\tns.lan.test. hostmaster.lan.test. (
\t\t\t\t2000000001 ; serial
\t\t\t\t3600 1800 604800 86400 )
\t\t\tNS\tns.lan.test.
$ORIGIN {rev}.
5\t\t\tPTR\told-name.lan.test.
100\t\t\tPTR\tlaptop.dhcp.lan.test.
$TTL 3600\t; 1 hour
\t\t\tDHCID\t( AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA= )
101\t300\tIN\tPTR\tphone.dhcp.lan.test.
"""
merged = merge_dynamic_records(rev, fabric_new, bind_old)
checks = {
    "a lease's PTR kept (relative owner)": "100.0.20.10.in-addr.arpa." in merged and "laptop.dhcp.lan.test." in merged,
    "its DHCID kept (owner repeated by indentation)": "DHCID" in merged,
    "a PTR written with TTL and class kept": "phone.dhcp.lan.test." in merged,
    "fabric's own PTR wins over BIND's older one": "old-name" not in merged and "printer.lan.test." in merged,
    "nothing to keep: the file unchanged": merge_dynamic_records(rev, fabric_new, "") == fabric_new,
    "merging twice keeps one copy": merge_dynamic_records(rev, merged, merged).count("laptop.dhcp") == 1,
}
with tempfile.TemporaryDirectory() as d:
    src, dst = os.path.join(d, "new"), os.path.join(d, f"db.{rev}")
    open(src, "w").write(fabric_new)
    open(dst, "w").write(bind_old)
    open(dst + ".jnl", "w").write("x")
    install_zone_file(src, dst, os.getuid(), os.getgid())
    got = open(dst).read()
    checks["install_zone_file keeps them in a reverse zone and drops the journal"] = \
        "laptop.dhcp.lan.test." in got and not os.path.exists(dst + ".jnl")
    fwd = os.path.join(d, "db.lan.test")
    open(fwd, "w").write("old forward with a PTR-looking line\n100 PTR x.\n")
    install_zone_file(src, fwd, os.getuid(), os.getgid())
    checks["a forward zone is replaced as before"] = open(fwd).read() == fabric_new
    # a deployed reverse zone holding fabric's render and the records kept from Kea is not a change; a new record is
    rend = os.path.join(d, "rendered")
    open(rend, "w").write(fabric_new)
    checks["the kept records are not a change (the next render finds nothing to swap)"] = \
        find_changed_zones_one(rend, dst) is False
    open(rend, "a").write("6                       PTR     scanner.lan.test.\n")
    checks["a new record of fabric's still is"] = find_changed_zones_one(rend, dst) is True

    # BIND serves a serial above the render's (Kea's registrations raise it): the file swapped in is given one above
    calls.clear()
    bumped_src, bumped_dst = os.path.join(d, "db.1.20.10.in-addr.arpa.new"), os.path.join(d, "db.1.20.10.in-addr.arpa")
    open(bumped_dst, "w").write(ZONE.format(serial=2000000500, records="5 PTR a.lan.test."))
    open(bumped_src, "w").write(ZONE.format(serial=2000000300, records="5 PTR b.lan.test."))
    DST["dir"] = d
    reload_zone("1.20.10.in-addr.arpa", bumped_src, bumped_dst, os.getuid(), os.getgid())
    checks["a serial BIND has passed is raised above it, and the swap is served"] = \
        file_serial(bumped_dst) == "2000000501" and "b.lan.test." in open(bumped_dst).read() \
        and calls.count("reload 1.20.10.in-addr.arpa") == 1
    open(bumped_src, "w").write(ZONE.format(serial=2000000900, records="5 PTR c.lan.test."))
    reload_zone("1.20.10.in-addr.arpa", bumped_src, bumped_dst, os.getuid(), os.getgid())
    checks["a serial above BIND's is left as rendered"] = file_serial(bumped_dst) == "2000000900"
for name, passed in checks.items():
    print(("PASS " if passed else "FAIL ") + "DHCP's PTRs: " + name)
    ok &= passed

print("ZONE TEST", "PASSED" if ok else "FAILED")
sys.exit(0 if ok else 1)
