import os
import time

from fabriclib.common.console import warn
from fabriclib.dns.rndc import rndc
from fabriclib.dns.set_negative_ttl import set_negative_ttl

NEGATIVE_TTL = 30          # seconds a resolver keeps "no such name" (2.1.4.9): a new lease's name answers soon


def ensure_ddns_zone(v, uid, gid, call=rndc):
    """Purpose: Create the DHCP subzone's file (SOA + NS) once. After that only Kea's DDNS writes to the zone, through
             BIND's journal; an existing zone made with another negative-caching TTL (300 s before 2.1.4.9) is given
             NEGATIVE_TTL under the running BIND (dns/set_negative_ttl), its registrations kept.
    Inputs:  v — the vars dict (deploy_base_dir, domain, dhcp.ddns_subdomain default "dhcp").
             uid, gid — int owner of the file (BIND's user). call — rndc (tests give their own).
    Returns: True if the file was created, False if it already existed.
    Fails:   KeyError on missing vars; OSError if <deploy_base>/bind9/data is missing or not writable.
    Feeds:   deploy_kea.
    Notes:   fabric never renders this file again, so hosts registered by DDNS survive every apply (design 2.1.4.1);
             the TTL change is the one edit, made frozen. One it cannot make yet (BIND down with a journal pending) is
             a warning, and the next apply makes it.
    """
    d = v.get("dhcp") or {}
    zone = f"{d.get('ddns_subdomain', 'dhcp')}.{v['domain']}"
    path = os.path.join(v["deploy_base_dir"], "bind9", "data", f"db.{zone}")
    if os.path.exists(path):
        done = set_negative_ttl(zone, path, NEGATIVE_TTL, call=call)
        if done.startswith("left"):
            warn(f"{zone}: negative-caching TTL not set to {NEGATIVE_TTL} s yet ({done[6:]})")
        return False
    serial = int(time.time()) + 1000000000
    text = (f"$TTL 3600\n$ORIGIN {zone}.\n"
            f"@  IN SOA ns.{v['domain']}. hostmaster.{v['domain']}. ({serial} 3600 1800 604800 {NEGATIVE_TTL})\n"
            f"@  IN NS  ns.{v['domain']}.\n")
    with open(path, "w") as f:
        f.write(text)
    os.chown(path, uid, gid)
    os.chmod(path, 0o640)
    return True
