import os
import subprocess
import tempfile

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import AUDIT_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.dhcp.stale_dhcp_names import stale_dhcp_names
from fabriclib.dns import constants


def _first_line(res):
    """Purpose: what a failed command said, in one line.
    Inputs:  res — a CompletedProcess, or None (a timeout).
    Returns: str.
    Fails:   never.
    Feeds:   clear_stale_dhcp_names."""
    if res is None:
        return "timed out"
    text = " ".join((res.stdout + " " + res.stderr).split())
    return text[:300] or f"exit status {res.returncode}"


def _served_zone(zone):
    """Purpose: a dynamic zone as BIND serves it: its file with the journal applied, read in BIND's container by
             named-compilezone (read only; BIND transfers none of its zones, and `rndc sync` writes the file later).
    Inputs:  zone — the zone's name (from validated settings); its file is /var/lib/bind/db.<zone>.
    Returns: the zone's text, one record per line with absolute names.
    Fails:   ValidationError when the zone cannot be read (BIND's container not running, a damaged file).
    Feeds:   clear_stale_dhcp_names."""
    try:
        res = subprocess.run(["docker", "exec", constants.BIND_CONTAINER, "named-compilezone", "-j", "-f", "text",
                              "-F", "text", "-s", "full", "-o", "-", zone, f"/var/lib/bind/db.{zone}"],
                             capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        res = None
    if res is None or res.returncode != 0:
        raise ValidationError(f"{zone} could not be read as BIND serves it (named-compilezone: {_first_line(res)})")
    return res.stdout


def clear_stale_dhcp_names(v, addresses, secret, actor, source, audit=AUDIT_FILE):
    """Purpose: delete what DHCP registered in dhcp.<domain> for addresses whose names are now set by hand (decision
             2.1.10.22, manual 1.10.4.20): the zone read as BIND serves it (its file and journal, in BIND's
             container), the stale records found there (stale_dhcp_names) and deleted in one RFC 2136 update signed
             with Kea's key (`nsupdate`, the key in a 0600 file, never on its command line); each removal audited.
    Inputs:  v — settings (install_kea, dhcp.ddns and ddns_subdomain, domain, deploy_base_dir, host_ip,
             bind_dns_port); addresses — hand_set_addresses(); secret — Kea's key (kea_ddns_secret); actor, source —
             the audit's (source "apply", "timer" or "cli"); audit — the audit log.
    Returns: list of (owner FQDN, type, rdata) deleted; [] with Kea or its DNS registration off, no address set by
             hand, or nothing left behind (nothing is sent then).
    Fails:   ValidationError: the zone could not be read, Kea's key has no secret, or BIND refused the update
             (nothing is deleted then: the update is one message).
    Feeds:   deploy/restart_changed (every apply), dhcp/clean_dhcp_names (`fabricctl dhcp clean-names`, the hourly
             fabric-dhcp-names timer)."""
    d = v.get("dhcp") or {}
    if not v.get("install_kea") or not d.get("ddns", True) or not addresses:
        return []
    zone = f"{d.get('ddns_subdomain', 'dhcp')}.{v['domain']}"
    stale = stale_dhcp_names(_served_zone(zone), zone, addresses)
    if not stale:
        return []
    if not secret:
        raise ValidationError("Kea's DNS key has no secret: DHCP names left behind cannot be deleted")
    script = [f"server {v.get('host_ip')} {v.get('bind_dns_port', 53)}", f"zone {zone}"]
    done = set()
    for owner, rtype, rdata in stale:
        if rtype == "DHCID":
            if owner not in done:                         # the name's whole DHCID set: no address is left at it
                script.append(f"update delete {owner} DHCID")
                done.add(owner)
        else:
            script.append(f"update delete {owner} {rtype} {rdata}")
    fd, keyfile = tempfile.mkstemp(prefix="fabric-kea-ddns-", suffix=".key")     # 0600, root's
    try:
        with os.fdopen(fd, "w") as f:
            f.write(f'key "kea-ddns" {{\n    algorithm hmac-sha256;\n    secret "{secret}";\n}};\n')
        try:
            sent = subprocess.run(["nsupdate", "-k", keyfile], input="\n".join(script + ["send", ""]),
                                  capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            sent = None
    finally:
        os.remove(keyfile)
    if sent is None or sent.returncode != 0:
        raise ValidationError(f"BIND refused deleting {len(stale)} record(s) DHCP left behind in {zone} "
                              f"(nsupdate: {_first_line(sent)}); nothing was deleted")
    for owner, rtype, rdata in stale:
        write_audit(actor, "DHCP_NAME_CLEAR", f"{owner.rstrip('.')} {rtype} {rdata} (its address's names are set "
                    "by hand, 2.1.10.22)", source, path=audit)
    return stale
