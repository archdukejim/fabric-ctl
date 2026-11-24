"""Run in the DC's image with the DC stopped (manual 1.3.7.6): BIND's copy of the DNS partitions (bind-dns/dns) and
its keytab made again after a restore from an online bundle, whose offline copy does not bring them. `docker compose
run --rm --no-deps --entrypoint python3 samba /fabric/make_bind_dns.py`; fabric/backup/load_directory_dump runs it."""
import runpy
import sys

import ldb
import samba.provision as provision
import samba.provision.sambadns as sambadns
from samba.dcerpc import security
from samba.ndr import ndr_unpack

TOOL = "/usr/sbin/samba_upgradedns"
CONF = "/data/etc/smb.conf"


def dnsadmins_sid(samdb, domaindn):
    """Purpose: the DnsAdmins group's SID, found by its name. Samba's own lookup builds its DN from the well-known users
             container, which fabric moves to OU=people (ensure_layout, 1.6.13.2) while the group stays in CN=Users,
             so samba_upgradedns stops with "No such Base DN" (found 2026-11-23 by the samba suite).
    Inputs:  samdb — the open sam.ldb; domaindn — the domain's DN (str).
    Returns: security.dom_sid, as Samba's get_dnsadmins_sid does.
    Fails:   LookupError when no single DnsAdmins group is in the domain.
    Feeds:   main (put in place of samba.provision's get_dnsadmins_sid)."""
    res = samdb.search(base=domaindn, scope=ldb.SCOPE_SUBTREE, attrs=["objectSid"],
                       expression="(&(objectClass=group)(sAMAccountName=DnsAdmins))")
    if len(res) != 1:
        raise LookupError(f"the domain has {len(res)} DnsAdmins groups, not one")
    return ndr_unpack(security.dom_sid, res[0]["objectSid"][0])


def main():
    """Purpose: the tool's entry: Samba's samba_upgradedns for BIND's DLZ, unchanged but for the DnsAdmins lookup.
    Inputs:  none.
    Returns: samba_upgradedns's exit status (0 when made).
    Fails:   what samba_upgradedns raises, printed by Python (exit 1).
    Feeds:   the command line above."""
    provision.get_dnsadmins_sid = sambadns.get_dnsadmins_sid = dnsadmins_sid
    sys.argv = [TOOL, "--dns-backend=BIND9_DLZ", f"--configfile={CONF}"]
    try:
        runpy.run_path(TOOL, run_name="__main__")
    except SystemExit as exc:
        return exc.code or 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
