"""Group Policy between sites (manual 1.9.8.15, 2.1.6.16 revised, S8.4): Samba replicates GPO objects but not their
SYSVOL folders, so every DC copies the folders it does not own from the DC that does, over SMB as its own machine
account.
    docker exec samba python3 /fabric/pull_sysvol.py
Run by the DC's entrypoint every 5 minutes. Prints one line per GPO copied or refused; exit 0 unless it could not
start (the DC's database or SYSVOL unreadable)."""
import fcntl
import os
import re
import shutil
import sys

import ldb
from samba.credentials import MUST_USE_KERBEROS, Credentials
from samba.netcmd.gpo import copy_directory_remote_to_local, smb_connection

from open_samdb import open_samdb
from set_gpo_acl import set_gpo_acl

CONF = "/data/etc/smb.conf"
LOCK = "/run/samba/pull_sysvol.lock"     # one pull at a time (the entrypoint's round, or one run by hand)
# a site's own GPOs, by their display names (converge, admin_gpo): the site is the second word
SITE_GPO = re.compile(r"^fabric: ([a-z0-9][a-z0-9-]*) (?:Windows baseline|admin settings|controls)$")


def _version(text):
    """Purpose: the version a GPT.INI states.
    Inputs:  text — str, the file's content.
    Returns: int, or -1 when it states none.
    Fails:   never.
    Feeds:   pull_sysvol."""
    m = re.search(r"^\s*Version\s*=\s*(\d+)", text, re.M | re.I)
    return int(m.group(1)) if m else -1


def _owner(name):
    """Purpose: the site a GPO belongs to, by fabric's display name for a site's GPOs ("fabric: <site> Windows
             baseline", "fabric: <site> admin settings", "fabric: <site> controls"); every other GPO is the root's
             (the domain's own, fabric's domain-wide ones, an admin's).
    Inputs:  name — the GPO's displayName.
    Returns: str site name, or None (the root's).
    Fails:   never.
    Feeds:   pull_sysvol."""
    m = SITE_GPO.match(name)
    return m.group(1) if m else None


def _writable_dcs(samdb):
    """Purpose: the domain's writable DCs, by AD site: the DCs that may hold a GPO's folders (a read-only DC's site
             has its GPOs written at a writable DC: manual 1.9.8.14).
    Inputs:  samdb — SamDB.
    Returns: list of (AD site name, dnsHostName, NTDS Settings DN), by AD site and DN.
    Fails:   ldb.LdbError from a search.
    Feeds:   pull_sysvol."""
    out = []
    for ntds in samdb.search(base=f"CN=Sites,{samdb.get_config_basedn()}", scope=ldb.SCOPE_SUBTREE,
                             expression="(objectClass=nTDSDSA)", attrs=["objectCategory"]):
        if "NTDS-DSA-RO" in str(ntds["objectCategory"][0]).upper():
            continue
        server = samdb.search(base=str(ntds.dn.parent()), scope=ldb.SCOPE_BASE, attrs=["dNSHostName"])[0]
        if "dNSHostName" in server:      # CN=NTDS Settings,CN=<dc>,CN=Servers,CN=<site>,CN=Sites,...
            out.append((str(ntds.dn).split(",")[3].split("=", 1)[1], str(server["dNSHostName"][0]), str(ntds.dn)))
    return sorted(out, key=lambda x: (x[0].lower(), x[2].lower()))


def _root_site(samdb):
    """Purpose: the root site: the site of the domain's first DC (dc-0001's record, 2.1.6.79), the lowest-numbered
             record when it is gone.
    Inputs:  samdb — SamDB.
    Returns: str, or None before any DC has a record.
    Fails:   ldb.LdbError from a search other than a missing CN=dcs.
    Feeds:   pull_sysvol."""
    try:
        found = samdb.search(base=f"CN=dcs,CN=fabric,CN=System,{samdb.domain_dn()}", scope=ldb.SCOPE_ONELEVEL,
                             expression="(objectClass=fabricDcInfo)", attrs=["cn", "fabricSite"])
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        return None
    found = sorted((m for m in found if m.get("fabricSite")), key=lambda m: str(m["cn"][0]).lower())
    return str(found[0]["fabricSite"][0]) if found else None


def pull_sysvol():
    """Purpose: bring this DC's copy of every GPO folder it does not own up to its object's version.
    Inputs:  none (the DC's database and smb.conf, its machine account's Kerberos credentials).
    Returns: list of str, one per GPO copied or refused.
    Fails:   ldb.LdbError / RuntimeError opening the database; a folder that cannot be copied is reported, never
             half written (a copy goes into a new folder that replaces the old one only once complete).
    Feeds:   this script's main."""
    samdb, lp = open_samdb(CONF)
    base, realm = str(samdb.domain_dn()), lp.get("realm").lower()
    me = str(samdb.get_dsServiceName()).lower()
    root = _root_site(samdb)
    dcs = _writable_dcs(samdb)
    policies = os.path.join(lp.get("path", "sysvol"), realm, "Policies")
    creds = None
    conns, out = {}, []
    for gpo in samdb.search(base=f"CN=Policies,CN=System,{base}", scope=ldb.SCOPE_ONELEVEL,
                            expression="(objectClass=groupPolicyContainer)",
                            attrs=["cn", "versionNumber", "displayName"]):
        guid = str(gpo["cn"][0]).upper()
        want = int(str(gpo.get("versionNumber", ["0"])[0]))
        folder = os.path.join(policies, guid)
        ini = os.path.join(folder, "GPT.INI")
        have = _version(open(ini, encoding="utf-8", errors="replace").read()) if os.path.exists(ini) else -1
        if have == want:
            continue
        owner = _owner(str(gpo.get("displayName", [""])[0])) or root
        # the owner site's writable DCs first, then the root's, then the others: the first whose files are the
        # object's version is copied from (a read-only DC's site has its GPOs written at its parent's DC)
        order = sorted(dcs, key=lambda d: (d[0].lower() != (owner or "").lower(),
                                           d[0].lower() != (root or "").lower()))
        if order and order[0][2].lower() == me:
            continue                    # this DC owns it: its own writes keep it current
        found, why = None, []
        for _, host, dn in order:
            if dn.lower() == me:
                continue
            try:
                if host not in conns:
                    if creds is None:
                        creds = Credentials()
                        creds.guess(lp)
                        creds.set_machine_account(lp)
                        creds.set_kerberos_state(MUST_USE_KERBEROS)
                    conns[host] = smb_connection(host, "sysvol", lp, creds)
                ini = conns[host].loadfile(f"{realm}\\Policies\\{guid}\\GPT.INI")
                theirs = _version(ini.decode("utf-8", "replace"))
            except Exception as e:      # one DC unreachable never stops the others
                why.append(f"{host}: {type(e).__name__}: {e}")
                continue
            if theirs == want:
                found = host
                break
            why.append(f"{host} has version {theirs}")
        if found is None:
            if why:
                out.append(f"{guid}: not copied: no writable DC holds version {want} ({'; '.join(why)})")
            continue
        host, conn, remote = found, conns[found], f"{realm}\\Policies\\{guid}"
        try:
            os.makedirs(policies, exist_ok=True)       # a joined DC may have no Policies folder yet
            tmp = os.path.join(policies, f".fabric-pull-{guid}")
            shutil.rmtree(tmp, ignore_errors=True)
            copy_directory_remote_to_local(conn, remote, tmp)
            if _version(open(os.path.join(tmp, "GPT.INI"), encoding="utf-8", errors="replace").read()) != want:
                shutil.rmtree(tmp, ignore_errors=True)
                out.append(f"{guid}: not copied from {host}: it changed during the copy (next round)")
                continue
            old = os.path.join(policies, f".fabric-old-{guid}")
            shutil.rmtree(old, ignore_errors=True)
            if os.path.exists(folder):
                os.rename(folder, old)
            os.rename(tmp, folder)
            shutil.rmtree(old, ignore_errors=True)
            set_gpo_acl(samdb, lp, guid)
            out.append(f"{guid}: version {want} copied from {host}")
        except Exception as e:          # one owner unreachable never stops the others
            out.append(f"{guid}: not copied from {host}: {type(e).__name__}: {e}")
    return out


if __name__ == "__main__":
    lock = open(LOCK, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for line in pull_sysvol():
            print(f"pull_sysvol: {line}", flush=True)
    except Exception as e:                  # reported in the DC's log; the DC keeps running
        print(f"pull_sysvol: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
