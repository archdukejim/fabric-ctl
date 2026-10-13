import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.samba.writable_server import writable_server
from fabriclib.secrets.load_secrets import load_secrets

CONF = "/data/etc/smb.conf"
DENIED = "denied rodc password replication group"
# never weakened (2.1.6.55): the read-only DC's denied list holds these, and the denied group these privileged groups
NEVER_REVEAL = (DENIED, "administrators", "server operators", "backup operators", "account operators")
DENIED_MEMBERS = ("domain admins", "enterprise admins", "schema admins", "krbtgt")


def _local(container, base, attr, scope="base"):
    """Purpose: one attribute's values from the read-only DC's own copy of the domain (as root in its container: no
             credentials, no network), long LDIF lines unfolded.
    Inputs:  container — the DC's container; base — the entry's DN; attr — the attribute; scope — ldbsearch's.
    Returns: list of str (the values, as written).
    Fails:   ValidationError when the DC's database cannot be read (the DC is not running).
    Feeds:   _check_lists."""
    res = subprocess.run(["docker", "exec", container, "ldbsearch", "-H", "/data/private/sam.ldb", "-b", base, "-s",
                          scope, attr], capture_output=True, text=True, timeout=120)
    if res.returncode != 0:
        raise ValidationError(f"this site's read-only domain controller could not be read: "
                              f"{(res.stderr or res.stdout).strip()[-300:]}")
    text = res.stdout.replace("\n ", "")
    return [x.split(": ", 1)[1] for x in text.splitlines() if x.lower().startswith(f"{attr.lower()}: ")]


def _check_lists(v, container):
    """Purpose: refuse to cache anyone unless the read-only DC's password replication lists are as fabric needs them:
             the site's cache group on its allow list (written at the join, 2.1.6.52), and its denied list whole —
             the Denied RODC Password Replication Group (with Domain Admins, Enterprise Admins, Schema Admins and
             krbtgt in it) and the built-in privileged groups — so a privileged account is never cached, whatever the
             site's groups hold (2.1.6.55).
    Inputs:  v — fabric vars (dc_name, site_name, ad_domain, ad_base_dn, ad_site_ou); container — the DC's container.
    Returns: None.
    Fails:   ValidationError naming what is missing, before anything is changed.
    Feeds:   sync_rodc_cache."""
    base = v.get("ad_base_dn") or ",".join(f"DC={x}" for x in str(v["ad_domain"]).split("."))
    site = str(v.get("site_name") or "").lower()
    rodc = f"CN={str(v['dc_name']).split('.')[0].upper()},OU=Domain Controllers,{base}"
    allowed = [x.lower() for x in _local(container, rodc, "msDS-RevealOnDemandGroup")]
    if not any(x.startswith(f"cn={site}-rodc-cache,") for x in allowed):
        raise ValidationError(f"{site}-rodc-cache is not on this site's read-only DC's password replication allow "
                              "list (a site joined before 0.7.1): run setup with the join account to write it "
                              "(manual 1.6.11.13); nothing was cached")
    denied = [x.lower() for x in _local(container, rodc, "msDS-NeverRevealGroup")]
    missing = [g for g in NEVER_REVEAL if not any(x.startswith(f"cn={g},") for x in denied)]
    members = [x.lower() for x in _local(container, f"CN=Denied RODC Password Replication Group,CN=Users,{base}",
                                         "member")]
    missing += [f"{g} (in {DENIED})" for g in DENIED_MEMBERS if not any(x.startswith(f"cn={g},") for x in members)]
    if missing:
        raise ValidationError("this site's read-only DC's denied list is weaker than fabric allows (missing: "
                              + ", ".join(missing) + "): put them back at the writable DC; nothing was cached "
                              "(decision 2.1.6.55)")


def _preload(dns, server, container):
    """Purpose: have the read-only DC cache these accounts now, from the writable DC (as the DC's own machine
             account: samba-tool's fallback), the list on stdin; an account the writable DC refuses (one on the
             denied list) is skipped and reported, never retried as another.
    Inputs:  dns — list of account DNs; server — the writable DC's address; container — the DC's container.
    Returns: list of str, the DNs refused.
    Fails:   ValidationError when the preload itself fails (the writable DC not answering).
    Feeds:   sync_rodc_cache."""
    res = subprocess.run(["docker", "exec", "-i", container, "samba-tool", "rodc", "preload", "--file=-",
                          "--ignore-errors", f"--server={server}", "-s", CONF], input="\n".join(dns) + "\n",
                         capture_output=True, text=True, timeout=600)
    if res.returncode != 0:
        raise ValidationError(f"this site's read-only DC could not cache its accounts from {server}: "
                              f"{(res.stderr or res.stdout).strip()[-300:]}")
    out = res.stdout + res.stderr
    return [line.split("Error replicating DN ", 1)[1].strip() for line in out.splitlines()
            if "Error replicating DN " in line]


def sync_rodc_cache(v, secrets=None, container="samba"):
    """Purpose: at a site whose DC is read-only, cache the site's people and machines there so they sign in while the
             link to the writable DC is down (decision 2.1.6.55, manual 1.6.11.14): the read-only DC's lists checked
             (the cache group allowed, the denied list whole), the site's `<site>-rodc-cache` group kept at the
             writable DC as the site's agent (its people groups nested, its machines members, nothing else), then the
             site's own accounts preloaded. Idempotent: a second run changes no membership (the preload only
             refreshes). A person or machine removed from the site leaves the group's reach and is cached no more.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server, dc_name, ad_domain, ad_base_dn); secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: list of str, what was done ([] where the site's DC is not read-only).
    Fails:   ValidationError: no writable DC known, the lists not as needed, the writable DC refusing or not
             answering (run_op's messages), the preload failing; and, after the rest is done, accounts of another
             site or of the organisation reached through the site's groups (named, with the group to remove them
             from: never preloaded).
    Feeds:   setup/start_services (after the join), deploy/restart_changed (every apply), samba/run_domain_command
             (`fabricctl domain rodc-cache`, the fabric-rodc-cache timer)."""
    if v.get("ad_dc_type") != "rodc":
        return []
    server = writable_server(v, "keep the read-only DC's cached accounts at")
    _check_lists(v, container)
    site = v["site_name"]
    done = run_op(v, secrets if secrets is not None else load_secrets(), "sync_rodc_cache", {}, container, server)
    lines = [f"{site}-rodc-cache: {dn.split(',', 1)[0][3:]} added" for dn in done["added"]]
    lines += [f"{site}-rodc-cache: {dn.split(',', 1)[0][3:]} taken out (no longer the site's)"
              for dn in done["removed"]]
    refused = _preload(done["accounts"], server, container) if done["accounts"] else []
    lines.append(f"read-only DC: {len(done['accounts']) - len(refused)} of the site's accounts cached")
    lines += [f"read-only DC: not cached (refused by its denied list): {dn}" for dn in refused]
    if done["foreign"]:
        raise ValidationError("; ".join(lines) + ". Reached through the site's groups but not the site's own, so "
                              "never preloaded; remove them from that group: "
                              + ", ".join(f"{dn} (through {g.split(',', 1)[0][3:]})" for dn, g in done["foreign"]))
    return lines
