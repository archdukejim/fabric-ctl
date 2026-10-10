import ldb

import paths
from acl_entries import sid_of
from ensure_gpo import ensure_gpo
from legacy_logon_groups import legacy_logon_groups
from logon_rights_policy import BUILTIN_ADMINISTRATORS, EXTENSIONS, logon_rights_policy
from remove_gpo import remove_gpo
from site_roles import role_group

INF = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
ALWAYS = "fabric-break-glass"        # with each machine's local Administrators: never locked out (2.1.7.6)


def _name(site, ou):
    """Purpose: the display name of a site's log-on GPO for one OU.
    Inputs:  site — str; ou — the OU's path below the site's OU ("" for the site's OU itself).
    Returns: str "fabric: <site> log-on <ou path or 'site'>".
    Fails:   never.
    Feeds:   ensure_logon_policies."""
    return f"fabric: {site} log-on {ou or 'site'}"


def _ou_dn(site_dn, ou):
    """Purpose: the DN of an OU given by its path below the site's OU.
    Inputs:  site_dn — str; ou — "a/b" (checked on the host: safe segments only) or "".
    Returns: str, e.g. "OU=linux,OU=machines,<site_dn>".
    Fails:   never.
    Feeds:   ensure_logon_policies."""
    return ",".join([f"OU={seg}" for seg in reversed(ou.split("/")) if seg] + [site_dn])


def _sids(samdb, names, report, where):
    """Purpose: the SIDs of the groups named, always ending with fabric-break-glass and BUILTIN\\Administrators; a
             group that does not exist (removed since it was granted) is left out and reported, never fatal.
    Inputs:  samdb — SamDB; names — list of str; report — list the reports are added to; where — the OU's label.
    Returns: list of SID str, without repeats, in the order given.
    Fails:   ldb.LdbError from a search.
    Feeds:   ensure_logon_policies."""
    out = []
    for name in list(names) + [ALWAYS]:
        try:
            sid = sid_of(samdb, name)
        except IndexError:
            msg = f"log-on {where}: no group {name} in the domain, left out"
            if msg not in report:                 # once, though both rights name it
                report.append(msg)
            continue
        if sid not in out:
            out.append(sid)
    return out + [BUILTIN_ADMINISTRATORS]


def ensure_logon_policies(samdb, lp, site, policies, admin_group):
    """Purpose: who may sign in to the site's machines (manual 1.6.11.4, 2.1.6.42): with `policies` null, the site's
             one log-on GPO as before 0.9, on its OU, from legacy_logon_groups (an upgrade changes nothing, 2.1.6.44);
             otherwise one GPO per OU named in `policies`, linked to that OU, granting log-on at the keyboard to its
             console groups and remotely to its remote groups, each with fabric-break-glass and the machine's local
             Administrators. Either way the site's other fabric log-on GPOs (the legacy one, or an OU's no longer
             named) are removed. Every GPO also makes the windows-admins of the site and the sites above local
             Administrators. An OU that does not exist is reported and skipped, as is a granted group that no longer
             exists.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; site — str; policies — None or {ou path: {"console":
             [group], "remote": [group]}} (checked on the host: check_logon_policies); admin_group — the web
             console's admin group (in the legacy list).
    Returns: list of str, what changed and what was skipped.
    Fails:   ldb.LdbError, OSError from ensure_gpo or remove_gpo; IndexError when a windows-admins role is missing.
    Feeds:   converge."""
    owners = [site] + paths.ancestors(samdb, site)
    local_admins = [sid_of(samdb, role_group(o, "windows-admins")) for o in owners]
    site_dn = paths.site_dn(samdb, site)
    done, wanted = [], set()
    if policies is None:
        sids = [sid_of(samdb, g) for g in legacy_logon_groups(samdb, site, admin_group)] + [BUILTIN_ADMINISTRATORS]
        wanted.add(f"fabric: {site} log-on rights")
        done += ensure_gpo(samdb, lp, f"fabric: {site} log-on rights", site_dn, EXTENSIONS,
                           {INF: logon_rights_policy(sids, local_admins)})
    for ou, entry in sorted((policies or {}).items()):
        name, where = _name(site, ou), ou or "site"
        wanted.add(name)
        dn = _ou_dn(site_dn, ou)
        try:
            samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dn"])
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
            done.append(f"log-on {where}: no OU {dn}, skipped")
            continue
        console = _sids(samdb, entry.get("console") or [], done, where)
        remote = _sids(samdb, entry.get("remote") or [], done, where)
        done += ensure_gpo(samdb, lp, name, dn, EXTENSIONS, {INF: logon_rights_policy(console, local_admins, remote)})
    prefix = f"fabric: {site} log-on "
    for gpo in samdb.search(base=f"CN=Policies,CN=System,{samdb.domain_dn()}", scope=ldb.SCOPE_ONELEVEL,
                            expression=f"(&(objectClass=groupPolicyContainer)"
                                       f"(displayName={ldb.binary_encode(prefix.rstrip())}*))", attrs=["displayName"]):
        name = str(gpo["displayName"][0])
        if name.startswith(prefix) and name not in wanted:
            done += remove_gpo(samdb, lp, name)
    return done
