import ldb

import paths
from acl_entries import sid_of
from ensure_gpo import ensure_gpo
from legacy_logon_groups import legacy_logon_groups
from logon_rights_policy import BUILTIN_ADMINISTRATORS, EXTENSIONS, logon_rights_policy
from remove_gpo import remove_gpo
from plan_logon_entries import plan_logon_entries
from site_roles import CLASSES, remote_users, role_group

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
    Returns: str, e.g. "OU=linux,OU=servers,OU=machines,<site_dn>".
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


def _rdp_users(samdb, site, ou, report):
    """Purpose: the class remote users group an OU's policy also makes each machine's Remote Desktop Users (2.1.7.14
             as revised 2026-10-13): for a class OU and the OUs below it, so its members reach the class's Windows
             machines by RDP, which needs that membership beside the remote right.
    Inputs:  samdb — SamDB; site — str; ou — the OU's path; report — list a missing group is reported to.
    Returns: [SID str] (one, or none: not a class OU, or the group not made yet).
    Fails:   ldb.LdbError from a search.
    Feeds:   ensure_logon_policies."""
    for cls, path in CLASSES.items():
        if ou == f"machines/{path}" or ou.startswith(f"machines/{path}/"):
            try:
                return [sid_of(samdb, remote_users(site, cls))]
            except IndexError:
                report.append(f"log-on {ou}: no group {remote_users(site, cls)} in the domain yet, left out")
    return []


def ensure_logon_policies(samdb, lp, site, policies, admin_group):
    """Purpose: who may sign in to the site's machines (manual 1.6.11.4, 2.1.6.42): with `policies` null, the site's
             one log-on GPO as before 0.9, on its OU, from legacy_logon_groups (an upgrade changes nothing, 2.1.6.44);
             otherwise one GPO per OU named in `policies`, linked to that OU, granting log-on at the keyboard to its
             console groups and remotely to its remote groups, each with fabric-break-glass and the machine's local
             Administrators. Either way the site's OU=fabric-hosts carries a policy (the setting's, or by default the
             fabric admins, 2.1.6.53), and each class OU (`machines/servers`, `machines/desktops`) one that grants
             remote sign-in to its `<site>-<class>-remote-users` on top of what it inherits (plan_logon_entries,
             2.1.7.14 as revised 2026-10-13), and puts that group in each such machine's Remote Desktop Users (RDP
             needs both). The site's other fabric log-on GPOs (the legacy one, or an OU's
             no longer named) are removed. Every GPO also makes the windows-admins of the site and the sites above local
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
    legacy = legacy_logon_groups(samdb, site, admin_group) if policies is None else []
    if policies is None:
        sids = [sid_of(samdb, g) for g in legacy] + [BUILTIN_ADMINISTRATORS]
        wanted.add(f"fabric: {site} log-on rights")
        done += ensure_gpo(samdb, lp, f"fabric: {site} log-on rights", site_dn, EXTENSIONS,
                           {INF: logon_rights_policy(sids, local_admins, sids)})
    for ou, entry in sorted(plan_logon_entries(site, policies, legacy).items()):
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
        console = None if entry["console"] is None else _sids(samdb, entry["console"], done, where)
        remote = _sids(samdb, entry["remote"], done, where)
        rdp = _rdp_users(samdb, site, ou, done)
        done += ensure_gpo(samdb, lp, name, dn, EXTENSIONS,
                           {INF: logon_rights_policy(console, local_admins, remote, rdp)})
    prefix = f"fabric: {site} log-on "
    for gpo in samdb.search(base=f"CN=Policies,CN=System,{samdb.domain_dn()}", scope=ldb.SCOPE_ONELEVEL,
                            expression=f"(&(objectClass=groupPolicyContainer)"
                                       f"(displayName={ldb.binary_encode(prefix.rstrip())}*))", attrs=["displayName"]):
        name = str(gpo["displayName"][0])
        if name.startswith(prefix) and name not in wanted:
            done += remove_gpo(samdb, lp, name)
    return done
