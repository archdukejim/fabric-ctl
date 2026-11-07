from grant_members import find_group
from group_names import DC_HOSTS
from set_gpo_filter import set_gpo_filter

DOMAIN_CONTROLLERS, READ_ONLY_DCS = 516, 521     # the RIDs of AD's groups of the writable and read-only DCs


def member_gpo_filter(samdb, lp, name):
    """Purpose: a GPO linked at the domain's root that every member takes, and the domain controllers and the fabric
             hosts do not: they are denied Apply Group Policy (2.1.6.98's pattern; the fallback, the site's Windows
             baseline and its admin GPOs, 2.1.6.106).
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; name — the GPO's display name.
    Returns: list of str, what changed.
    Fails:   ValueError "no GPO <name>"; ldb.LdbError; NTSTATUSError from set_gpo_acl.
    Feeds:   compile_grants, converge, admin_gpo."""
    domain_sid = str(samdb.get_domain_sid())
    hosts = find_group(samdb, DC_HOSTS)          # ensure_groups makes it before any of these
    denied = [f"{domain_sid}-{DOMAIN_CONTROLLERS}", f"{domain_sid}-{READ_ONLY_DCS}"] + ([hosts[1]] if hosts else [])
    return set_gpo_filter(samdb, lp, name, None, deny_sids=denied)
