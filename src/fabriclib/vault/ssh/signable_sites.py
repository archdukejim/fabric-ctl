from fabriclib.federation.site_below import site_below
from fabriclib.samba.domain_sites import domain_sites


def signable_sites(v, sites, domain=None):
    """Purpose: which of a person's SSH sites this site's user CA may sign for (decision 2.1.7.14, revised
             2026-10-13; manual 1.6.11.9.14): this site itself and the sites below it (their OUs inside this site's
             OU, 1.9.8.14) — so central IT at the top signs for every site, a branch only for its own.
    Inputs:  v — settings: site_name; sites — the sites whose `<site>-ssh-users` the person is in; domain — the
             domain's sites ([{"site", "dn"}], default domain_sites(): read from this site's DC).
    Returns: (in_scope, elsewhere): two sorted lists of site names.
    Fails:   ValidationError from domain_sites (the DC does not answer).
    Feeds:   vault/ssh/sign_ssh_key, vault/ssh/ssh_overview."""
    me = v.get("site_name")
    wanted = sorted(set(sites))
    if not wanted or wanted == [me]:          # nothing to place in the tree: the domain is not asked
        return wanted, []
    domain = domain_sites() if domain is None else domain
    mine = [s for s in wanted if s == me or site_below(domain, me, s)[0]]
    return mine, [s for s in wanted if s not in mine]
