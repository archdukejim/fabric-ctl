import ldb

import paths


def plan_cidrs(samdb, site):
    """Purpose: the networks of the site's subnets in the address manager's plan (manual 1.10.4.13), served by DHCP or
             not: with the site's other networks they are its AD site's subnets (1.9.8.5), so convergence run from
             settings that do not carry the plan (setup's) never drops them.
    Inputs:  samdb — SamDB; site — str.
    Returns: list of CIDR str, sorted.
    Fails:   ldb.LdbError from the search (OU=networks missing: ensure_layout makes it first).
    Feeds:   converge (ensure_ad_site)."""
    found = samdb.search(base=f"OU=networks,{paths.site_dn(samdb, site)}", scope=ldb.SCOPE_ONELEVEL,
                         expression="(objectClass=fabricSubnet)", attrs=["fabricCidr"])
    return sorted({str(m["fabricCidr"][0]) for m in found if "fabricCidr" in m})
