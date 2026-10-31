import ldb

import paths

MARK = "fabric: this site's record: its number and its DHCP options (manual 1.10.4.32)"


def ensure_site_record(samdb, site):
    """Purpose: the site's record, `CN=<site>,CN=sites,CN=fabric,CN=System` (decision 2.1.10.34, manual 1.10.4.32),
             made when missing, beside the site's group: where its number and its DHCP options are kept. What it
             holds is never changed here (the plan's writes are fabric-agent's), and it is never removed here.
    Inputs:  samdb — SamDB (as the system); site — the site's name.
    Returns: list of str, what was created (empty when it was there).
    Fails:   ldb.LdbError other than "already exists" (CN=sites missing: ensure_layout makes it first).
    Feeds:   converge."""
    dn = paths.site_record_dn(samdb, site)
    try:
        samdb.add({"dn": dn, "objectClass": "fabricSiteRecord", "description": MARK})
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
        return []
    return [f"site record {site} created"]
