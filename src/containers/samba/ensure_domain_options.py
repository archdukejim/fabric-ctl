import ldb

import paths

MARK = "fabric: the domain's DHCP options, every site's Kea rendered with them first (manual 1.10.4.32)"


def ensure_domain_options(samdb):
    """Purpose: the domain's DHCP option set, `CN=dhcp-options,CN=fabric,CN=System` (decision 2.1.10.34, manual
             1.10.4.32; what was the organisation's, 2.1.10.23), made when missing and empty. Only fabric-agent writes
             what it holds, after the grants' check (1.10.4.34); no group or access entry of its own.
    Inputs:  samdb — SamDB (as the system).
    Returns: list of str, what was created (empty when it was there).
    Fails:   ldb.LdbError other than "already exists".
    Feeds:   converge (the root site only)."""
    try:
        samdb.add({"dn": paths.domain_options_dn(samdb), "objectClass": "fabricOptionSet", "description": MARK})
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
        return []
    return ["the domain's DHCP options entry created"]
