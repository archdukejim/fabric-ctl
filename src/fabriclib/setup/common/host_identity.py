from fabriclib.common.errors import ValidationError
from fabriclib.samba.writable_server import writable_server


def _account_name(hostname):
    """Purpose: the computer account name a host takes in AD, as adcli and Windows make it: the host name's first
             label, cut to 15 characters (NetBIOS), without a dash left at the end, in upper case.
    Inputs:  hostname — the host's name (one DNS label; any case).
    Returns: str, e.g. "FAB1"; "" for no name.
    Fails:   never.
    Feeds:   host_identity."""
    return str(hostname or "").split(".")[0][:15].rstrip("-").upper()


def host_identity(v):
    """Purpose: the domain account the fabric host signs in with (manual 1.6.11.8, decisions 2.1.6.48, 2.1.6.52): its
             own computer account `<HOSTNAME>$`, a member like any other machine (in OU=fabric-hosts,
             2.1.6.49, 1.6.13.10.9), so a GPO linked there reaches it. At a site whose DC is read-only the account is
             written at the writable DC it replicates from (samba/writable_server), and cached by the read-only one
             (2.1.6.52). A DC that has the host's name (the two names one account) is refused, not worked around
             (2.1.6.51), as is a read-only DC's site with no writable DC known: `refused` says why, for the member
             step to stop on.
    Inputs:  v — vars: hostname, dc_name, ad_domain, ad_dc_type, ad_join_server (a read-only DC's writable partner).
    Returns: {"account": "FAB1" (the sAMAccountName without its $), "fqdn": the name sssd and Kerberos use for this
             host ("fab1.ad.test"), "principals": the keytab's principals (the account and its host/ names only),
             "write_server": None, or the writable DC's address where this site's DC is read-only, "refused": "" or
             why the host cannot be a member under its name}.
    Fails:   never.
    Feeds:   consent/plan_member, setup/join_host_domain, setup/common/render_member_files, undo/remove_host_account."""
    dc = str(v.get("dc_name") or "").split(".")[0].upper()
    own = _account_name(v.get("hostname"))
    try:
        write_server, no_writer = writable_server(v, "make the host's account at"), ""
    except ValidationError as e:
        write_server, no_writer = None, str(e)
    refused = ""
    if not own:
        refused = "this host has no name"
    elif own == dc:
        refused = ("the domain controller has this host's name: the host's own computer account would be the "
                   "domain controller's")
    elif no_writer:
        refused = no_writer
    fqdn = f"{own.lower()}.{v.get('ad_domain')}"
    return {"account": own, "fqdn": fqdn, "refused": refused, "write_server": write_server,
            "principals": [f"{own}$", f"host/{fqdn}", f"host/{own}"]}
