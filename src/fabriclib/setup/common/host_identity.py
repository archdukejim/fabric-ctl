def _account_name(hostname):
    """Purpose: the computer account name a host takes in AD, as adcli and Windows make it: the host name's first
             label, cut to 15 characters (NetBIOS), without a dash left at the end, in upper case.
    Inputs:  hostname — the host's name (one DNS label; any case).
    Returns: str, e.g. "FAB1"; "" for no name.
    Fails:   never.
    Feeds:   host_identity."""
    return str(hostname or "").split(".")[0][:15].rstrip("-").upper()


def host_identity(v):
    """Purpose: which domain account the fabric host signs in with (manual 1.6.11.8, decision 2.1.6.48): its own
             computer account `<HOSTNAME>$`, a member like any other machine (in the site's OU=fabric-hosts,
             2.1.6.49), so the site's group policy reaches it. The DC's own account only where the host cannot have
             its own: a site whose DC is read-only (it cannot create the account nor hold its keys; an open point,
             2.3.6.7). A DC that has the host's name (the two names one account) is refused, not worked around
             (2.1.6.51): `refused` says why, for the member step to stop on.
    Inputs:  v — vars: hostname, dc_name, hostname_dc, ad_domain, ad_dc_type.
    Returns: {"own": bool, "account": "FAB1" (the sAMAccountName without its $), "fqdn": the name sssd and Kerberos
             use for this host ("fab1.ad.test", or hostname_dc for the DC's), "principals": the keytab's principals
             (the account and its host/ names only), "why": "" or why the host keeps the DC's account, "refused": ""
             or why the host cannot be a member under its name}.
    Fails:   never.
    Feeds:   consent/plan_member, setup/join_host_domain, setup/common/render_member_files."""
    dc = str(v.get("dc_name") or "").split(".")[0].upper()
    own = _account_name(v.get("hostname"))
    if v.get("ad_dc_type") == "rodc":
        return {"own": False, "account": dc, "fqdn": v.get("hostname_dc"), "refused": "",
                "why": "this site's domain controller is read-only: it cannot create the host's own account nor hold "
                       "its keys",
                "principals": [f"{dc}$", f"host/{v.get('hostname_dc')}", f"host/{dc}"]}
    refused = ""
    if not own:
        refused = "this host has no name"
    elif own == dc:
        refused = (f"the domain controller has this host's name ({dc}): the host's own computer account would be the "
                   "domain controller's")
    fqdn = f"{own.lower()}.{v.get('ad_domain')}"
    return {"own": True, "account": own, "fqdn": fqdn, "why": "", "refused": refused,
            "principals": [f"{own}$", f"host/{fqdn}", f"host/{own}"]}
