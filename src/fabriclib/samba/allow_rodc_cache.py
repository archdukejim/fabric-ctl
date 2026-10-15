import subprocess

from fabriclib.common.errors import ValidationError

AUTH = "/run/secrets/join.auth"     # the join account's credentials, mounted in the DC's container (never argv)


def allow_rodc_cache(v, container="samba"):
    """Purpose: put the site's `<site>-rodc-cache` group on this site's read-only DC's password replication allow
             list (msDS-RevealOnDemandGroup on its computer account, decision 2.1.6.52, manual 1.6.11.13), so the
             accounts fabric puts in that group (the fabric host's own) are cached there and sign in with the link
             down. Written at the writable DC the site joined through, with the join account (a Domain Admin for the
             hour of the join: only it may change a DC's account), right after the join and before that account is
             deleted (samba/finish_join).
    Inputs:  v — this site's vars: ad_dc_type ("rodc", else nothing to do), ad_join_server (the writable DC's
             address), dc_name, site_name, ad_domain, ad_base_dn, ad_site_ou; container — this site's DC.
    Returns: str, what was done ("" when nothing: not a read-only DC, or the group already allowed).
    Fails:   ValidationError when the writable DC does not answer or refuses.
    Feeds:   setup/start_services (before finish_join)."""
    if v.get("ad_dc_type") != "rodc":
        return ""
    base = v.get("ad_base_dn") or ",".join(f"DC={x}" for x in str(v["ad_domain"]).split("."))
    site = str(v.get("site_name") or "").lower()
    site_ou = v.get("ad_site_ou") or f"OU={site},OU=sites"
    group = f"CN={site}-rodc-cache,OU=groups,{site_ou},{base}"
    rodc = f"CN={str(v['dc_name']).split('.')[0].upper()},OU=Domain Controllers,{base}"
    ldap = ["-H", f"ldap://{v['ad_join_server']}", "-A", AUTH, "--use-kerberos=off"]
    res = subprocess.run(["docker", "exec", container, "ldbsearch", *ldap, "-b", rodc, "-s", "base",
                          "msDS-RevealOnDemandGroup"], capture_output=True, text=True, timeout=120)
    if res.returncode != 0:
        raise ValidationError("the read-only DC's allow list could not be read at the writable DC "
                              f"{v['ad_join_server']}: {(res.stderr or res.stdout).strip()[-300:]}")
    if group.lower() in res.stdout.replace("\n ", "").lower():     # LDIF folds long values
        return ""
    ldif = (f"dn: {rodc}\nchangetype: modify\nadd: msDS-RevealOnDemandGroup\n"
            f"msDS-RevealOnDemandGroup: {group}\n")
    res = subprocess.run(["docker", "exec", "-i", container, "ldbmodify", *ldap], input=ldif, capture_output=True,
                         text=True, timeout=120)
    if res.returncode != 0:
        raise ValidationError(f"the read-only DC's allow list could not be changed at {v['ad_join_server']}: "
                              f"{(res.stderr or res.stdout).strip()[-300:]}")
    return f"{site}-rodc-cache on the read-only DC's password replication allow list"
