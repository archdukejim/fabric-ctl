from fabriclib.consent.plan_member import KRB5_CONF, SSSD_CONF
from fabriclib.setup.common.host_identity import host_identity

HEAD = "# fabric: written by fabricctl setup (manual 1.6.11.8); `fabricctl setup --undo member` restores the original\n"


def _sudo_search_base(site_dn, org_dn):
    """Purpose: sssd's sudo search bases, as the Linux join builds them: the site's OU=sudoers, each site's above it
             (their roles reach the sites below, 2.1.9.13), then the organisation's.
    Inputs:  site_dn — the site's OU (full DN); org_dn — the organisation's OU (full DN).
    Returns: str for ldap_sudo_search_base.
    Fails:   never.
    Feeds:   render_member_files."""
    bases, dn = [], site_dn
    while dn.upper().startswith("OU=") and not dn.upper().startswith("OU=SITES,") and "," in dn:
        bases.append(f"OU=sudoers,{dn}?onelevel??")
        dn = dn.split(",", 1)[1]
    return "".join(bases) + f"OU=sudoers,{org_dn}?onelevel?"


def _access(ident, domain, site, site_dn, org_dn):
    """Purpose: sssd's access lines. With the host's own account (2.1.6.48): AD's access provider, so the log-on
             policy of the host's OU applies as on every joined machine (GPO access control enforcing), and on top
             of it the fabric admins only (an access filter: members, nested too, of `<site>-fabric-admins` or
             `fabric-admins`). With the DC's account (2.1.6.34; no OU's policy reaches a DC's account): the fabric
             admins only, by sssd's simple access provider.
    Inputs:  ident — host_identity's answer; domain — the AD domain; site — the site's name; site_dn, org_dn — the
             site's and the organisation's OU (full DNs).
    Returns: str, the access lines of the [domain/…] section.
    Fails:   never.
    Feeds:   render_member_files."""
    if not ident["own"]:
        return f"access_provider = simple\nsimple_allow_groups = fabric-admins, {site}-fabric-admins\n"
    chain = "memberOf:1.2.840.113556.1.4.1941:="           # AD's matching rule for nested membership
    # DOM:<domain>: is required: without it sssd takes the matching rule's colons for a prefix of its own and denies
    # everyone (found by the sandbox suite)
    return ("access_provider = ad\n"
            "ad_gpo_access_control = enforcing\n"
            f"ad_access_filter = DOM:{domain}:(|({chain}CN={site}-fabric-admins,OU=groups,{site_dn})"
            f"({chain}CN=fabric-admins,OU=groups,{org_dn}))\n")


def render_member_files(v):
    """Purpose: the Kerberos and SSSD files that make the fabric host a member of its own domain (manual 1.6.11.8),
             written as the Linux join writes them (1.6.7.3) but against this host's own DC: with the host's own
             account (2.1.6.48), the log-on policy of its OU and the fabric admins only (_access); sudo from the
             site's rules; no dynamic DNS (the DC keeps its own records).
    Inputs:  v — vars: ad_domain, ad_realm, ad_base_dn, ad_site_ou, ad_org_ou, hostname_dc, site_name (or
             hostname), and what host_identity reads (hostname, dc_name, ad_dc_type). All of them follow strict
             rules (domain labels, a site name), so they go in as they are (manual 1.1.5.7).
    Returns: {KRB5_CONF: str, SSSD_CONF: str}, each starting with fabric's marker line (HEAD).
    Fails:   KeyError when ad_domain, ad_realm or hostname_dc is missing.
    Feeds:   setup/join_host_domain."""
    domain, realm, dc = v["ad_domain"], v["ad_realm"], v["hostname_dc"]
    ident = host_identity(v)
    base = v.get("ad_base_dn") or ",".join(f"DC={x}" for x in domain.split("."))
    site = (v.get("site_name") or v.get("hostname") or "").lower()
    site_ou = v.get("ad_site_ou") or f"OU={site},OU=sites"
    org_ou = v.get("ad_org_ou") or f"OU=organisation,{site_ou}"
    krb5 = (HEAD
            + "[libdefaults]\n"
            f"    default_realm = {realm}\n"
            "    dns_lookup_realm = false\n"
            "    dns_lookup_kdc = false\n"
            "    rdns = false\n"
            "\n[realms]\n"
            f"    {realm} = {{\n"
            f"        kdc = {dc}\n"
            f"        admin_server = {dc}\n"
            "    }\n"
            "\n[domain_realm]\n"
            f"    .{domain} = {realm}\n"
            f"    {domain} = {realm}\n")
    sssd = (HEAD
            + "[sssd]\n"
            f"domains = {domain}\n"
            "services = nss, pam, sudo\n"
            f"\n[domain/{domain}]\n"
            "id_provider = ad\n"
            + _access(ident, domain, site, f"{site_ou},{base}", f"{org_ou},{base}")
            + "sudo_provider = ad\n"
            f"ad_domain = {domain}\n"
            f"krb5_realm = {realm}\n"
            f"ad_server = {dc}\n"
            f"ad_hostname = {ident['fqdn']}\n"
            "dyndns_update = false\n"
            "ldap_id_mapping = false\n"
            "use_fully_qualified_names = false\n"
            "fallback_homedir = /home/%u\n"
            "default_shell = /bin/bash\n"
            "cache_credentials = true\n"
            "enumerate = false\n"
            f"ldap_sudo_search_base = {_sudo_search_base(f'{site_ou},{base}', f'{org_ou},{base}')}\n")
    return {KRB5_CONF: krb5, SSSD_CONF: sssd}
