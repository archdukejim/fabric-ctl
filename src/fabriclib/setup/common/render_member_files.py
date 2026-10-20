from fabriclib.consent.plan_member import KRB5_CONF, SSSD_CONF
from fabriclib.setup.common.host_identity import host_identity
from fabriclib.setup.common.renew_days import renew_days

HEAD = "# fabric: written by fabricctl setup (manual 1.6.11.8); `fabricctl setup --undo member` restores the original\n"


def render_member_files(v):
    """Purpose: the Kerberos and SSSD files that make the fabric host a member of its own domain (manual 1.6.11.8),
             written as the Linux join writes them (1.6.7.3) but against this host's own DC, with the host's own
             account (2.1.6.48). A host that runs a DC is the top tier, so nobody from the domain signs in to it and
             no domain sudo rule reaches it (2.1.6.75, 2.1.6.78; manual 1.6.11.11): sssd's access provider denies
             every domain account and there is no sudo provider; the domain's names still resolve. No dynamic DNS
             (the DC keeps its own records); the machine password renewed after host_machine_password_renew_days,
             or never (0, the default, 1.6.11.12).
    Inputs:  v — vars: ad_domain, ad_realm, hostname_dc, host_machine_password_renew_days, and what host_identity
             reads (hostname, dc_name, ad_dc_type). All of them follow strict rules (domain labels), so they go in
             as they are (manual 1.1.5.7).
    Returns: {KRB5_CONF: str, SSSD_CONF: str}, each starting with fabric's marker line (HEAD).
    Fails:   KeyError when ad_domain, ad_realm or hostname_dc is missing.
    Feeds:   setup/join_host_domain."""
    domain, realm, dc = v["ad_domain"], v["ad_realm"], v["hostname_dc"]
    ident = host_identity(v)
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
            # the top tier's host: no domain account signs in, no domain sudo rule (2.1.6.75, 2.1.6.78)
            + "access_provider = deny\n"
            "sudo_provider = none\n"
            f"ad_domain = {domain}\n"
            f"krb5_realm = {realm}\n"
            f"ad_server = {dc}\n"
            f"ad_hostname = {ident['fqdn']}\n"
            # 0: never renewed; renewal needs adcli (1.6.11.12)
            f"ad_maximum_machine_account_password_age = {renew_days(v)}\n"
            "dyndns_update = false\n"
            "ldap_id_mapping = false\n"
            "use_fully_qualified_names = false\n"
            "fallback_homedir = /home/%u\n"
            "default_shell = /bin/bash\n"
            "cache_credentials = true\n"
            "enumerate = false\n")
    return {KRB5_CONF: krb5, SSSD_CONF: sssd}
