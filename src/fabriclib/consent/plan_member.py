from fabriclib.setup.common.host_identity import host_identity
from fabriclib.setup.common.missing_packages import missing_packages

# What the host needs to sign in with its domain (manual 1.6.11.8): sssd's AD provider, NSS and PAM for sss, sudo's
# sss support, the Kerberos tools; SASL's GSSAPI module (without it sssd cannot bind to the DC: "No worthy mechs
# found", found by the sandbox suite) and sssctl, as the Linux join installs them
MEMBER_PACKAGES = ["sssd-ad", "sssd-tools", "libnss-sss", "libpam-sss", "libsss-sudo", "krb5-user",
                   "libsasl2-modules-gssapi-mit"]
KRB5_CONF = "/etc/krb5.conf"
SSSD_CONF = "/etc/sssd/sssd.conf"
KEYTAB = "/etc/krb5.keytab"
NSSWITCH = "/etc/nsswitch.conf"
HOSTS = "/etc/hosts"
# the host files the step keeps before its first change and the undo puts back (common/keep_original)
KEPT_FILES = (KRB5_CONF, SSSD_CONF, KEYTAB, NSSWITCH, HOSTS)
# what was on before fabric (PAM profiles, sssd enabled, sudo's alternative) and the host's own computer account
# fabric made ("account"): <config>/member.json, for the undo
RECORD = "member.json"


def plan_member(v):
    """Purpose: what making this host a member of its own domain changes (manual 1.2.9.3 `member`, 1.6.11.8): the
             packages it installs when missing, the host's own computer account in the domain (2.1.6.48) and the
             files it writes, asked once as a kind.
    Inputs:  v — vars: host_join_domain (default True), ad_domain, ad_realm, dc_name, hostname, hostname_dc, host_ip,
             site_name, ad_dc_type (setup/common/host_identity).
    Returns: list of str; [] when host_join_domain is false or there is no AD domain (nothing to join).
    Fails:   FileNotFoundError without dpkg-query (missing_packages).
    Feeds:   consent/plan_host_changes, setup/join_host_domain, undo/undo_group."""
    if v.get("host_join_domain", True) is False or not v.get("ad_domain"):
        return []
    ident = host_identity(v)
    site = (v.get("site_name") or v.get("hostname") or "").lower()
    if ident["own"]:
        account = [
            f"the domain: this host's own computer account {ident['account']}$ in the site's OU=machines/OU=linux "
            "(a member like any other machine: the site's group policy reaches it; not a fabric-machine), its "
            "password random and kept nowhere",
            f"{KEYTAB} (0600): the keys of this host's own computer account {ident['account']}$ and its host/ names "
            "only, exported from the domain controller",
            f"{SSSD_CONF} (0600): domain sign-in for fabric-admins and {site}-fabric-admins only, and only where the "
            "log-on policy of the host's OU allows it; sudo from the domain's rules; sssd enabled and restarted "
            "(local accounts, root and local sudo unchanged)"]
    else:
        account = [
            f"{KEYTAB} (0600): the keys of this host's domain controller account {ident['account']}$ and its host/ "
            f"names only, exported from the domain controller (not its own account: {ident['why']})",
            f"{SSSD_CONF} (0600): domain sign-in for fabric-admins and {site}-fabric-admins only, sudo from the "
            "domain's rules; sssd enabled and restarted (local accounts, root and local sudo unchanged)"]
    return [f"apt: install {p}" for p in missing_packages(MEMBER_PACKAGES)] + account[:-1] + [
        f"{KRB5_CONF}: the realm {v.get('ad_realm')}, its KDC this host's domain controller ({v.get('hostname_dc')})",
        account[-1],
        f"{NSSWITCH}: sss for passwd, group and sudoers",
        "PAM: pam-auth-update --enable sss mkhomedir (a home folder made at the first sign-in)",
        f"{HOSTS}: {v.get('hostname_dc')} as {v.get('host_ip')}, only when this host cannot resolve it",
        "sudo: the classic sudo instead of sudo-rs, only where sudo-rs is the default (it cannot read the domain's "
        "sudo rules)",
    ]
