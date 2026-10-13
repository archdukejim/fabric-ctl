from fabriclib.setup.common.host_identity import host_identity
from fabriclib.setup.common.missing_packages import missing_packages
from fabriclib.setup.common.renew_days import renew_days

# What the host needs to sign in with its domain (manual 1.6.11.8): sssd's AD provider, NSS and PAM for sss, sudo's
# sss support, the Kerberos tools; SASL's GSSAPI module (without it sssd cannot bind to the DC: "No worthy mechs
# found", found by the sandbox suite) and sssctl, as the Linux join installs them
MEMBER_PACKAGES = ["sssd-ad", "sssd-tools", "libnss-sss", "libpam-sss", "libsss-sudo", "krb5-user",
                   "libsasl2-modules-gssapi-mit"]
# while the host's machine password is renewed (1.6.11.12): sssd renews it with adcli
RENEW_PACKAGE = "adcli"
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


def _packages(v):
    """Purpose: the packages the host needs as a member of its domain: MEMBER_PACKAGES, and RENEW_PACKAGE while its
             machine password is renewed (host_machine_password_renew_days, 1.6.11.12).
    Inputs:  v — vars.
    Returns: list of str.
    Fails:   never.
    Feeds:   plan_member (setup/join_host_domain asks the same)."""
    return MEMBER_PACKAGES + ([RENEW_PACKAGE] if renew_days(v) else [])


def plan_member(v):
    """Purpose: what making this host a member of its own domain changes (manual 1.2.9.3 `member`, 1.6.11.8): the
             packages it installs when missing, the host's own computer account in the domain (2.1.6.48), placed as
             the site's fabric host (2.1.6.49), the files it writes, and fabric's management of the host while it is
             in <site>-fabric-machines (1.6.11.11), asked once as a kind.
    Inputs:  v — vars: host_join_domain (default True), ad_domain, ad_realm, dc_name, hostname, hostname_dc, host_ip,
             site_name, ad_dc_type (setup/common/host_identity), host_machine_password_renew_days, use_host_dns,
             domain.
    Returns: list of str; [] when host_join_domain is false or there is no AD domain (nothing to join).
    Fails:   FileNotFoundError without dpkg-query (missing_packages).
    Feeds:   consent/plan_host_changes, setup/join_host_domain, undo/undo_group."""
    if v.get("host_join_domain", True) is False or not v.get("ad_domain"):
        return []
    ident = host_identity(v)
    site = (v.get("site_name") or v.get("hostname") or "").lower()
    if ident["own"]:
        days = renew_days(v)
        account = [
            f"the domain: this host's own computer account {ident['account']}$, placed once in the site's "
            f"OU=fabric-hosts and in {site}-fabric-machines (the site's fabric host, managed by fabric: the site's "
            "group policy reaches it), its password random and kept nowhere, "
            + (f"renewed by sssd with adcli every {days} days" if days else "never renewed"),
            f"{KEYTAB} (0600): the keys of this host's own computer account {ident['account']}$ and its host/ names "
            "only, exported from the domain controller",
            f"{SSSD_CONF} (0600): domain sign-in for fabric-admins and {site}-fabric-admins only, and only where the "
            "log-on policy of the host's OU allows it; sudo from the domain's rules; sssd enabled and restarted "
            "(local accounts, root and local sudo unchanged)"]
        managed = [
            f"while this host is in {site}-fabric-machines, where an SSH server is installed: "
            "/etc/ssh/sshd_config.d/10-fabric.conf (Kerberos for SSH; local accounts' sign-in unchanged, so the host "
            "stays reachable with its domain controller down; checked with `sshd -t` before it is loaded) and "
            "/etc/pam.d/sshd (pam_localuser: a domain account's password refused over SSH)"]
        if v.get("use_host_dns", True) is not False:
            managed.append(f"while this host is in {site}-fabric-machines: /etc/systemd/resolved.conf.d/fabric.conf "
                           f"(the names of {v.get('ad_domain')} and {v.get('domain')} from fabric's DNS at "
                           f"{v.get('host_ip')}; other names as before), where systemd-resolved runs")
    else:
        account = [
            f"{KEYTAB} (0600): the keys of this host's domain controller account {ident['account']}$ and its host/ "
            f"names only, exported from the domain controller (not its own account: {ident['why']})",
            f"{SSSD_CONF} (0600): domain sign-in for fabric-admins and {site}-fabric-admins only, sudo from the "
            "domain's rules; sssd enabled and restarted (local accounts, root and local sudo unchanged)"]
        managed = []
    return [f"apt: install {p}" for p in missing_packages(_packages(v))] + account[:-1] + [
        f"{KRB5_CONF}: the realm {v.get('ad_realm')}, its KDC this host's domain controller ({v.get('hostname_dc')})",
        account[-1],
        f"{NSSWITCH}: sss for passwd, group and sudoers",
        "PAM: pam-auth-update --enable sss mkhomedir (a home folder made at the first sign-in)",
        f"{HOSTS}: {v.get('hostname_dc')} as {v.get('host_ip')}, only when this host cannot resolve it",
        "sudo: the classic sudo instead of sudo-rs, only where sudo-rs is the default (it cannot read the domain's "
        "sudo rules)",
    ] + managed
