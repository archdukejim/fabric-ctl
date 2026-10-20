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
# the Enterprise Admin's sudo on a DC's host: a local rule (2.1.6.78)
SUDOERS = "/etc/sudoers.d/fabric-admin"
KEYTAB = "/etc/krb5.keytab"
NSSWITCH = "/etc/nsswitch.conf"
HOSTS = "/etc/hosts"
# the host files the step keeps before its first change and the undo puts back (common/keep_original)
KEPT_FILES = (KRB5_CONF, SSSD_CONF, SUDOERS, KEYTAB, NSSWITCH, HOSTS)
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
             the site's fabric host (2.1.6.49; at a read-only DC's site made at the writable DC and cached, 2.1.6.52),
             the files it writes, and fabric's management of the host while it is in fabric-managed (1.6.11.11),
             asked once as a kind.
    Inputs:  v — vars: host_join_domain (default True), ad_domain, ad_realm, dc_name, hostname, hostname_dc, host_ip,
             ad_dc_type, ad_join_server (setup/common/host_identity), host_machine_password_renew_days,
             use_host_dns, domain.
    Returns: list of str; [] when host_join_domain is false or there is no AD domain (nothing to join).
    Fails:   FileNotFoundError without dpkg-query (missing_packages).
    Feeds:   consent/plan_host_changes, setup/join_host_domain, undo/undo_group."""
    if v.get("host_join_domain", True) is False or not v.get("ad_domain"):
        return []
    ident = host_identity(v)
    days = renew_days(v)
    where = (f" (made at the writable domain controller {ident['write_server']}, this site's being read-only; in "
             f"rodc-cache-{v.get('dc_name')}, so the read-only one caches its password, decision 2.1.6.52)"
             if ident["write_server"] else "")
    account = [
        f"the domain: this host's own computer account {ident['account']}$, placed once in OU=fabric-hosts and "
        f"in fabric-managed and dc-hosts (a fabric host, managed by fabric; in no site's group, so no grant on a "
        f"site reaches it){where}, its password random and kept nowhere, "
        + (f"renewed by sssd with adcli every {days} days" if days else "never renewed"),
        f"{KEYTAB} (0600): the keys of this host's own computer account {ident['account']}$ and its host/ names "
        "only, exported from the domain controller",
        f"{SSSD_CONF} (0600): the domain's names resolve, but no domain account signs in but fabric-admin, the "
        "Enterprise Admin, and no domain sudo rule applies (a host that runs a domain controller is the top tier, "
        "decisions 2.1.6.75, 2.1.6.78); sssd enabled and restarted (local accounts, root and local sudo unchanged)",
        f"{SUDOERS} (0440): fabric-admin may use sudo here (a local rule, not the domain's)"]
    managed = [
        "while this host is in fabric-managed, where an SSH server is installed: "
        "/etc/ssh/sshd_config.d/10-fabric.conf (Kerberos for SSH; local accounts' sign-in unchanged, so the host "
        "stays reachable with its domain controller down; checked with `sshd -t` before it is loaded) and "
        "/etc/pam.d/sshd (pam_localuser: a domain account's password refused over SSH)"]
    if v.get("use_host_dns", True) is not False:
        managed.append("while this host is in fabric-managed: /etc/systemd/resolved.conf.d/fabric.conf "
                       f"(the names of {v.get('ad_domain')} and {v.get('domain')} from fabric's DNS at "
                       f"{v.get('host_ip')}; other names as before), where systemd-resolved runs")
    return [f"apt: install {p}" for p in missing_packages(_packages(v))] + account[:-1] + [
        f"{KRB5_CONF}: the realm {v.get('ad_realm')}, its KDC this host's domain controller",     # unnamed: 2.1.6.65
        account[-1],
        f"{NSSWITCH}: sss for passwd, group and sudoers",
        "PAM: pam-auth-update --enable sss mkhomedir (a home folder made at the first sign-in)",
        f"{HOSTS}: the domain controller's name as {v.get('host_ip')}, only when this host cannot resolve it",
        "sudo: the classic sudo instead of sudo-rs, only where sudo-rs is the default (it cannot read the domain's "
        "sudo rules)",
    ] + managed
