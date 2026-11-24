import grp
import os

from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.samba.write_bind_dlz import write_bind_dlz


def deploy_samba(v, secrets, jinja_env):
    """Purpose: write the domain controller's files under <deploy_base>/samba during apply (manual 1.6.5): the
             Administrator's password for provisioning and the code that converges the domain inside the DC.
    Inputs:  v — the rendered vars: deploy_base_dir, host_ip, ad_domain. secrets — fabric's secrets
             (ad_admin_password).
             jinja_env — Jinja environment whose first search path holds samba/converge/*.py (an install) or sits
             beside src/containers/samba (a checkout).
    Returns: {"converge": True if the converge code changed, "restart": True if the DC's resolv.conf changed}.
             (The password file is read only when the domain is provisioned: a change to it changes nothing in a
             running domain.) BIND's DLZ files are written when missing, so BIND
             can start, and again while the DC's DNS database is not there (a restored bundle brings dlz.conf back
             before an online bundle's databases load: manual 1.3.7.6; found by the sandbox, 2026-11-23): either way
             they can only be turned off here; turning DLZ on (and restarting BIND) happens after the domain is
             converged.
    Fails:   KeyError without ad_admin_password; OSError from creating, owning or writing.
    Feeds:   deploy/deploy_optional_parts (apply); tests/samba.
    Notes:   the folders are root's (the DC runs as root in its container): data/ (0755: the DC serves SYSVOL as each
             user, who must be able to reach it; Samba keeps private/ 0700 and SYSVOL under its own ACLs; etc/ and
             bind-dns/ are mounted into BIND), secrets/, tls/ (filled by setup's certificate step), converge/ (0700;
             read-only in the container); bind/ is BIND's (write_bind_dlz); resolv.conf (the DC's resolver, mounted
             read-only)."""
    base = os.path.join(v["deploy_base_dir"], "samba")
    for sub in ("secrets", "tls", "converge"):
        ensure_dir(os.path.join(base, sub), 0o700, 0, 0)
    # the DC serves SYSVOL and NETLOGON as each user (it switches identity), so its data folder must be traversable;
    # what is secret inside it has its own modes (private/ 0700) and SYSVOL its own ACLs
    ensure_dir(os.path.join(base, "data"), 0o755, 0, 0)
    # BIND mounts these two (its DLZ): made once if missing, never reset — provisioning gives them BIND's group
    for sub in ("etc", "bind-dns"):
        os.makedirs(os.path.join(base, "data", sub), mode=0o755, exist_ok=True)
    # winbind's sockets, on the host so FreeRADIUS can reach them (PEAP through ntlm_auth); winbind makes the pipe
    ensure_dir(os.path.join(base, "winbindd"), 0o755, 0, 0)
    # its time-signing socket (2.1.13.1): root and chrony's group, 0750 (Samba checks the owner and the mode), so the
    # host's chrony signs Windows members' time
    ensure_dir(v["ad_ntp_signd_dir"], 0o750, 0, _chrony_gid())
    # BIND includes these when it starts: they must exist, and name no database that is not there (a restore's
    # dlz.conf before its databases load); turning DLZ on is for after the domain is converged
    if (not os.path.exists(os.path.join(base, "bind", "dlz.conf"))
            or not os.path.exists(os.path.join(base, "data", "bind-dns", "dns", "sam.ldb"))):
        write_bind_dlz(v)
    write_file_if_changed(os.path.join(base, "secrets", "admin_password"), secrets["ad_admin_password"] + "\n", 0o600)
    # a site joining the root's domain (manual 1.9.8.4): the temporary join account as a credentials file, kept until
    # the account is deleted after the join (finish_join)
    join, auth = secrets.get("ad_join") or {}, os.path.join(base, "secrets", "join.auth")
    if join.get("user"):
        write_file_if_changed(auth, f"username={join['user']}\npassword={join['password']}\n"
                                    f"domain={v['ad_netbios']}\n", 0o600)
    elif os.path.exists(auth):
        os.remove(auth)
    joining = bool(v.get("ad_join_server")) and not os.path.exists(os.path.join(base, "data", ".fabric-provisioned"))
    # the DC's own resolver: the host's address (BIND, or the DNS filter in front of it), which knows the AD zone —
    # in the host network it would otherwise use the host's resolver, which may not (use_host_dns), and then cannot
    # find its own KDC or send its signed updates. Until a site's DC has joined, this host's BIND has no AD zone:
    # the root's address answers for it
    resolver = v["ad_join_server"] if joining else v["host_ip"]
    restart = write_file_if_changed(os.path.join(base, "resolv.conf"),
                                    f"nameserver {resolver}\nsearch {v['ad_domain']}\n", 0o644)
    src = os.path.join(jinja_env.loader.searchpath[0], "samba", "converge")
    if not os.path.isdir(src):              # a checkout: the converge code lives in src/containers/ (manual 1.2.2)
        src = os.path.join(os.path.dirname(jinja_env.loader.searchpath[0]), "src", "containers", "samba")
    converge = False
    for name in sorted(os.listdir(src)):
        if name.endswith(".py"):
            converge |= write_file_if_changed(os.path.join(base, "converge", name),
                                              open(os.path.join(src, name)).read(), 0o600)
    return {"converge": converge, "restart": restart}


def _chrony_gid():
    """Purpose: the host's chrony group, which signs Windows time through the DC's socket.
    Inputs:  none.
    Returns: int gid of `_chrony` (Ubuntu's), else 0 (no chrony: nothing to sign for).
    Fails:   never.
    Feeds:   deploy_samba."""
    try:
        return grp.getgrnam("_chrony").gr_gid
    except KeyError:
        return 0
