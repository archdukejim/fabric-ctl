import json
import os
import socket
import struct
import subprocess

from fabriclib.common.console import info, ok, warn
from fabriclib.common.errors import ValidationError
from fabriclib.common.keep_original import keep_original
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_member import (HOSTS, KEYTAB, MEMBER_PACKAGES, NSSWITCH, RECORD, RENEW_PACKAGE,
                                           SSSD_CONF, plan_member)
from fabriclib.directory.add_machine import add_machine
from fabriclib.directory.place_fabric_host import place_fabric_host
from fabriclib.directory.remove_machine import remove_machine
from fabriclib.setup.common.apply_host_managed import apply_host_managed
from fabriclib.setup.common.apt_install import apt_install
from fabriclib.setup.common.export_keytab import export_keytab
from fabriclib.setup.common.find_computer import find_computer
from fabriclib.setup.common.host_identity import host_identity
from fabriclib.setup.common.missing_packages import missing_packages
from fabriclib.setup.common.render_member_files import render_member_files
from fabriclib.setup.common.renew_days import renew_days
from fabriclib.setup.errors import SetupError

NSS_DATABASES = ("passwd", "group", "sudoers")
PAM_AUTH, PAM_SESSION = "/etc/pam.d/common-auth", "/etc/pam.d/common-session"
SUDO_ALTERNATIVE = "/etc/alternatives/sudo"
CLASSIC_SUDO = "/usr/bin/sudo.ws"


def _keys(data):
    """Purpose: what a keytab holds, without the time each entry was written (an export stamps it), so a re-export
             of unchanged keys compares equal.
    Inputs:  data — bytes of an MIT keytab (version 0x0502), or None.
    Returns: set of (principal, kvno, enctype, key bytes); empty for None or a file that is not one.
    Fails:   never.
    Feeds:   run."""
    out = set()
    if not data or data[:2] != b"\x05\x02":
        return out
    i = 2
    try:
        while i + 4 <= len(data):
            (size,) = struct.unpack(">i", data[i:i + 4])
            i += 4
            if size <= 0:                                   # a hole left by a removed entry
                i += -size
                continue
            e, i = data[i:i + size], i + size
            (count,), j = struct.unpack(">H", e[0:2]), 2
            parts = []
            for _ in range(count + 1):                      # the realm, then each component
                (n,) = struct.unpack(">H", e[j:j + 2])
                parts.append(e[j + 2:j + 2 + n].decode())
                j += 2 + n
            j += 8                                          # name type, timestamp
            kvno = e[j]
            (etype, klen) = struct.unpack(">HH", e[j + 1:j + 5])
            key = e[j + 5:j + 5 + klen]
            if len(e) >= j + 5 + klen + 4:                  # a 32-bit kvno replaces the 8-bit one when present
                kvno = struct.unpack(">I", e[j + 5 + klen:j + 9 + klen])[0] or kvno
            out.add(("/".join(parts[1:]) + "@" + parts[0], kvno, etype, key))
    except (struct.error, IndexError, UnicodeDecodeError):
        return set()
    return out


def _answers(server):
    """Purpose: whether a writable DC answers over LDAP (its rootDSE, read anonymously from inside this site's DC):
             a read-only DC's site writes the host's account there (2.1.6.52).
    Inputs:  server — the writable DC's address.
    Returns: bool.
    Fails:   never.
    Feeds:   run."""
    try:
        res = subprocess.run(["docker", "exec", "samba", "ldbsearch", "-H", f"ldap://{server}", "--use-kerberos=off",
                              "-s", "base", "-b", "", "defaultNamingContext"], capture_output=True, text=True,
                             timeout=60)
    except subprocess.TimeoutExpired:
        return False
    return res.returncode == 0 and "defaultNamingContext" in res.stdout


def _preload(account, server):
    """Purpose: have this site's read-only DC cache the host's account now (its password included), from the
             writable DC: the account is in <site>-rodc-cache, on the read-only DC's allow list (2.1.6.52), so the
             host's keys can be exported here and its sign-ins work with the link down.
    Inputs:  account — the account's name without its $; server — the writable DC's address.
    Returns: None.
    Fails:   SetupError when the read-only DC cannot cache it (the writable DC refuses: not on the allow list).
    Feeds:   run."""
    res = subprocess.run(["docker", "exec", "samba", "samba-tool", "rodc", "preload", f"{account}$",
                          f"--server={server}", "-s", "/data/etc/smb.conf"], capture_output=True, text=True,
                         timeout=120)
    if res.returncode != 0:
        raise SetupError(f"this site's read-only domain controller could not cache {account}$ from {server}: "
                         f"{(res.stderr or res.stdout).strip()[-300:]} (the site's <site>-rodc-cache group must be on "
                         "its password replication allow list, which setup writes at the site's join: manual "
                         "1.6.11.13)")


def _with_sss(text):
    """Purpose: nsswitch.conf with sss after the local files for the databases domain sign-in needs (passwd, group,
             sudoers); every other line as it was.
    Inputs:  text — the file's content.
    Returns: the new content (the same str when nothing was missing).
    Fails:   never.
    Feeds:   run."""
    lines, seen, changed = text.splitlines(), set(), False
    for n, line in enumerate(lines):
        db = line.split(":", 1)[0].strip()
        if db in NSS_DATABASES and ":" in line and not line.lstrip().startswith("#"):
            seen.add(db)
            if "sss" not in line.split(":", 1)[1].split():
                lines[n], changed = line.rstrip() + " sss", True
    added = [f"{db + ':':<16}files sss" for db in NSS_DATABASES if db not in seen]
    if not changed and not added:
        return text
    return "\n".join(lines + added) + "\n"


def _read(path, mode="r"):
    """Purpose: a file's content, or None when it does not exist.
    Inputs:  path; mode — "r" or "rb".
    Returns: str / bytes / None.
    Fails:   OSError other than a missing file.
    Feeds:   run."""
    try:
        with open(path, mode) as f:
            return f.read()
    except FileNotFoundError:
        return None


def _resolves(name, address):
    """Purpose: whether this host already finds the DC's name at its address (DNS or /etc/hosts).
    Inputs:  name — hostname_dc; address — host_ip.
    Returns: bool.
    Fails:   never.
    Feeds:   run."""
    try:
        return address in {a[4][0] for a in socket.getaddrinfo(name, None)}
    except (socket.gaierror, UnicodeError):
        return False


def _pam_on():
    """Purpose: the PAM profiles domain sign-in needs that are on now.
    Inputs:  none (reads PAM_AUTH, PAM_SESSION).
    Returns: list of "sss" / "mkhomedir".
    Fails:   never.
    Feeds:   run."""
    return [p for p, f, mod in (("sss", PAM_AUTH, "pam_sss.so"), ("mkhomedir", PAM_SESSION, "pam_mkhomedir.so"))
            if mod in (_read(f) or "")]


def _sudo_rs():
    """Purpose: whether sudo-rs is the host's sudo while the classic one is installed (Ubuntu 26.04): sudo-rs cannot
             read the domain's sudo rules.
    Inputs:  none.
    Returns: bool.
    Fails:   never.
    Feeds:   run."""
    return "/cargo/bin/sudo" in os.path.realpath("/usr/bin/sudo") and os.access(CLASSIC_SUDO, os.X_OK)


def _sssd_on():
    """Purpose: whether sssd is enabled and running.
    Inputs:  none.
    Returns: bool.
    Fails:   never.
    Feeds:   run."""
    return all(subprocess.run(["systemctl", what, "--quiet", "sssd"], capture_output=True).returncode == 0
               for what in ("is-enabled", "is-active"))


def _record_before(config_dir):
    """Purpose: what was on before fabric made this host a member, once (the first change), for the undo: the PAM
             profiles, whether sssd was enabled, sudo's alternative.
    Inputs:  config_dir — the install's config folder (None: nothing kept, tests on a scratch tree).
    Returns: None; <config_dir>/RECORD written (0600) unless it exists.
    Fails:   OSError writing it.
    Feeds:   run; read by undo/undo_member."""
    if not config_dir or os.path.exists(os.path.join(config_dir, RECORD)):
        return
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "sssd"], capture_output=True).returncode == 0
    before = {"pam": _pam_on(), "sssd_enabled": enabled,
              "sudo": os.readlink(SUDO_ALTERNATIVE) if os.path.islink(SUDO_ALTERNATIVE) else None}
    fd = os.open(os.path.join(config_dir, RECORD), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(before, f)


def _recorded(config_dir, key):
    """Purpose: what RECORD keeps under a key: "account", the host's own computer account fabric made in the domain;
             "placed", the account fabric made the site's fabric host (OU=fabric-hosts, 2.1.6.49), once.
    Inputs:  config_dir — the install's config folder (None: tests on a scratch tree); key — str.
    Returns: str (e.g. "FAB1") or None.
    Fails:   OSError / ValueError reading a damaged RECORD.
    Feeds:   run."""
    path = os.path.join(config_dir or "", RECORD)
    if not config_dir or not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f).get(key)


def _record(config_dir, key, value):
    """Purpose: keep a value in RECORD (after _record_before): the host's own account's name ("account"), so the undo
             removes it and a later run knows the account is this host's; the account placed ("placed"), so it is
             placed once and an admin's later move is kept.
    Inputs:  config_dir — the install's config folder (None: nothing kept); key — str; value — str, or None to forget.
    Returns: None; RECORD rewritten (0600).
    Fails:   OSError / ValueError on RECORD.
    Feeds:   run."""
    path = os.path.join(config_dir or "", RECORD)
    if not config_dir or not os.path.exists(path):
        return
    with open(path) as f:
        record = json.load(f)
    record[key] = value
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)


def _write(path, data, mode):
    """Purpose: replace a file whole (written beside it, then renamed), with the mode given.
    Inputs:  path; data — str or bytes; mode — e.g. 0o600.
    Returns: None.
    Fails:   OSError.
    Feeds:   run."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.fabric-new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def run(ctx):
    """Purpose: make the fabric host a member of its own domain (manual 1.6.11.8, decisions 2.1.6.34, 2.1.6.48,
             2.1.6.49, 2.1.6.52): it signs in with its own computer account `<HOSTNAME>$`, pre-created as `fabricctl
             domain add-machine` makes one and placed once in the site's OU=fabric-hosts and <site>-fabric-machines, so
             the site's group policy reaches it; whom that OU's log-on policy allows (the fabric admins by default,
             2.1.6.53) sign in to it with their domain accounts, with sudo from the site's rules; while the account is
             in <site>-fabric-machines, fabric manages the host (setup/common/apply_host_managed: Kerberos for SSH, the
             domain's names from fabric's DNS; local accounts' sign-in untouched). At a site whose DC is read-only, the
             account is written at the writable DC it replicates from, put in <site>-rodc-cache and cached by the
             read-only DC (2.1.6.52); with that DC not answering, refused. Local accounts, root and local sudo are
             untouched.
    Inputs:  ctx — SetupContext: vars (host_join_domain, default true; host_machine_password_renew_days; the
             domain's names: render_member_files, plan_member, host_identity), config_dir (the `member` consent; the
             kept originals; RECORD), offline, secrets (the site's agent account, which creates and places the host's
             account).
    Returns: None. Skipped (said so) with host_join_domain false or the consent declined. Otherwise, after the
             consent and with each host file kept before its first change (common/keep_original): the packages
             installed when missing (adcli too while the password is renewed); the host's own account created when
             missing (recorded in RECORD) and placed once (recorded); an account fabric made for this host under an
             earlier name removed; /etc/krb5.keytab (0600) with the account's current keys (an install whose keytab
             held the DC's account moves to its own: the keytab replaced); /etc/krb5.conf and /etc/sssd/sssd.conf
             (0600); sss in nsswitch.conf for passwd, group and sudoers; PAM's sss and mkhomedir profiles on; the
             DC's name in /etc/hosts when the host cannot resolve it; the classic sudo where sudo-rs is the default;
             sssd enabled and restarted when anything changed; fabric's management applied or removed as the
             account's membership says. Idempotent: a second run changes nothing.
    Fails:   SetupError: a domain controller with this host's name (2.1.6.51), or a read-only DC's site whose writable
             DC does not answer (2.1.6.52), before anything changes; the read-only DC not caching the account;
             offline with packages missing; a computer of the host's name in the domain that fabric did not make
             for it; the DC not answering (find_computer) or not exporting the keys (export_keytab); sshd refusing its
             configuration (apply_host_managed: nothing loaded); apt (apt_install). ValidationError: the directory
             refusing the account (add_machine, place_fabric_host). CalledProcessError from pam-auth-update,
             update-alternatives or systemctl; OSError on the files.
    Feeds:   setup step `member`, run by run_setup via STEPS."""
    v = ctx.vars
    if v.get("host_join_domain", True) is False:
        ok("this host stays out of its domain (host_join_domain: false; status shows it)")
        return
    plan = plan_member(v)
    if not plan:
        ok("no AD domain to join")
        return
    ident = host_identity(v)
    if ident["refused"]:
        raise SetupError(f"this host cannot be a member of its domain: {ident['refused']} (decisions 2.1.6.51, "
                         "2.1.6.52). Give the domain controller another name (dc_name) before the domain is made, or "
                         "leave this host out of it (host_join_domain: false); nothing was changed (manual 1.6.11.8)")
    server = ident["write_server"]                 # a read-only DC's site: written at its writable partner (2.1.6.52)
    current = _read(KEYTAB, "rb")
    recorded = _recorded(ctx.config_dir, "account")
    found = find_computer(ident["account"])
    if found and recorded != ident["account"] and not any(
            k[0].upper().startswith(f"{ident['account']}$@") for k in _keys(current)):
        raise SetupError(f"the domain already has a computer named {ident['account']} ({found['dn']}) that fabric "
                         "did not make for this host: remove it in the web console (Directory → Machines) or rename "
                         "this host, then run `sudo fabricctl setup --step member` again (manual 1.6.11.8)")
    missing = missing_packages(MEMBER_PACKAGES + ([RENEW_PACKAGE] if renew_days(v) else []))
    files = render_member_files(v)
    keytab = None
    if found:
        try:
            keytab = export_keytab(ident["principals"])
        except SetupError:
            if not server or not _answers(server):     # a read-only DC that does not cache it yet: preloaded below
                raise
    stale = recorded if recorded and recorded != ident["account"] else None
    hosts_line = None if _resolves(v["hostname_dc"], v["host_ip"]) else f"{v['host_ip']} {v['hostname_dc']}\n"
    nss = _read(NSSWITCH) or ""
    # placed once per account (2.1.6.49): an admin's later move, or taking it out of the group, is kept
    place = _recorded(ctx.config_dir, "placed") != ident["account"]
    group = f"cn={str(v.get('site_name') or '').lower()}-fabric-machines,"
    managed = place or any(g.lower().startswith(group) for g in (found or {}).get("member_of", []))
    host_changes = apply_host_managed(v, managed, dry=True)
    todo = (missing or not found or stale or _keys(keytab) != _keys(current)
            or any(_read(p) != c for p, c in files.items()) or _with_sss(nss) != nss or hosts_line
            or len(_pam_on()) < 2 or _sudo_rs() or not _sssd_on() or place or host_changes)
    if not todo:
        ok("this host is a member of its domain (nothing to change)")
        return
    if missing and ctx.offline:
        raise SetupError(f"offline install but packages are missing: {' '.join(missing)}")
    if server and (not found or place or stale or keytab is None) and not _answers(server):
        raise SetupError(f"this site's domain controller is read-only, so the host's account is made at the writable "
                         f"domain controller it replicates from ({server}), which does not answer. Bring the link "
                         "back (`fabricctl federation status`), then run `sudo fabricctl setup --step member` again; "
                         "or leave this host out of its domain (host_join_domain: false). Nothing was changed "
                         "(decision 2.1.6.52, manual 1.6.11.13)")
    if not check_consent(ctx.config_dir, "member", plan):
        return
    _record_before(ctx.config_dir)
    for path in (KEYTAB, *files, NSSWITCH) + ((HOSTS,) if hosts_line else ()):
        keep_original(path, ctx.config_dir, marker="# fabric")
    if missing:
        info(f"installing {' '.join(missing)}")
        apt_install(missing, "They are in Ubuntu's main and universe components: check the host's apt sources, run "
                             "`apt-get update`, then re-run `sudo fabricctl setup --step member`.")
    changed = bool(missing)
    if not found:
        # a random password the domain's policy accepts, never shown nor kept: the keytab is all the host needs
        add_machine(v, "fabricctl setup", ident["account"].lower(), source="setup", secrets=ctx.secrets,
                    os="linux", managed=False, server=server)
        _record(ctx.config_dir, "account", ident["account"])
        ok(f"the domain: this host's own computer account {ident['account']}$ made"
           + (f" at the writable domain controller {server}" if server else ""))
    elif recorded != ident["account"]:
        _record(ctx.config_dir, "account", ident["account"])     # made before it was recorded (its keys are here)
    if place:
        done = place_fabric_host(v, "fabricctl setup", ident["account"], source="setup", secrets=ctx.secrets,
                                 server=server)
        _record(ctx.config_dir, "placed", ident["account"])
        ok(f"the domain: {ident['account']}$ is {v.get('site_name')}'s fabric host, managed by fabric "
           f"({'moved into ' if done.get('moved') else 'in '}OU=fabric-hosts, in {v.get('site_name')}-fabric-machines"
           + (f", in {v.get('site_name')}-rodc-cache" if server else "") + ")")
    if server and (not found or place or keytab is None):
        _preload(ident["account"], server)
        ok(f"this site's read-only domain controller caches {ident['account']}$ "
           f"(its password replicated from {server})")
    if not found or keytab is None:
        keytab = export_keytab(ident["principals"])
    if _keys(keytab) != _keys(_read(KEYTAB, "rb")):
        held = {k[0].split("@")[0].upper() for k in _keys(_read(KEYTAB, "rb"))}
        moved = bool(held) and f"{ident['account']}$" not in held
        _write(KEYTAB, keytab, 0o600)
        changed = True
        ok(f"{KEYTAB}: the keys of {ident['account']}$ and its host/ names"
           + (" (it held another account's: replaced)" if moved else ""))
    if stale:
        try:
            remove_machine(v, "fabricctl setup", stale.lower(), source="setup", secrets=ctx.secrets, server=server)
            ok(f"the domain: {stale}$, this host's account under its earlier name, removed")
        except ValidationError as e:
            warn(f"the domain: {stale}$, this host's account under its earlier name, not removed ({e}): remove it "
                 "in the web console (Directory → Machines)")
    for path, content in files.items():
        if _read(path) != content:
            _write(path, content, 0o600 if path == SSSD_CONF else 0o644)
            changed = True
            ok(f"{path} written")
    nss = _read(NSSWITCH) or ""                        # the packages may have changed it
    if _with_sss(nss) != nss:
        with open(NSSWITCH, "w") as f:
            f.write(_with_sss(nss))
        ok(f"{NSSWITCH}: sss for {', '.join(NSS_DATABASES)}")
    if hosts_line:
        with open(HOSTS, "a") as f:                    # in place: a container's /etc/hosts is a bind mount
            f.write(hosts_line)
        ok(f"{HOSTS}: {hosts_line.strip()}")
    if len(_pam_on()) < 2:
        subprocess.run(["pam-auth-update", "--enable", "sss", "mkhomedir"], check=True, capture_output=True)
        ok("PAM: sss and mkhomedir on")
    if _sudo_rs():
        subprocess.run(["update-alternatives", "--set", "sudo", CLASSIC_SUDO], check=True, capture_output=True)
        ok("sudo: the classic sudo (sudo-rs cannot read the domain's sudo rules)")
    if changed or not _sssd_on():
        subprocess.run(["systemctl", "enable", "sssd"], check=True, capture_output=True)
        subprocess.run(["systemctl", "restart", "sssd"], check=True, capture_output=True)
        ok("sssd enabled and restarted")
    for line in apply_host_managed(v, managed):
        ok(line)
    ok(f"this host is a member of {v['ad_domain']}: whom OU=fabric-hosts' log-on policy allows signs in with a "
       "domain account (the fabric admins by default, 2.1.6.53)"
       + ("; fabric manages it (manual 1.6.11.11)" if managed else ""))
