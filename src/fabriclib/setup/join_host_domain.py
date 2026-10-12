import json
import os
import socket
import struct
import subprocess

from fabriclib.common.console import info, ok
from fabriclib.common.keep_original import keep_original
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_member import (HOSTS, KEYTAB, MEMBER_PACKAGES, NSSWITCH, RECORD, SSSD_CONF,
                                           plan_member)
from fabriclib.setup.common.apt_install import apt_install
from fabriclib.setup.common.export_dc_keytab import export_dc_keytab
from fabriclib.setup.common.missing_packages import missing_packages
from fabriclib.setup.common.render_member_files import render_member_files
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
    """Purpose: make the fabric host a member of its own domain (manual 1.6.11.8, decision 2.1.6.34): it signs in
             with its DC's own machine account, the fabric admins (fabric-admins, <site>-fabric-admins) sign in to it
             with their domain accounts and have sudo from the site's rules. Local accounts, root and local sudo are
             untouched.
    Inputs:  ctx — SetupContext: vars (host_join_domain, default true; the domain's names: render_member_files,
             plan_member), config_dir (the `member` consent; the kept originals), offline.
    Returns: None. Skipped (said so) with host_join_domain false or the consent declined. Otherwise, after the
             consent and with each host file kept before its first change (common/keep_original): the packages
             installed when missing; /etc/krb5.keytab (0600) with the DC account's current keys; /etc/krb5.conf and
             /etc/sssd/sssd.conf (0600); sss in nsswitch.conf for passwd, group and sudoers; PAM's sss and
             mkhomedir profiles on; the DC's name in /etc/hosts when the host cannot resolve it; the classic sudo
             where sudo-rs is the default; sssd enabled and restarted when anything changed. Idempotent: a second
             run changes nothing.
    Fails:   SetupError: offline with packages missing; the DC not exporting its keys (export_dc_keytab); apt
             (apt_install). CalledProcessError from pam-auth-update, update-alternatives or systemctl; OSError on
             the files.
    Feeds:   setup step `member`, run by run_setup via STEPS."""
    v = ctx.vars
    if v.get("host_join_domain", True) is False:
        ok("this host stays out of its domain (host_join_domain: false; status shows it)")
        return
    plan = plan_member(v)
    if not plan:
        ok("no AD domain to join")
        return
    missing = missing_packages(MEMBER_PACKAGES)
    files = render_member_files(v)
    keytab = export_dc_keytab(v)
    hosts_line = None if _resolves(v["hostname_dc"], v["host_ip"]) else f"{v['host_ip']} {v['hostname_dc']}\n"
    nss = _read(NSSWITCH) or ""
    todo = (missing or _keys(keytab) != _keys(_read(KEYTAB, "rb"))
            or any(_read(p) != c for p, c in files.items()) or _with_sss(nss) != nss or hosts_line
            or len(_pam_on()) < 2 or _sudo_rs() or not _sssd_on())
    if not todo:
        ok("this host is a member of its domain (nothing to change)")
        return
    if missing and ctx.offline:
        raise SetupError(f"offline install but packages are missing: {' '.join(missing)}")
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
    if _keys(keytab) != _keys(_read(KEYTAB, "rb")):
        _write(KEYTAB, keytab, 0o600)
        changed = True
        ok(f"{KEYTAB}: the keys of {str(v['dc_name']).upper()}$ and its host/ names")
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
    ok(f"this host is a member of {v['ad_domain']}: fabric-admins and {v.get('site_name')}-fabric-admins sign in "
       "with their domain accounts")
