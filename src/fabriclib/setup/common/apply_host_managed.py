import glob
import os
import subprocess

from fabriclib.setup.common.sshd_check import sshd_check as _sshd_check
from fabriclib.setup.errors import SetupError

SSHD_DIR = "/etc/ssh/sshd_config.d"
# 10-: sshd keeps the first value it reads, and Ubuntu's cloud images set their own in 50-cloud-init.conf
SSHD_DROPIN = "/etc/ssh/sshd_config.d/10-fabric.conf"
PAM_SSHD = "/etc/pam.d/sshd"
PAM_MODULES = ("/usr/lib/*/security/pam_localuser.so", "/lib/*/security/pam_localuser.so",
               "/usr/lib/security/pam_localuser.so", "/lib/security/pam_localuser.so")
RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/fabric.conf"
RESOLVED_RUN = "/run/systemd/resolve"        # present while systemd-resolved runs
MARK = "# fabric (manual 1.6.11.11)"
PAM_MARK = (f"{MARK}: over SSH a password is taken for local accounts only; a domain account signs in with "
            "Kerberos. `fabricctl setup --undo member` removes these two lines")
PAM_LINE = "auth requisite pam_localuser.so"
SSHD_TEXT = (f"{MARK}: written by fabricctl setup while this host is in its site's fabric-machines; domain sign-in\n"
             "# with Kerberos. Local accounts' sign-in is left as the host had it: PasswordAuthentication is not\n"
             "# set here, so the appliance stays reachable when its own domain controller is down.\n"
             "GSSAPIAuthentication yes\n"
             "GSSAPICleanupCredentials yes\n"
             "# the keytab holds only this host's own keys; the host's resolver may not give its AD name back\n"
             "GSSAPIStrictAcceptorCheck no\n"
             "UsePAM yes\n")


def _read(path):
    """Purpose: a file's content, or None when it does not exist.
    Inputs:  path.
    Returns: str or None.
    Fails:   OSError other than a missing file.
    Feeds:   apply_host_managed."""
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def _write(path, text):
    """Purpose: replace a file whole (written beside it, then renamed), 0644; None removes it.
    Inputs:  path; text — str or None.
    Returns: None.
    Fails:   OSError.
    Feeds:   apply_host_managed."""
    if text is None:
        if os.path.exists(path):
            os.remove(path)
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.fabric-new"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _pam_with(text):
    """Purpose: /etc/pam.d/sshd with fabric's two lines (PAM_MARK, PAM_LINE) before its first `@include common-auth`
             (or its first auth line, or at the top): a password over SSH is then refused for any account not in
             /etc/passwd before the password is checked. Kerberos (GSSAPI) and keys do not run PAM's auth stack.
    Inputs:  text — the file's content.
    Returns: the new content (the same when the lines are there).
    Fails:   never.
    Feeds:   apply_host_managed."""
    if PAM_LINE in _pam_without(text) and PAM_MARK not in text:
        return text                                  # the owner's own line: nothing to add
    if PAM_MARK in text:
        return text
    lines = text.splitlines()
    at = next((i for i, x in enumerate(lines) if x.strip().startswith("@include common-auth")), None)
    if at is None:
        at = next((i for i, x in enumerate(lines) if x.strip().startswith("auth")), 0)
    return "\n".join(lines[:at] + [PAM_MARK, PAM_LINE] + lines[at:]) + "\n"


def _pam_without(text):
    """Purpose: /etc/pam.d/sshd without fabric's two lines.
    Inputs:  text — the file's content.
    Returns: the new content (the same when they are not there).
    Fails:   never.
    Feeds:   apply_host_managed, _pam_with."""
    lines = text.splitlines()
    if PAM_MARK not in lines:
        return text
    i = lines.index(PAM_MARK)
    drop = 2 if i + 1 < len(lines) and lines[i + 1].strip() == PAM_LINE else 1
    return "\n".join(lines[:i] + lines[i + drop:]) + "\n"


def _reload(what):
    """Purpose: let a running service read its changed configuration; nothing when it does not run.
    Inputs:  what — "ssh" (reloaded: open sessions stay) or "resolved" (systemd-resolved restarted).
    Returns: None.
    Fails:   never (systemctl's own failure is ignored: the files are what counts).
    Feeds:   apply_host_managed."""
    unit = ["try-reload-or-restart", "ssh.service"] if what == "ssh" else ["try-restart", "systemd-resolved.service"]
    subprocess.run(["systemctl", *unit], capture_output=True)


def apply_host_managed(v, managed, dry=False):
    """Purpose: fabric's management of the fabric host itself (decision 2.1.6.49, manual 1.6.11.11), applied while
             its account is in <site>-fabric-machines (managed) and removed when it is not: where an SSH server is
             installed, Kerberos for SSH (SSHD_DROPIN) and a domain account's password refused over SSH (PAM_LINE in
             /etc/pam.d/sshd); where systemd-resolved runs with its stub (use_host_dns), the domain's names from
             fabric's DNS (RESOLVED_DROPIN). Never locks anyone out: local accounts' SSH sign-in is left as the host
             had it (PasswordAuthentication is never written), and sshd's configuration is checked (`sshd -t`) before
             and after the change: a configuration sshd refuses is put back and never loaded. Idempotent.
    Inputs:  v — vars: host_ip, ad_domain, domain, use_host_dns (default True); managed — bool; dry — True: change
             nothing, say what would change.
    Returns: list of str, what changed (or would change); [] when nothing.
    Fails:   SetupError when sshd already refuses its configuration (nothing is changed), when it refuses it with
             fabric's drop-in (the drop-in put back, nothing reloaded), or when pam_localuser is missing; OSError on
             the files.
    Feeds:   setup/join_host_domain (the `member` step), setup/common/sync_host_managed (`fabricctl domain
             host-managed`, the fabric-host-managed timer), undo/undo_member (managed False)."""
    ssh_server = os.path.isdir(SSHD_DIR) and os.path.exists(PAM_SSHD)
    want_sshd = SSHD_TEXT if managed and ssh_server else None
    dns = managed and v.get("use_host_dns", True) is not False and os.path.isdir(RESOLVED_RUN)
    want_dns = (f"{MARK}: the domain's names from fabric's DNS; every other name as the host had them\n"
                f"[Resolve]\nDNS={v.get('host_ip')}\nDomains=~{v.get('ad_domain')} ~{v.get('domain')}\n"
                if dns else None)
    pam = _read(PAM_SSHD)
    want_pam = None if pam is None else (_pam_with(pam) if managed and ssh_server else _pam_without(pam))
    old_sshd, old_dns = _read(SSHD_DROPIN), _read(RESOLVED_DROPIN)
    if old_sshd is not None and MARK not in old_sshd:
        want_sshd = old_sshd                         # not fabric's file: left alone
    if old_dns is not None and MARK not in old_dns:
        want_dns = old_dns
    done = []
    if old_sshd != want_sshd:
        done.append(f"{SSHD_DROPIN}: " + ("Kerberos for SSH (local accounts' sign-in unchanged)" if want_sshd
                                          else "removed"))
    if pam is not None and want_pam != pam:
        done.append(f"{PAM_SSHD}: " + ("a domain account's password refused over SSH (pam_localuser)"
                                       if PAM_MARK in want_pam else "fabric's lines removed"))
    if old_dns != want_dns:
        done.append(f"{RESOLVED_DROPIN}: " + (f"the domain's names from fabric's DNS ({v.get('host_ip')})"
                                              if want_dns else "removed"))
    if dry or not done:
        return done
    if old_sshd != want_sshd or (pam is not None and want_pam != pam):
        if want_pam and PAM_MARK in want_pam and not any(glob.glob(p) for p in PAM_MODULES):
            raise SetupError("pam_localuser.so (libpam-modules) is missing: without it a domain account's password "
                             "would be taken over SSH; nothing was changed (manual 1.6.11.11)")
        if want_sshd:
            before = _sshd_check()
            if before:
                raise SetupError(f"sshd refuses its configuration as it is, before fabric changes anything: {before}. "
                                 "Fix it (`sudo sshd -t` says where), then run `sudo fabricctl setup --step member` "
                                 "again; nothing was changed (manual 1.6.11.11)")
        if old_sshd != want_sshd:
            _write(SSHD_DROPIN, want_sshd)
        if want_sshd and old_sshd != want_sshd:
            after = _sshd_check()
            if after:
                _write(SSHD_DROPIN, old_sshd)         # put back: a configuration sshd refuses is never loaded
                raise SetupError(f"sshd refuses its configuration with fabric's {SSHD_DROPIN} ({after}): put back as "
                                 "it was and nothing reloaded, so SSH works as before (manual 1.6.11.11)")
        if pam is not None and want_pam != pam:
            with open(PAM_SSHD, "w") as f:           # in place: its owner and mode stay
                f.write(want_pam)
        if old_sshd != want_sshd:
            _reload("ssh")
    if old_dns != want_dns:
        _write(RESOLVED_DROPIN, want_dns)
        _reload("resolved")
    return done
