import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.localadmin.constants import MARK, SSHD_DIR, SSHD_DROPIN, USER
from fabriclib.setup.common.sshd_check import sshd_check

OFF = (f"{MARK}: local-admin over SSH is off for this host (decision 2.1.7.19): sshd refuses it before any password.\n"
       "# Turned on only by the Enterprise Admin (sudo fabricctl local-admin ssh on); written by fabric.\n"
       f"DenyUsers {USER}\n")
ON = (f"{MARK}: local-admin over SSH is ON for this host (decision 2.1.7.19, a relaxation): its password, for this\n"
      "# user only. Turned off with `sudo fabricctl local-admin ssh off`; written by fabric.\n"
      f"Match User {USER}\n"
      "    PasswordAuthentication yes\n"
      "    KbdInteractiveAuthentication yes\n"
      "    PubkeyAuthentication no\n"
      "    AuthorizedKeysFile none\n"
      "Match all\n")


def _read(path):
    """Purpose: a file's content, or None when it does not exist.
    Inputs:  path.
    Returns: str or None.
    Fails:   OSError other than a missing file.
    Feeds:   apply_local_admin_ssh."""
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
    Feeds:   apply_local_admin_ssh."""
    if text is None:
        if os.path.exists(path):
            os.remove(path)
        return
    tmp = f"{path}.fabric-new"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def apply_local_admin_ssh(on, remove=False, check=sshd_check, reload=None, dropin=SSHD_DROPIN, folder=SSHD_DIR):
    """Purpose: the SSH switch of the host's local-admin applied to sshd (decision 2.1.7.19, manual 1.7.1.4.6), where
             an SSH server is installed: off, `DenyUsers local-admin`; on, a `Match User local-admin` block allowing
             its password for that user only. sshd's configuration is checked (`sshd -t`) before and after: one it
             refuses is put back and never loaded; sshd is reloaded after a change (open sessions stay). Idempotent.
    Inputs:  on — bool; remove — True: fabric's drop-in removed (the undo, uninstall); check — sshd_check (tests give
             their own); reload — callable() reloading sshd (default systemctl try-reload-or-restart ssh.service);
             dropin, folder — where (tests give their own).
    Returns: list of str, what changed ([] when nothing, or no SSH server).
    Fails:   ValidationError when sshd already refuses its configuration (nothing changed), or refuses it with fabric's
             drop-in (put back, nothing reloaded); OSError on the file.
    Feeds:   setup/setup_local_admin, check_local_admin, set_local_admin_ssh, remove_local_admin."""
    if not os.path.isdir(folder):
        return []
    old = _read(dropin)
    if old is not None and MARK not in old:
        raise ValidationError(f"{dropin} is not fabric's: left as it is (remove it or rename it, then run `sudo "
                              "fabricctl local-admin check`)")
    want = None if remove else (ON if on else OFF)
    if old == want:
        return []
    if want is not None:
        before = check()
        if before:
            raise ValidationError(f"sshd refuses its configuration as it is, before fabric changes anything: {before}; "
                                  "nothing was changed (fix it: `sudo sshd -t` says where)")
    _write(dropin, want)
    if want is not None:
        after = check()
        if after:
            _write(dropin, old)
            raise ValidationError(f"sshd refuses its configuration with fabric's {dropin} ({after}): put back as it "
                                  "was, nothing reloaded")
    (reload or (lambda: subprocess.run(["systemctl", "try-reload-or-restart", "ssh.service"],
                                       capture_output=True)))()
    if want is None:
        return [f"{dropin}: removed"]
    return [f"{dropin}: local-admin over SSH " + ("on (its password, for that user only)" if on else
                                                 "off (sshd refuses it)")]
