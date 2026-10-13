import glob
import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.setup.common.sshd_check import sshd_check
from fabriclib.vault.ssh.known_hosts_block import BEGIN, END, known_hosts_block
from fabriclib.vault.ssh.parse_ssh_cert import CERT_TYPES

SSHD_DIR = "/etc/ssh/sshd_config.d"
# after 10-fabric.conf (1.6.11.11); HostCertificate adds up, so the order among drop-ins does not matter
DROPIN = "/etc/ssh/sshd_config.d/11-fabric-host-cert.conf"
CERT_FILE = "/etc/ssh/fabric-host-cert-{}.pub"     # one per host key family: ed25519, ecdsa, rsa
KNOWN_HOSTS = "/etc/ssh/ssh_known_hosts"
MARK = "# fabric (manual 1.6.11.9.10)"


def _read(path):
    """Purpose: a file's content, or None when it does not exist.
    Inputs:  path.
    Returns: str or None.
    Fails:   OSError other than a missing file.
    Feeds:   apply_host_ssh_cert."""
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
    Feeds:   apply_host_ssh_cert."""
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


def _without_block(text):
    """Purpose: a known-hosts file without fabric's block (BEGIN to END).
    Inputs:  text — the file's content ("" when it does not exist).
    Returns: str.
    Fails:   never.
    Feeds:   apply_host_ssh_cert."""
    lines, out, inside = text.splitlines(), [], False
    for line in lines:
        if line == BEGIN:
            inside = True
        elif line == END and inside:
            inside = False
        elif not inside:
            out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def _reload():
    """Purpose: let a running sshd read its host certificates again; nothing when it does not run.
    Inputs:  none.
    Returns: None.
    Fails:   never (systemctl's own failure is ignored: the files are what counts).
    Feeds:   apply_host_ssh_cert."""
    subprocess.run(["systemctl", "try-reload-or-restart", "ssh.service"], capture_output=True)


def apply_host_ssh_cert(v, certs, ca_key, revoked=(), check=sshd_check, reload=_reload):
    """Purpose: the fabric host's own side of SSH host certificates (manual 1.6.11.9.10; decision 2.1.7.13): its host
             certificates beside its host keys and named by HostCertificate in DROPIN (where an SSH server is
             installed, checked with `sshd -t` before and after: a configuration sshd refuses is put back and never
             loaded), and, as an SSH client, the host CA trusted for the domain's names in /etc/ssh/ssh_known_hosts
             (fabric's block only; the rest of the file is the owner's). Empty certs and ca_key remove all of it.
             Idempotent.
    Inputs:  v — settings: ad_domain, domain; certs — list of certificate lines for this host's keys; ca_key — the
             host CA's public key line, or ""; revoked — host key lines refused by @revoked lines (1.6.11.9.12);
             check, reload — sshd_check and _reload (tests pass their own).
    Returns: list of str, what changed; [] when nothing.
    Fails:   ValidationError when sshd already refuses its configuration (nothing changed) or refuses it with the
             host certificates (the drop-in put back, nothing reloaded); OSError on the files.
    Feeds:   vault/ssh/sign_ssh_hosts (fabric-ssh-hosts.timer, `fabricctl domain ssh-hosts`)."""
    files = {}
    for line in certs:
        kind = str(line).split()[0] if str(line).split() else ""
        if kind in CERT_TYPES:
            family = CERT_TYPES[kind][0].replace("ssh-", "").split("-")[0]
            files[CERT_FILE.format(family)] = " ".join(str(line).split()[:2]) + "\n"
    server = os.path.isdir(SSHD_DIR)
    done = []
    old_files = {p: _read(p) for p in glob.glob(CERT_FILE.format("*"))}
    want_dropin = None
    if server and files:
        want_dropin = (f"{MARK}: this host's SSH host certificates, signed by fabric's host CA while SSH certificates "
                       "are on; written by fabric-ssh-hosts.timer\n"
                       + "".join(f"HostCertificate {p}\n" for p in sorted(files)))
    old_dropin = _read(DROPIN)
    if old_dropin is not None and MARK not in old_dropin:
        raise ValidationError(f"{DROPIN} is not fabric's: move it away, then run `sudo fabricctl domain ssh-hosts`")
    certs_change = any(old_files.get(p) != t for p, t in files.items()) or any(p not in files for p in old_files)
    if want_dropin and (old_dropin != want_dropin or certs_change):
        before = check()
        if before:
            raise ValidationError(f"sshd refuses its configuration as it is, before fabric changes anything: {before}; "
                                  "nothing was changed (manual 1.6.11.9.10)")
    for p, t in files.items():
        if old_files.get(p) != t:
            _write(p, t)
            done.append(f"{p}: written")
    for p in old_files:
        if p not in files:
            _write(p, None)
            done.append(f"{p}: removed")
    if old_dropin != want_dropin:
        _write(DROPIN, want_dropin)
        done.append(f"{DROPIN}: " + ("HostCertificate for each" if want_dropin else "removed"))
    if want_dropin and done:
        after = check()
        if after:
            _write(DROPIN, old_dropin)
            for p, t in old_files.items():
                _write(p, t)
            for p in files:
                if p not in old_files:
                    _write(p, None)
            raise ValidationError(f"sshd refuses its configuration with fabric's host certificates ({after}): put back "
                                  "as it was and nothing reloaded (manual 1.6.11.9.10)")
    if done and server:
        reload()
    old_known = _read(KNOWN_HOSTS)
    want_known = _without_block(old_known or "")
    if ca_key:
        want_known += known_hosts_block(ca_key, [v.get("ad_domain"), v.get("domain")], revoked)
    if want_known != (old_known or "") and not (old_known is None and not want_known):
        _write(KNOWN_HOSTS, want_known)
        done.append(f"{KNOWN_HOSTS}: " + ("fabric's host CA trusted for the domain's names" if ca_key
                                          else "fabric's host CA removed"))
    return done
