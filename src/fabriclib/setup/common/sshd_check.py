import os
import subprocess

SSHD = "/usr/sbin/sshd"
PRIVSEP_DIR = "/run/sshd"


def sshd_check():
    """Purpose: whether sshd accepts its configuration as it is on disk (`sshd -t`), so fabric never loads one it
             refuses (manual 1.6.11.11, 1.6.11.9.10).
    Inputs:  none.
    Returns: "" when it does; sshd's complaint otherwise.
    Fails:   never (an sshd that cannot run is a complaint).
    Feeds:   setup/common/apply_host_managed, vault/ssh/apply_host_ssh_cert.
    Notes:   sshd's test needs its privilege-separation folder, which ssh.service makes only when sshd first runs (on
             Ubuntu 24.04 the socket starts it at the first connection): made here as the service makes it."""
    try:
        os.makedirs(PRIVSEP_DIR, mode=0o755, exist_ok=True)
        res = subprocess.run([SSHD, "-t"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e)
    return "" if res.returncode == 0 else ((res.stderr or res.stdout).strip()[-400:] or f"exit {res.returncode}")
