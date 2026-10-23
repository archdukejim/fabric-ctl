"""A lab-only admin password, generated once into an owner-only file in the owner's Windows profile.

Purpose: Windows' labadmin and Proxmox's root need a password (their answer formats require one); the generator makes
  it, keeps it only in %USERPROFILE%\\fabric-lab\\<name>.txt (owner-only ACL) and in the answer media (2.1.1.65).
Inputs: the file's WSL path and its Windows path; the Windows account that owns it.
Returns: the password, for the answer media only. It is never printed, logged or put on a command line.
Fails: if the ACL cannot be set (icacls's exit status), so a readable password file never goes unnoticed.
Feeds: windows_seed.py, proxmox_seed.py.
"""
import os
import secrets
import string
import subprocess

_ALPHABET = string.ascii_letters + string.digits + "-_.+="


def lab_password(wsl_path, win_path, owner):
    if os.path.exists(wsl_path):
        with open(wsl_path, encoding="utf-8") as f:
            value = f.read().strip()
        if value:
            _restrict(win_path, owner)
            return value
    os.makedirs(os.path.dirname(wsl_path), exist_ok=True)
    # 20 characters from 67: about 121 bits; at least one of each class Windows' complexity rule asks for
    while True:
        value = "".join(secrets.choice(_ALPHABET) for _ in range(20))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in "-_.+=" for c in value)):
            break
    fd = os.open(wsl_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value + "\n")
    _restrict(win_path, owner)
    return value


def _restrict(win_path, owner):
    """Owner-only: inheritance off, full control for the owner, SYSTEM and Administrators only."""
    subprocess.run(["icacls.exe", win_path, "/inheritance:r", "/grant:r", owner + ":F",
                    "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"],
                   check=True, stdout=subprocess.DEVNULL)
