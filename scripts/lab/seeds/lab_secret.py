"""A lab-only admin password, generated once into an owner-only file on the build VM.

Purpose: Windows' labadmin and Proxmox's root need a password (their answer formats require one); the generator makes
  it, keeps it only in ~/fabric-lab/<name> on the build VM (folder 0700, file 0600, the running user's) and in the
  answer media (2.1.1.65, 2.1.1.99.2).
Inputs: the file's path.
Returns: the password, for the answer media only. It is never printed, logged or put on a command line.
Fails: if the folder or the file belongs to another user, is not a plain folder or file, or keeps a mode wider than
  owner-only after it is set, so a readable password file never goes unnoticed.
Feeds: windows_seed.py, proxmox_seed.py.
"""
import os
import secrets
import stat
import string

_ALPHABET = string.ascii_letters + string.digits + "-_.+="


def lab_password(path):
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    _restrict(folder, stat.S_ISDIR, 0o700)
    if os.path.lexists(path):
        _restrict(path, stat.S_ISREG, 0o600)
        with open(path, encoding="utf-8") as f:
            value = f.read().strip()
        if value:
            return value
    # 20 characters from 67: about 121 bits; at least one of each class Windows' complexity rule asks for
    while True:
        value = "".join(secrets.choice(_ALPHABET) for _ in range(20))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in "-_.+=" for c in value)):
            break
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value + "\n")
    _restrict(path, stat.S_ISREG, 0o600)
    return value


def _restrict(path, is_kind, mode):
    """Owner-only: the running user's, of the right kind (never a link), and exactly `mode` once set."""
    st = os.lstat(path)
    kind = "folder" if is_kind is stat.S_ISDIR else "file"
    if not is_kind(st.st_mode):
        raise SystemExit(f"{path}: not a plain {kind} (a link or another kind); the lab passwords need one")
    if st.st_uid != os.getuid():
        raise SystemExit(f"{path}: belongs to uid {st.st_uid}, not this user ({os.getuid()}); refusing its passwords")
    if stat.S_IMODE(st.st_mode) != mode:
        os.chmod(path, mode)
        if stat.S_IMODE(os.lstat(path).st_mode) != mode:
            raise SystemExit(f"{path}: its mode could not be set to {mode:o}")
