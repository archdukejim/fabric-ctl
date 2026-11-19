import os
import stat
import sys

from fabriclib.common.ask import ask_secret
from fabriclib.common.errors import ValidationError

MIN_PASSPHRASE = 12


def _value(args, flag):
    """Purpose: the value after a flag.
    Inputs:  args — list of arguments; flag — str.
    Returns: str, or None when the flag is not given.
    Fails:   ValidationError when the flag has no value after it.
    Feeds:   read_backup_key."""
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 >= len(args) or args[i + 1].startswith("--"):
        raise ValidationError(f"{flag} needs a value")
    return args[i + 1]


def _key_file(path):
    """Purpose: a private key read from a root-only file (global Rule 10: never an argument).
    Inputs:  path — the file.
    Returns: its first AGE-SECRET-KEY-1 line.
    Fails:   ValidationError when it is readable by others or holds no key; OSError.
    Feeds:   read_backup_key."""
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValidationError(f"{path} can be read by others: chmod 600 it first")
    with open(path) as f:
        key = next((line.strip() for line in f if line.startswith("AGE-SECRET-KEY-1")), None)
    if not key:
        raise ValidationError(f"{path} holds no age private key (AGE-SECRET-KEY-1…)")
    return key


def read_backup_key(args, v, opening):
    """Purpose: how a bundle is sealed or opened (manual 1.3.7.11, 1.3.7.12), never from a command line value: a
             passphrase asked twice on the terminal or read from stdin, the schedule's public key, a public key
             (not a secret), or a private key from a root-only file or stdin.
    Inputs:  args — the command's arguments: --public-key age1…, --scheduled-key, --key-stdin, --key-file PATH;
             v — vars (backup_public_key); opening — True to open a bundle, False to make one.
    Returns: {"passphrase": str or None, "public_key": str or None} to make; {"passphrase", "private_key"} to open.
    Fails:   ValidationError: two passphrases that differ, one shorter than 12 characters, --scheduled-key with no
             schedule, a key file others can read; EOFError with no terminal and no --key-stdin.
    Feeds:   run_backup_command, run_restore_command, run_uninstall_command, run_reinstall_command."""
    if opening:
        if "--key-file" in args:
            return {"passphrase": None, "private_key": _key_file(_value(args, "--key-file"))}
        line = (sys.stdin.readline().rstrip("\n") if "--key-stdin" in args
                else ask_secret("backup.open_key", "The bundle's passphrase, or the schedule's private key: "))
        if line.strip().startswith("AGE-SECRET-KEY-1"):
            return {"passphrase": None, "private_key": line.strip()}
        return {"passphrase": line, "private_key": None}
    if "--public-key" in args:
        return {"passphrase": None, "public_key": _value(args, "--public-key")}
    if "--scheduled-key" in args or "--scheduled" in args:
        if not v.get("backup_public_key"):
            raise ValidationError("no schedule's public key is set: `sudo fabricctl backup schedule --public-key …`")
        return {"passphrase": None, "public_key": v["backup_public_key"]}
    if "--key-stdin" in args:
        passphrase = sys.stdin.readline().rstrip("\n")
    else:
        passphrase = ask_secret("backup.passphrase", "A passphrase for this backup (12 characters or more): ")
        if ask_secret("backup.passphrase_again", "The same passphrase again: ") != passphrase:
            raise ValidationError("the two passphrases differ: nothing was made")
    if len(passphrase) < MIN_PASSPHRASE:
        raise ValidationError(f"the passphrase is shorter than {MIN_PASSPHRASE} characters: nothing was made")
    return {"passphrase": passphrase, "public_key": None}
