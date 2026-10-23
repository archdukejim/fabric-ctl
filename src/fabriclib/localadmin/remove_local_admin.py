import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.apply_local_admin_ssh import apply_local_admin_ssh
from fabriclib.localadmin.common.account_exists import account_exists
from fabriclib.localadmin.common.bao_call import bao_call
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.common.utc_now import utc_now
from fabriclib.localadmin.constants import MOUNT, RECORD, USER
from fabriclib.localadmin.record import load_record
from fabriclib.localadmin.secret_path import secret_path


def _userdel():
    """Purpose: the account and its home folder removed.
    Inputs:  none.
    Returns: "" when done; userdel's complaint otherwise (an account still signed in is refused).
    Fails:   never (no userdel is a complaint).
    Feeds:   remove_local_admin (its default)."""
    try:
        res = subprocess.run(["userdel", "--remove", USER], capture_output=True, text=True, timeout=60)
    except OSError as e:
        return str(e)
    return "" if res.returncode == 0 else ((res.stderr or res.stdout).strip()[-300:] or f"exit {res.returncode}")


def remove_local_admin(v, config_dir, userdel=_userdel, apply_ssh=apply_local_admin_ssh, token_fn=local_admin_token,
                       exists=account_exists, audit=write_audit, now=utc_now):
    """Purpose: the `local_admin` host change undone (decision 2.1.7.16, manual 1.7.1.4.1; global Rule 12): the account
             fabric made and its home removed, fabric's SSH drop-in removed (sshd reloaded), the record removed;
             OpenBao's versions kept as its history, marked removed when OpenBao answers. An account fabric did not
             make is never touched.
    Inputs:  v — rendered vars (None: OpenBao is not asked, as by uninstall, which removes the vault); config_dir — the
             install's config folder; userdel, apply_ssh, token_fn, exists, audit, now — the parts (tests give their
             own).
    Returns: list of str, what was done ([] when fabric had made nothing).
    Fails:   ValidationError when userdel refuses (an account still signed in): the record and the drop-in are kept,
             so running it again finishes it.
    Feeds:   undo/undo_group (`fabricctl setup --undo local_admin`), setup/uninstall."""
    rec = load_record(config_dir)
    if not rec["made"]:
        return []
    done = []
    if exists():
        why = userdel()
        if why:
            raise ValidationError(f"{USER} was not removed: {why} (sign it out, then undo again)")
        done.append(f"{USER}: the account and its home folder removed")
    try:
        done += apply_ssh(False, remove=True)
    except (ValidationError, OSError) as e:
        done.append(f"fabric's SSH drop-in for {USER} not removed: {e}")
    if v is not None:
        token, why = token_fn(v)
        if token:
            path = secret_path(v)
            got = bao_call(v, token, "GET", f"{MOUNT}/metadata/{path}").get("data") or {}
            meta = got.get("custom_metadata") or {}
            bao_call(v, token, "POST", f"{MOUNT}/metadata/{path}", {"custom_metadata": {
                **meta, "current": "none", "removed": now().isoformat()}})
            done.append(f"OpenBao: {USER}'s versions kept as its history, marked removed")
        else:
            done.append(f"OpenBao not told ({why}): its versions stay as they are")
    os.remove(os.path.join(config_dir, RECORD))
    audit("setup", "LOCAL_ADMIN_REMOVE", f"account={USER}", "cli")
    return done
