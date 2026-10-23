import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.common.account_exists import account_exists
from fabriclib.localadmin.common.admin_group import admin_group
from fabriclib.localadmin.common.utc_now import utc_now
from fabriclib.localadmin.constants import ADMIN_GROUPS, COMMENT, USER
from fabriclib.localadmin.ensure_local_admin_store import ensure_local_admin_store
from fabriclib.localadmin.read_local_admin_secret import read_local_admin_secret
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.set_local_admin_password import set_local_admin_password


def _useradd(group):
    """Purpose: the local account made: a home folder, bash, in the admin group, its password locked until set.
    Inputs:  group — the admin group.
    Returns: None.
    Fails:   ValidationError with useradd's complaint.
    Feeds:   ensure_local_admin (its default)."""
    res = subprocess.run(["useradd", "--create-home", "--shell", "/bin/bash", "--groups", group, "--comment", COMMENT,
                          USER], capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise ValidationError(f"useradd {USER}: {(res.stderr or res.stdout).strip()[-300:]}")


def ensure_local_admin(v, config_dir, token, useradd=_useradd, set_password=None, exists=account_exists,
                       audit=write_audit, now=utc_now):
    """Purpose: the fabric host's local-admin made and its password set by OpenBao (decision 2.1.7.16, manual
             1.7.1.4.1): OpenBao's mount and password policy, the account (only when no account of the name exists,
             or fabric's record says fabric made it: a reinstall makes it again), its first password generated, kept
             in OpenBao and set (reason initial, audited LOCAL_ADMIN_INITIAL). Converges: a made account whose current
             password OpenBao holds is left as it is.
    Inputs:  v — rendered vars; config_dir — the install's config folder; token — a fabric-setup token; useradd,
             set_password (None: chpasswd), exists, audit, now — the parts (tests give their own).
    Returns: list of str, what was made ([] when nothing).
    Fails:   ValidationError, nothing changed: an account named local-admin that fabric did not make; no sudo or wheel
             group; OpenBao refusing; the host refusing the password (the account then exists, OpenBao's version
             unmarked: a re-run sets one).
    Feeds:   setup/setup_local_admin; tests/openbao/local_admin.py."""
    rec = load_record(config_dir)
    present = exists()
    if present and not rec["made"]:
        raise ValidationError(f"a local account {USER} exists that fabric did not make: fabric leaves it as it is and "
                              "makes none (rename or remove it, then run `sudo fabricctl setup --step localadmin`)")
    done = ensure_local_admin_store(v, token)
    if not present:
        group = admin_group()
        if not group:
            raise ValidationError(f"this host has neither of the groups {', '.join(ADMIN_GROUPS)}: {USER} would have "
                                  "no sudo")
        useradd(group)
        rec.update(made=True, made_at=now().isoformat(), version=None, set_at=None, used=None, checkout=None,
                   waiting=None)
        save_record(config_dir, rec)
        done.append(f"{USER}: a local account in {group} (console sign-in; SSH refused unless turned on)")
    held = read_local_admin_secret(v, token)
    if rec["version"] is None or held["current"] != rec["version"]:
        kw = {"set_password": set_password} if set_password else {}
        new = set_local_admin_password(v, token, "initial", rec["policy"], now=now, **kw)
        rec.update(version=new["version"], set_at=new["set_at"], reason="initial", used=None, checkout=None,
                   waiting=None)
        save_record(config_dir, rec)
        audit("setup", "LOCAL_ADMIN_INITIAL", f"account={USER} version={new['version']}", "cli")
        done.append(f"{USER}: its password set by OpenBao (version {new['version']}), kept only there")
    return done
