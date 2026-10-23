from fabriclib.localadmin.common.account_exists import account_exists
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.constants import USER
from fabriclib.localadmin.read_local_admin_secret import read_local_admin_secret
from fabriclib.localadmin.record import load_record


def local_admin_checks(v, config_dir, approved, token_fn=local_admin_token, exists=account_exists, secret=None):
    """Purpose: doctor's view of the host's local-admin (manual 1.7.1.4.7): a check that the account exists and that
             the version OpenBao holds as current is the one the host set, while its host change is approved; and the
             warnings that do not fail a check: a rotation waiting (2.1.7.20), the last timer run failed, SSH on
             (2.1.7.19, a relaxation: shown by relaxed_settings).
    Inputs:  v — rendered vars; config_dir — the install's config folder; approved — whether the `local_admin` host
             change is approved; token_fn, exists, secret — the parts (secret: read_local_admin_secret; tests give
             their own).
    Returns: {"checks": [(name, passed, detail)], "warnings": [str]}.
    Fails:   ValueError, OSError from the record.
    Feeds:   setup/verify_install (doctor), system/host_reminders (the console's reminders: the warnings)."""
    rec = load_record(config_dir)
    checks, warnings = [], []
    if approved:
        name = f"{USER}: the host's break glass, its password set by OpenBao and kept only there (1.7.1.4)"
        if not rec["made"] or not exists():
            checks.append((name, False, "not made: run `sudo fabricctl setup --step localadmin`"))
        else:
            token, why = token_fn(v)
            if token is None:
                checks.append((name, False, f"OpenBao cannot be asked: {why}"))
            else:
                held = (secret or read_local_admin_secret)(v, token)
                checks.append((name, held["current"] == rec["version"],
                               f"OpenBao's current version {held['current']}, the host's {rec['version']}"))
    if rec["waiting"]:
        warnings.append(f"{USER}: a new password has been due since {rec['waiting']['since']} but waits "
                        f"({rec['waiting']['why']}): the used password stays valid until OpenBao is back and the "
                        "hourly timer rotates it (2.1.7.20)")
    last = rec["last_check"]
    if rec["made"] and last and not last.get("ok"):
        warnings.append(f"{USER}: the hourly check failed at {last['when']}: {last.get('detail')}")
    return {"checks": checks, "warnings": warnings}
