from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.common.bao_call import bao_call
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.common.utc_now import utc_now
from fabriclib.localadmin.constants import MOUNT, USER
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.secret_path import secret_path
from fabriclib.localadmin.set_local_admin_password import set_local_admin_password
from fabriclib.vault.common.bao_request import bao_request


def follow_rename(v_old, v_new, config_dir, actor="root", token_fn=local_admin_token, set_password=None,
                  audit=write_audit, now=utc_now):
    """Purpose: the host's local-admin follows its host to a new name (decision 2.1.6.104, manual 1.7.1.4.11): its
             place in OpenBao is named by the host (`<site>/fabric-host/<hostname>/local-admin`, 1.7.1.4.2), so a
             renamed host would find nothing current there (doctor: "OpenBao's current version None, the host's 2",
             the lab's joined campaign, 2.3.1.33). A new password is set under the new name, as a rotation sets one
             (reason "after rename": written to OpenBao first, set on the host, then marked current), the record
             takes its version and the host's new name, and the old name's path is marked as moved there, its
             versions kept as history. Run again after a failure, it does what is left.
    Inputs:  v_old, v_new — vars with the old and the new hostname (OpenBao's address, site_name); config_dir — the
             install's config folder; actor — the audit's; token_fn, set_password (None: chpasswd), audit, now — the
             parts (tests give their own).
    Returns: list of str, what was done ([] when fabric made no local-admin here or it already follows the name).
    Fails:   ValidationError when OpenBao gives no token (said why: the password is unchanged, nothing recorded) or the
             host refused the new password (the old one stays valid; run it again); OSError, ValueError from the
             record.
    Feeds:   breakglass/rename_host (`fabricctl admin rename-host`); tests/openbao/local_admin.py."""
    rec = load_record(config_dir)
    new = str(v_new["hostname"]).lower()
    if not rec["made"] or rec.get("host") == new:
        return []
    token, why = token_fn(v_new)
    if token is None:
        raise ValidationError(f"{USER} cannot follow the new name: {why}")
    kw = {"set_password": set_password} if set_password else {}
    done = set_local_admin_password(v_new, token, "after rename", rec["policy"], now=now, **kw)
    rec.update(version=done["version"], set_at=done["set_at"], reason="after rename", used=None, checkout=None,
               waiting=None, host=new)
    save_record(config_dir, rec)
    old_path, new_path = secret_path(v_old), secret_path(v_new)
    lines = [f"{USER}: a new password under the new name (OpenBao's version {done['version']}, {MOUNT}/{new_path})"]
    if old_path != new_path:
        status, answer = bao_request(v_old, "GET", f"{MOUNT}/metadata/{old_path}", token=token)
        got = (answer.get("data") or {}) if status == 200 else {}
        if got:
            meta = got.get("custom_metadata") or {}
            bao_call(v_old, token, "POST", f"{MOUNT}/metadata/{old_path}", {"custom_metadata": {
                **meta, "current": "none", "moved_to": new_path, "moved_on": now().isoformat()}})
            lines.append(f"{USER}: the old name's versions kept as history, marked moved ({MOUNT}/{old_path})")
    audit(actor, "LOCAL_ADMIN_ROTATE", f"account={USER} version={done['version']} reason=after rename "
                                       f"host={new}", "cli")
    return lines
