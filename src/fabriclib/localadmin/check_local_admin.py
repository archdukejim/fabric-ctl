from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.apply_local_admin_ssh import apply_local_admin_ssh
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.common.rotation_due import rotation_due
from fabriclib.localadmin.common.utc_now import parse_time, utc_now
from fabriclib.localadmin.constants import USER
from fabriclib.localadmin.find_local_admin_uses import find_local_admin_uses
from fabriclib.localadmin.read_ssh_switch import read_ssh_switch
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.set_local_admin_password import set_local_admin_password


def _sync_ssh(v, rec, read_switch, apply_ssh, now):
    """Purpose: the SSH switch as the domain keeps it applied to sshd; a DC that does not answer leaves what was last
             applied (off when nothing ever was).
    Inputs:  v — rendered vars; rec — the record (its "ssh" updated in place); read_switch, apply_ssh — the functions;
             now — the clock.
    Returns: list of str, what was done or said.
    Fails:   ValidationError from apply_ssh (sshd refusing its configuration).
    Feeds:   check_local_admin."""
    last = rec.get("ssh") or {}
    try:
        switch = read_switch(v)
        on, said = switch["ssh"], []
        source = {"by": switch.get("by"), "set_at": switch.get("when")}
    except ValidationError as e:
        on, source = last.get("on") is True, {k: last.get(k) for k in ("by", "set_at")}
        said = [f"the domain's SSH switch could not be read ({e}): sshd keeps what was last applied "
                f"({'on' if on else 'off'})"]
    done = apply_ssh(on)
    rec["ssh"] = {"on": on, "applied_at": now().isoformat() if done or not last else last.get("applied_at"),
                  **source}
    return said + done


def check_local_admin(v, config_dir, actor="root", source="timer", find_uses=find_local_admin_uses,
                      token_fn=local_admin_token, set_password=None, read_switch=read_ssh_switch,
                      apply_ssh=apply_local_admin_ssh, audit=write_audit, now=utc_now):
    """Purpose: the hourly run (`fabricctl local-admin check --scheduled`, decisions 2.1.7.16, 2.1.7.17, 2.1.7.19,
             2.1.7.20; manual 1.7.1.4.4): the current password's first use seen in the journal or wtmp marked (audited
             LOCAL_ADMIN_USED); once a use or a check-out is past its grace, a new password from OpenBao set and marked
             current (audited LOCAL_ADMIN_ROTATE) — or, with OpenBao locked, the rotation left waiting (the used
             password stays valid, the record says why); then the domain's SSH switch applied to sshd. The run is
             recorded for status and doctor.
    Inputs:  v — rendered vars; config_dir — the install's config folder; actor, source — the audit's; find_uses,
             token_fn, set_password (None: chpasswd), read_switch, apply_ssh, audit, now — the parts (tests give their
             own).
    Returns: {"ok": bool, "lines": [str]} ("nothing to check" when fabric made no local-admin here).
    Fails:   never for what it finds: a host that refused the new password, or sshd refusing the drop-in, is a failed
             run (ok False, said and recorded); OSError, ValueError from the record propagate.
    Feeds:   run_local_admin_command (`fabricctl local-admin check`, the fabric-local-admin timer),
             setup/setup_local_admin (its last part)."""
    rec = load_record(config_dir)
    if not rec["made"]:
        return {"ok": True, "lines": [f"nothing to check: fabric made no {USER} on this host"]}
    lines, ok = [], True
    stamp = now()
    since = parse_time(rec["set_at"])
    if since and not rec["used"]:
        uses = find_uses(since)
        if uses:
            when, how = uses[0]
            rec["used"] = {"when": when.isoformat(), "how": how}
            audit(actor, "LOCAL_ADMIN_USED", f"account={USER} version={rec['version']} when={when.isoformat()} "
                                             f"how={how}", source)
            lines.append(f"{USER} was used at {when.isoformat()} ({how}): its password is rotated once the grace "
                         "has passed")
    due, why = rotation_due(rec)
    if due and stamp >= due:
        token, locked = token_fn(v)
        if token is None:
            rec["waiting"] = {"since": (rec.get("waiting") or {}).get("since") or stamp.isoformat(), "why": locked}
            lines.append(f"a new password for {USER} is due ({why}) but waits: {locked}; the used password stays "
                         "valid until OpenBao is back (2.1.7.20)")
        else:
            try:
                kw = {"set_password": set_password} if set_password else {}
                done = set_local_admin_password(v, token, "after use", rec["policy"], now=now, **kw)
            except ValidationError as e:
                ok = False
                lines.append(f"{USER}'s rotation failed: {e}")
            else:
                audit(actor, "LOCAL_ADMIN_ROTATE", f"account={USER} version={done['version']} reason=after use "
                                                   f"({why})", source)
                rec.update(version=done["version"], set_at=done["set_at"], reason="after use", used=None,
                           checkout=None, waiting=None)
                lines.append(f"{USER} has a new password (OpenBao's version {done['version']}), after it was {why}")
    try:
        lines += _sync_ssh(v, rec, read_switch, apply_ssh, now)
    except ValidationError as e:
        ok = False
        lines.append(f"local-admin's SSH switch not applied: {e}")
    rec["last_check"] = {"when": stamp.isoformat(), "ok": ok, "detail": "; ".join(lines)[-500:]}
    save_record(config_dir, rec)
    return {"ok": ok, "lines": lines}
