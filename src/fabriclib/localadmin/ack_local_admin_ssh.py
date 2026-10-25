import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.common.utc_now import utc_now
from fabriclib.localadmin.constants import USER
from fabriclib.localadmin.local_admin_request import local_admin_request
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.require_enterprise_admin import require_enterprise_admin

DC_RE = re.compile(r"^dc-\d{4}$")


def ack_local_admin_ssh(v, config_dir, caller, actor, dc=None, source="cli", container="samba", audit=write_audit,
                        now=utc_now):
    """Purpose: the alert of a DC's host's local-admin let in over SSH acknowledged (decision 2.1.7.21, manual
             1.7.1.4.10), only by the Enterprise Admin's tier: who and when kept with the switch in the domain (at this
             host's DC when it is writable), audited LOCAL_ADMIN_SSH_ACK, and copied to this host's record when it is
             this host's (another host's at its next timer run). Doctor and the console's reminders stop warning of it;
             the switch's state is still shown everywhere, and turning it off and on again raises the alert again.
    Inputs:  v — rendered vars (dc_name); config_dir — the install's config folder; caller — the signed-in person
             (None: root on the host); actor — who, for the audit; dc — the DC whose host is meant (default this
             host's); source — "cli" or "web"; container, audit, now — the parts (tests give their own).
    Returns: {"dc", "ack": {"by", "when"}, "changed": bool}.
    Fails:   ValidationError, nothing changed: a caller below the Enterprise Admin; a dc not named dc-NNNN or no DC of
             the domain; the switch off (nothing to acknowledge); this host's DC read-only (the writable DC named); the
             DC not running.
    Feeds:   run_local_admin_command (`fabricctl local-admin ssh ack`), agent/post_local_admin (POST
             /v1/local-admin/ssh, ssh "ack")."""
    require_enterprise_admin(v, caller, "acknowledge the alert of local-admin over SSH", container)
    dc = (dc or v["dc_name"]).lower()
    if not DC_RE.match(dc):
        raise ValidationError(f"{dc} is not a domain controller's name (dc-NNNN)")
    out = local_admin_request(v, {"op": "ack", "dc": dc, "by": actor, "when": now().isoformat()}, container)
    if out["changed"]:
        audit(actor, "LOCAL_ADMIN_SSH_ACK", f"account={USER} dc={dc} alert acknowledged", source)
    if dc == v["dc_name"].lower():
        rec = load_record(config_dir)
        if rec["made"] and (rec.get("ssh") or {}).get("on"):
            rec["ssh"] = {**rec["ssh"], "ack": out.get("ack")}
            save_record(config_dir, rec)
    return {"dc": dc, "ack": out.get("ack"), "changed": out["changed"]}
