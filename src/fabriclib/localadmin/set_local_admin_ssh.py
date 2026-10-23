import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.localadmin.apply_local_admin_ssh import apply_local_admin_ssh
from fabriclib.localadmin.common.utc_now import utc_now
from fabriclib.localadmin.constants import USER
from fabriclib.localadmin.local_admin_request import local_admin_request
from fabriclib.localadmin.record import load_record, save_record
from fabriclib.localadmin.require_enterprise_admin import require_enterprise_admin

DC_RE = re.compile(r"^dc-\d{4}$")


def set_local_admin_ssh(v, config_dir, caller, actor, ssh, dc=None, source="cli", container="samba",
                        apply_ssh=None, audit=write_audit, now=utc_now):
    """Purpose: the SSH switch of a DC's host's local-admin set in the domain (decision 2.1.7.19, manual 1.7.1.4.6),
             only by the Enterprise Admin's tier: written at this host's DC when it is writable, audited
             LOCAL_ADMIN_SSH, and applied to sshd at once when it is this host's (another host's at its next timer
             run).
    Inputs:  v — rendered vars (dc_name); config_dir — the install's config folder; caller — the signed-in person
             (None: root on the host); actor — who, for the audit; ssh — "on" or "off"; dc — the DC whose host is
             meant (default this host's); source — "cli" or "web"; container, apply_ssh (None:
             apply_local_admin_ssh), audit, now — the parts (tests give their own).
    Returns: {"dc", "ssh": bool, "changed": bool, "applied": [str] (this host's sshd; [] for another host's)}.
    Fails:   ValidationError, nothing changed: a caller below the Enterprise Admin; ssh not on or off; a dc not named
             dc-NNNN or no DC of the domain; this host's DC read-only (the writable DC named); the DC not running.
             ValidationError from apply_ssh after the switch was stored (sshd refusing: said, the timer tries again).
    Feeds:   run_local_admin_command (`fabricctl local-admin ssh`),
             agent/post_local_admin (POST /v1/local-admin/ssh)."""
    require_enterprise_admin(v, caller, "turn local-admin over SSH on or off", container)
    if ssh not in ("on", "off"):
        raise ValidationError("ssh: on or off")
    dc = (dc or v["dc_name"]).lower()
    if not DC_RE.match(dc):
        raise ValidationError(f"{dc} is not a domain controller's name (dc-NNNN)")
    out = local_admin_request(v, {"op": "set", "dc": dc, "ssh": ssh == "on", "by": actor,
                                  "when": now().isoformat()}, container)
    if out["changed"]:
        audit(actor, "LOCAL_ADMIN_SSH", f"account={USER} dc={dc} ssh={ssh}", source)
    applied = []
    if dc == v["dc_name"].lower():
        rec = load_record(config_dir)
        if rec["made"]:
            applied = (apply_ssh or apply_local_admin_ssh)(ssh == "on")
            rec["ssh"] = {"on": ssh == "on", "applied_at": now().isoformat(), "by": out.get("by"),
                          "set_at": out.get("when")}
            save_record(config_dir, rec)
    return {"dc": dc, "ssh": out["ssh"], "changed": out["changed"], "applied": applied}
