from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dhcp.common.turn_dhcp_on import turn_dhcp_on
from fabriclib.security.apply_signin import apply_signin
from fabriclib.security.refresh_firewall import refresh_firewall
from fabriclib.settings.constants import LOG_HOST_KEYS
from fabriclib.settings.mark_wizard_finished import mark_wizard_finished
from fabriclib.settings.plan_is_current import plan_is_current
from fabriclib.system.apply_changes import apply_changes
from fabriclib.system.host_networks import host_networks

STALE = ("the settings changed since this plan was made (someone else applied first): nothing was changed; review "
         "the plan again")


def _log_forwarding(new, old):
    """Purpose: the wizard's log forwarding with the host's own sub-keys kept as they were (a CA file, names to
             resolve: console only, LOG_HOST_KEYS).
    Inputs:  new — the wizard's value; old — the settings' value now.
    Returns: the value to save.
    Fails:   never.
    Feeds:   apply_settings."""
    old = old if isinstance(old, dict) else {}
    out = {k: (dict(c) if isinstance(c, dict) else c) for k, c in new.items()}
    for part, keys in LOG_HOST_KEYS.items():
        source = old if not part else old.get(part)
        target = out if not part else out.get(part)
        for key in keys:
            if isinstance(source, dict) and key in source and isinstance(target, dict):
                target[key] = source[key]
    return out


def apply_settings(plan, actor, have_gb=None, networks=None, apply=None, firewall=None, config_dir=None):
    """Purpose: apply a plan of the wizard's settings (manual 1.8.5.5): under the settings' lock, refused when stale
             (someone applied first) and changing nothing then; the changed keys written to vars.yaml (DHCP turned on
             with its first subnet, turn_dhcp_on; log forwarding keeping the host's own sub-keys); audited as
             SETTINGS_CHANGE with who, from where and the keys; then one apply — with fabric's Keycloak configuration
             when Kerberos sign-in changed (apply_signin), the host firewall brought in line when DHCP changed
             (refresh_firewall, as the Kea tab does) — and the wizard marked finished.
    Inputs:  plan — plan_settings' result (source, base, settings, keys); actor — who (audit); have_gb — the host's
             GB (None: measured); networks — host_networks() (None: this host's); apply — callable(actor, source) ->
             (ok, output) (None: apply_changes, or apply_signin when signin_kerberos changed); firewall — callable() ->
             (ok, output) (None: refresh_firewall); config_dir — where the wizard's record is (None: vars.yaml's).
    Returns: {"ok": bool, "keys": [...], "message": str, "output": the apply's last 3000 characters}.
    Fails:   ValidationError (nothing changed): the plan is stale; DHCP can no longer be turned on with its first
             subnet. OSError / yaml errors from the settings, the lock or the audit log; subprocess.TimeoutExpired
             from the apply.
    Feeds:   agent/post_settings (POST /v1/settings/apply, as a job), settings/run_settings_command
             (`fabricctl settings import`)."""
    keys, new, source = list(plan["keys"]), plan["settings"], plan.get("source", "web")
    audit_source = "cli" if source == "cli" else "web"
    with vars_lock():
        data = load_vars()
        if not plan_is_current(plan, data, have_gb):
            raise ValidationError(STALE)
        for key in keys:
            if key == "dhcp":
                continue
            if key == "install_kea" and new[key]:
                d = new["dhcp"]
                data["dhcp"] = turn_dhcp_on(data, d["interface"], d["subnet"], d["pool"], d["router"],
                                            host_networks() if networks is None else networks)
            data[key] = (_log_forwarding(new[key], data.get(key)) if key == "log_forwarding" else new[key])
        if keys:
            save_vars(data)
    write_audit(actor, "SETTINGS_CHANGE", f"from {source}: " + (", ".join(k for k in keys if k != "dhcp") or "none"),
                audit_source)
    if not keys:
        mark_wizard_finished("applied", actor, audit_source, config_dir)
        return {"ok": True, "keys": [], "message": "Nothing to change: the settings were already so.", "output": ""}
    run = apply or (apply_signin if "signin_kerberos" in keys else apply_changes)
    ok, output = run(actor, audit_source)
    if ok and "install_kea" in keys:
        ok, more = (firewall or refresh_firewall)()
        output += "\n" + more
    if ok:
        mark_wizard_finished("applied", actor, audit_source, config_dir)
    shown = ", ".join(k for k in keys if k != "dhcp")
    message = (f"Applied: {shown}." if ok else
               f"Saved ({shown}) but the apply did not finish: see its output, fix what it names and apply again "
               "(sudo fabricctl --apply, or the Overview).")
    return {"ok": ok, "keys": keys, "message": message, "output": output[-3000:]}
