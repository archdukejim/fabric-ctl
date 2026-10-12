from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.plan_holds_subnets import MOVED, plan_holds_subnets


def remove_reservation(actor, mac, source="cli"):
    """Purpose: Remove a MAC's reservation from vars.yaml. Applied by the next apply; the client then gets a pool
             address at its next renewal.
    Inputs:  actor — str, who asks (audit).
             mac — str (case, and - or :, do not matter).
             source — "cli" (default) or "web". Reads/writes vars.yaml under vars_lock.
    Returns: None.
    Fails:   ValidationError MOVED once the subnets live in the address plan (manual 1.10.4.9); ValidationError
             "no reservation for …"; OSError or yaml.YAMLError from vars_lock / load_vars / save_vars /
             write_audit.
    Feeds:   agent route POST /v1/dhcp/reservations/<mac>/delete (fabric-agent, src/agent/, called by
             the web UI); run_dhcp_command (unreserve).
    Notes:   only the first subnet holding the MAC is changed (normalize_dhcp keeps MACs unique).
    """
    mac = str(mac).strip().lower().replace("-", ":")
    with vars_lock():
        data = load_vars()
        if plan_holds_subnets(data):
            raise ValidationError(MOVED)
        for s in (data.get("dhcp") or {}).get("subnets") or []:
            kept = [r for r in s.get("reservations") or [] if r.get("mac", "").lower() != mac]
            if len(kept) != len(s.get("reservations") or []):
                s["reservations"] = kept
                save_vars(data)
                break
        else:
            raise ValidationError(f"no reservation for {mac}")
    write_audit(actor, "DHCP_UNRESERVE", f"mac={mac}", source)
