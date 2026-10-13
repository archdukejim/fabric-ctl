from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan


def check_role_vlan(v, vlan, plan=None, secrets=None):
    """Purpose: a device role's VLAN names a VLAN of this site's address plan (manual 1.10.4.5, 1.11.1.8): when the
             plan has VLANs, the role's must be one of them; a site whose plan has none yet keeps bare numbers.
    Inputs:  v — fabric vars (site_name); vlan — int or None (check_role_fields' value); plan — this site's plan
             (site_plan's shape; tests), default read from the DC (read_plan); secrets — fabric's secrets for that
             read (the caller's, default load_secrets()).
    Returns: None (no VLAN, a plan VLAN, or a plan without VLANs).
    Fails:   ValidationError "VLAN <n> is not in <site>'s address plan (its VLANs: …): add it with
             `fabricctl ipam vlan add` first, or choose one of them"; read_plan's errors (the DC not answering: the
             save refuses too, failing loudly).
    Feeds:   add_role, update_role."""
    if not vlan:
        return
    if plan is None:
        plan = site_plan(read_plan(v, secrets, of=v["site_name"]), v["site_name"])
    ids = [x["id"] for x in plan.get("vlans") or []]
    if not ids or vlan in ids:
        return
    names = ", ".join(f"{x['id']} ({x['name']})" if x.get("name") else str(x["id"]) for x in plan["vlans"])
    raise ValidationError(f"VLAN {vlan} is not in {plan.get('site') or v['site_name']}'s address plan (its VLANs: "
                          f"{names}): add it with `fabricctl ipam vlan add` first, or choose one of them")
