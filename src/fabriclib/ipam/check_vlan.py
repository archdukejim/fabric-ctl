from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import LABEL_RE
from fabriclib.ipam.common.fields import ACCESS, notes, one_line


def check_vlan(vlan, plan, current=None):
    """Purpose: a VLAN of a site's plan checked against the model's rules (manual 1.10.4.3): an ID from 1 to 4094 and a
             name, each unique in the site; purpose and notes; access full or guest (1.10.3.3).
    Inputs:  vlan — {"id", "name", "purpose", "access", "notes"}; plan — the site's plan (read_plan: "vlans");
             current — the ID of the VLAN being changed (it may keep its own name), None for a new one.
    Returns: the VLAN normalized: {"id" (int), "name" (lower-case label), "purpose", "access", "notes"}.
    Fails:   ValidationError: an ID that is not 1-4094 or already the site's (naming its VLAN), a name that is not one
             DNS label or is another VLAN's, a purpose over one line of 200 characters, notes over 500, an access
             other than full or guest.
    Feeds:   add_vlan, set_vlan, move_subnets_to_plan (through subnets_to_plan)."""
    vid = vlan.get("id")
    if isinstance(vid, bool) or not isinstance(vid, int) or not 1 <= vid <= 4094:
        raise ValidationError(f"VLAN ID {vid!r} is a number from 1 to 4094")
    name = str(vlan.get("name") or "").strip().lower()
    if not LABEL_RE.match(name):
        raise ValidationError(f"VLAN name {vlan.get('name')!r} is one DNS label (letters, digits, hyphens), e.g. iot")
    for other in plan.get("vlans") or []:
        if other["id"] == current:
            continue
        if other["id"] == vid:
            raise ValidationError(f"VLAN {vid} is already in this site's plan ({other['name']})")
        if other["name"] == name:
            raise ValidationError(f"the name {name} is already VLAN {other['id']}'s in this site")
    access = str(vlan.get("access") or "full").strip().lower()
    if access not in ACCESS:
        raise ValidationError("access is full (fabric's services, the default) or guest (DNS and NTP only)")
    return {"id": vid, "name": name, "purpose": one_line(vlan.get("purpose"), "purpose"), "access": access,
            "notes": notes(vlan.get("notes"))}
