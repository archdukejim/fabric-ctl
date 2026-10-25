from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import LABEL_RE
from fabriclib.ipam.common.fields import ACCESS, notes, one_line
from fabriclib.ipam.common.vlan_refs import check_location


def check_vlan(vlan, plan, current=None):
    """Purpose: a VLAN of a site's plan checked against the model's rules (manual 1.10.4.3, 1.10.4.46.1): an ID from 1
             to 4094 and a name, each unique in the site and location (a location without a DC is labelled inside
             the site that serves it, 2.1.10.49; "" is the DC's own); purpose and notes; access full or guest
             (1.10.3.3).
    Inputs:  vlan — {"id", "location" (optional), "name", "purpose", "access", "notes"}; plan — the site's plan
             (read_plan: "vlans"); current — the VLAN being changed, as (ID, location) or its ID alone at the DC's own
             location (it may keep its own ID and name), None for a new one.
    Returns: the VLAN normalized: {"id" (int), "location" (label or ""), "name" (lower-case label), "purpose",
             "access", "notes"}.
    Fails:   ValidationError: an ID that is not 1-4094 or already one of the location's (naming its VLAN), a name that
             is not one DNS label or is another VLAN's at the location, a location that is not one DNS label, a
             purpose over one line of 200 characters, notes over 500, an access other than full or guest.
    Feeds:   add_vlan, set_vlan, add_dhcp_subnet, move_subnets_to_plan (through subnets_to_plan)."""
    vid = vlan.get("id")
    if isinstance(vid, bool) or not isinstance(vid, int) or not 1 <= vid <= 4094:
        raise ValidationError(f"VLAN ID {vid!r} is a number from 1 to 4094")
    location = check_location(vlan.get("location"))
    name = str(vlan.get("name") or "").strip().lower()
    if not LABEL_RE.match(name):
        raise ValidationError(f"VLAN name {vlan.get('name')!r} is one DNS label (letters, digits, hyphens), e.g. iot")
    if current is not None and not isinstance(current, tuple):
        current = (current, "")
    at = f" at {location}" if location else ""
    for other in plan.get("vlans") or []:
        key = (other["id"], other.get("location") or "")
        if key == current or key[1] != location:
            continue
        if other["id"] == vid:
            raise ValidationError(f"VLAN {vid}{at} is already in this site's plan ({other['name']})")
        if other["name"] == name:
            raise ValidationError(f"the name {name} is already VLAN {other['id']}'s" + (at or " in this site"))
    access = str(vlan.get("access") or "full").strip().lower()
    if access not in ACCESS:
        raise ValidationError("access is full (fabric's services, the default) or guest (DNS and NTP only)")
    return {"id": vid, "location": location, "name": name, "purpose": one_line(vlan.get("purpose"), "purpose"),
            "access": access, "notes": notes(vlan.get("notes"))}
