"""How a VLAN is named inside a site with locations (decision 2.1.10.49, manual 1.10.4.46): `<id>` for the DC's own
location, `<id>@<location>` for another; the small helpers every part of the plan shares."""
from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_dhcp import LABEL_RE


def check_location(text):
    """Purpose: a location's label checked (manual 1.10.4.46.1): one DNS label, lower case; "" is the DC's own.
    Inputs:  text — anything (None is "").
    Returns: str, the label or "".
    Fails:   ValidationError "location <text> is one DNS label (letters, digits, hyphens), e.g. branch".
    Feeds:   check_vlan, parse_vlan_ref, set_vlan (--to-location)."""
    out = str(text or "").strip().lower()
    if out and not LABEL_RE.match(out):
        raise ValidationError(f"location {text!r} is one DNS label (letters, digits, hyphens), e.g. branch")
    return out


def parse_vlan_ref(text):
    """Purpose: a VLAN named as typed: `10`, or `10@branch` for one at another location (manual 1.10.4.46.1).
    Inputs:  text — int or str.
    Returns: (int ID, location str: "" for the DC's own).
    Fails:   ValidationError: an ID that is not a number from 1 to 4094, a location that is not one DNS label.
    Feeds:   fields.find_vlan, ipam/cli/run_plan_change (vlan add), agent/post_networks."""
    vid, _, location = str(text if text is not None else "").strip().partition("@")
    try:
        number = int(vid)
    except ValueError:
        raise ValidationError(f"VLAN {text!r}: a VLAN ID, 1 to 4094, with @<location> for one at another location")
    if not 1 <= number <= 4094:
        raise ValidationError(f"VLAN {text!r}: a VLAN ID, 1 to 4094")
    return number, check_location(location)


def vlan_ref(vlan):
    """Purpose: how a VLAN of the plan is named: its key in AD (`CN=<site>/vlan/<ref>`) and in commands and routes.
    Inputs:  vlan — a VLAN of the plan ({"id", "location"}).
    Returns: str, "10" or "10@branch".
    Fails:   never.
    Feeds:   the plan's changes (add_vlan, set_vlan, remove_vlan), its views (networks_view, show_plan)."""
    location = vlan.get("location") or ""
    return f"{vlan['id']}@{location}" if location else str(vlan["id"])


def vlan_label(vlan):
    """Purpose: a VLAN as a message says it.
    Inputs:  vlan — {"id", "location"}.
    Returns: str, "VLAN 10" or "VLAN 10 at branch".
    Fails:   never.
    Feeds:   the plan's messages and views."""
    location = vlan.get("location") or ""
    return f"VLAN {vlan['id']}" + (f" at {location}" if location else "")


def of_vlan(subnet, vlan):
    """Purpose: whether a subnet of the plan is one of a VLAN's: its VLAN ID and its location both (two VLAN 10s may
             share a site, 1.10.4.46.1).
    Inputs:  subnet — a subnet of the plan ({"vlan", "location"}); vlan — a VLAN ({"id", "location"}).
    Returns: bool.
    Fails:   never.
    Feeds:   fields.find_vlan and the plan's views."""
    return subnet.get("vlan") == vlan["id"] and (subnet.get("location") or "") == (vlan.get("location") or "")


def subnet_base(vlan):
    """Purpose: the name a VLAN's first subnet takes (manual 1.10.4.46.1): the VLAN's name, or at another location
             `<location>-<VLAN name>`, since a subnet's name is unique in the whole site (cut to one DNS label).
    Inputs:  vlan — {"name", "location"}.
    Returns: str.
    Fails:   never.
    Feeds:   add_vlan, add_subnet."""
    location = vlan.get("location") or ""
    return f"{location}-{vlan['name']}"[:63].rstrip("-") if location else vlan["name"]
