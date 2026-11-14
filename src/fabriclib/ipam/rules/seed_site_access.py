import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.rules.access_table import access_table
from fabriclib.ipam.rules.constants import SERVICES
from fabriclib.ipam.rules.rule_networks import rule_networks


def seed_site_access(v, plan, secrets=None, container="samba"):
    """Purpose: an upgraded site's access table written once, at its first apply (manual 1.10.4.48.10, decision
             2.1.10.59): only on positive evidence, a plan with VLANs and nothing kept; what it keeps is what each VLAN
             reached before (access_table's seed). A fresh site (no VLAN) and a site with a table are left alone.
    Inputs:  v — rendered vars (site_name); plan — this site's plan as just read (site_plan's); secrets, container —
             as edit_plan.
    Returns: list of str to show: the table written, or why it could not be (the apply goes on with the same table
             enforced from the plan); [] when there was nothing to do.
    Fails:   never: a refusal or a DC that does not answer is reported in the lines.
    Feeds:   ipam/load_address_plan."""
    if not plan or plan.get("rules_kept") or not plan.get("vlans"):
        return []
    host = rule_networks(v, plan)["host_vlan"]
    table = access_table(plan, host)
    defaults = access_table({**plan, "rules": [], "rules_kept": True}, host)
    rows = [{"net": k, **table[k]} for k in table if table[k] != defaults[k]]

    def said(row):
        return ", ".join(s for s in SERVICES if row[s] == "allow") or "nothing"

    def change(_plan, read, org):
        return ([{"do": "set", "what": "rules", "site": plan["site"], "fields": {"rules": rows}}],
                {"rules": rows}, "access=" + " | ".join(f"{r['net']}: {said(r)}" for r in rows), [])
    try:
        edit_plan(v, "root", plan["site"], "IPAM_RULES_SEEDED", change, secrets, container)
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:
        return [f"access: not written yet ({e}); the site keeps what its VLANs reached until it is"]
    return ["access: written once, keeping what each VLAN reached before 0.10.0 (2.1.10.59):"] + [
        f"  VLAN {r['net']}: {said(r)}" for r in rows]
