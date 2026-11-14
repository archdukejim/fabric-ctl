import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.rules.rule_networks import rule_networks
from fabriclib.ipam.rules.seed_rules import seed_rules


def seed_site_rules(v, plan, secrets=None, container="samba"):
    """Purpose: an upgraded site's rules written once, at its first apply (manual 1.10.4.48.7, decision 2.1.10.59):
             only on positive evidence, a plan with VLANs and no rule kept; what they keep is what each VLAN reached
             before (seed_rules). A fresh site (no VLAN) and a site with rules are left alone.
    Inputs:  v — rendered vars (site_name); plan — this site's plan as just read (site_plan's); secrets, container —
             as edit_plan.
    Returns: list of str to show: the rules written, or why they could not be (the apply goes on with the same rules
             enforced from the plan, effective_rules); [] when there was nothing to do.
    Fails:   never: a refusal or a DC that does not answer is reported in the lines.
    Feeds:   ipam/load_address_plan."""
    if not plan or plan.get("rules_kept") or not plan.get("vlans"):
        return []
    rules = seed_rules(plan, rule_networks(v, plan)["host_vlan"])

    def change(_plan, read, org):
        text = " | ".join(f"from {r['from']} service {r['service']} {r['action']}" for r in rules)
        return ([{"do": "set", "what": "rules", "site": plan["site"], "fields": {"rules": rules}}],
                {"rules": rules}, f"rules={text}", [])
    try:
        edit_plan(v, "root", plan["site"], "IPAM_RULES_SEEDED", change, secrets, container)
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:
        return [f"access rules: not written yet ({e}); the site keeps what its VLANs reached until they are"]
    return ["access rules: written once, keeping what each VLAN reached before 0.9.6 (2.1.10.59):"] + [
        f"  {n} from {r['from']} service {r['service']} {r['action']}" for n, r in enumerate(rules, 1)]
