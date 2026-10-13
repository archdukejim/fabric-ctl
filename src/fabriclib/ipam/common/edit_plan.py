from fabriclib.common.write_audit import write_audit
from fabriclib.federation.read_address_plan import read_address_plan
from fabriclib.ipam.common.plan_cache import save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.write_plan import write_plan
from fabriclib.secrets.load_secrets import load_secrets


def edit_plan(v, actor, site, event, change, secrets=None, container="samba", source="cli", networks=False):
    """Purpose: one change to a site's plan, the way every `fabricctl ipam` change makes it (manual 1.10.4.13): the
             site's plan read from the domain, the change checked against it (and, for a subnet, against every
             site's networks), written as the site's agent account, the plan read back and kept when it is this
             site's, and audited. A refusal writes nothing.
    Inputs:  v — fabric vars (site_name, fabric_subnet); actor — who asks (audit); site — the site whose plan changes
             ("" is this site); event — the audit event (e.g. "IPAM_VLAN_ADD"); change — function(plan, read,
             networks) -> (changes, result, audit detail str, warnings list); secrets — fabric's secrets (default
             load_secrets()); container — the DC's container; source — "cli" or "web"; networks — whether the change
             needs every site's networks (read_address_plan) for the overlap rule.
    Returns: {"result", "warnings", "done" (what the domain changed), "site"}.
    Fails:   ValidationError from the change (a rule, named), the reads or the write (the DC not answering, a site
             AD does not let this site's agent write: "not permitted for this site"); OSError from the audit log or
             the kept copy.
    Feeds:   add_vlan, set_vlan, remove_vlan, add_range, remove_range, add_address, set_address, remove_address."""
    secrets = secrets if secrets is not None else load_secrets()
    site = site or v["site_name"]
    read = read_plan(v, secrets, of=site, container=container)
    plan = site_plan(read, site)
    org = read_address_plan(v, secrets, container=container) if networks else []
    changes, result, detail, warnings = change(plan, read, org)
    done = write_plan(v, secrets, changes, container=container)
    if site == v["site_name"]:
        save_plan_cache(site_plan(read_plan(v, secrets, of=site, container=container), site))
    write_audit(actor, event, f"site={site} {detail}", source)
    return {"result": result, "warnings": warnings, "done": done, "site": site}
