from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.federation.read_address_plan import read_address_plan
from fabriclib.ipam.common.plan_cache import save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.write_plan import write_plan
from fabriclib.samba.writable_server import writable_server
from fabriclib.secrets.load_secrets import load_secrets


def edit_plan(v, actor, site, event, change, secrets=None, container="samba", source="cli", networks=False,
              caller=None, right="plan"):
    """Purpose: one change to a site's plan, the way every `fabricctl ipam` change makes it (manual 1.10.4.16,
             1.10.4.33, 1.10.4.34): fabric-agent's check first (the caller holds the networks right at the site,
             1.6.13.12), then the site's plan read from the domain, the change checked against it (and, for a subnet,
             against every site's networks), written as this DC's agent account (at a read-only DC's site, at its
             writable DC, 2.1.6.52, where it is read too), the plan read back and kept when it is this site's, and
             audited with this DC, the site and what allowed it (1.10.4.34). A refusal writes nothing.
    Inputs:  v — fabric vars (site_name, dc_name, fabric_subnet, ad_dc_type, ad_join_server); actor — who asks (audit);
             site — the site whose plan changes ("" is this site); event — the audit event (e.g. "IPAM_VLAN_ADD");
             change — function(plan, read, networks) -> (changes, result, audit detail str, warnings list); secrets —
             fabric's secrets (default load_secrets()); container — the DC's container; source — "cli" or "web";
             networks — whether the change needs every site's networks (read_address_plan) for the overlap rule;
             caller — the signed-in person's user name, or None (root, acting for the Enterprise Admin); right — the
             networks right the change needs ("plan" or "options").
    Returns: {"result", "warnings", "done" (what the domain changed), "site"}.
    Fails:   ValidationError: no domain yet (no ad_agent_password); from check_access ("no grant gives you networks
             plan at <site>"); from the change (a rule, named); from the reads ("no such site") or the write (the DC
             not answering; a read-only DC with no writable DC known). OSError from the audit log or the kept copy.
    Feeds:   add_vlan, set_vlan, remove_vlan, add_subnet, set_subnet, remove_subnet, add_range, remove_range,
             add_address, set_address, remove_address, set_block."""
    secrets = secrets if secrets is not None else load_secrets()
    if not secrets.get("ad_agent_password"):           # no domain yet: say so before anything asks the DC
        raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")
    site = site or v["site_name"]
    allowed = check_access(v, caller, f"networks:{right}", {"site": site}, container)
    server = writable_server(v, "write the address plan at")
    read = read_plan(v, secrets, of=site, container=container, server=server)
    plan = site_plan(read, site)
    org = read_address_plan(v, secrets, container=container) if networks else []
    changes, result, detail, warnings = change(plan, read, org)
    done = write_plan(v, secrets, changes, container=container, server=server)
    if site == v["site_name"]:
        save_plan_cache(site_plan(read_plan(v, secrets, of=site, container=container, server=server), site))
    by = f"from={v.get('dc_name') or v['site_name']} site={site} by={allowed['by']}"
    write_audit(actor, event, f"{by} {detail}", source)
    return {"result": result, "warnings": warnings, "done": done, "site": site}
