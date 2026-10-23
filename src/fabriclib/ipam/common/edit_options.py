from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.plan_cache import save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.write_plan import write_plan
from fabriclib.samba.writable_server import writable_server
from fabriclib.secrets.load_secrets import load_secrets


def edit_options(v, actor, site, event, change, secrets=None, container="samba", source="cli", caller=None,
                 domain=False):
    """Purpose: one change to the DHCP options in the plan (decision 2.1.10.23, manual 1.10.4.24.2), made the way
             edit_plan makes a plan change: fabric-agent's check first (the caller holds networks options at the site,
             or at every site for the domain's set, 1.6.13.12), then the site's plan and the option sets read, the
             change checked against them, written as this DC's agent account (at a read-only DC's site, at its writable
             DC, 2.1.6.52, where it is read too), the plan read back and kept when it is this site's, and audited with
             the person, this DC, the site, the scope and what allowed it (1.10.4.34). A refusal writes nothing.
    Inputs:  v — fabric vars (site_name, dc_name, ad_dc_type, ad_join_server); actor — who asks (audit); site — the site
             whose plan the change is about ("" is this site; the domain's set is read with any site's); event — the
             audit event (e.g. "IPAM_OPTION_SET"); change — function(plan) -> (write_plan changes, result, audit detail
             str, warnings list); secrets — fabric's secrets (default load_secrets()); container — the DC's container;
             source — "cli" or "web"; caller — the signed-in person's user name, or None (root, acting for the
             Enterprise Admin); domain — whether the change writes the domain's set (checked at `all`).
    Returns: {"result", "warnings", "done" (what the domain changed), "site"}.
    Fails:   ValidationError: no domain yet (no ad_agent_password); from check_access ("no grant gives you networks
             options at <site>", or at all sites for the domain's set); from the change (a rule, named); from the
             reads or the write (the DC not answering; a read-only DC with no writable DC known). OSError from the
             audit log or the kept copy.
    Feeds:   set_plan_option, remove_plan_option, define_plan_option, undefine_plan_option, add_plan_class,
             remove_plan_class, set_netboot, clear_netboot."""
    secrets = secrets if secrets is not None else load_secrets()
    if not secrets.get("ad_agent_password"):           # no domain yet: say so before anything asks the DC
        raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")
    here = v["site_name"]
    site = site or here
    allowed = check_access(v, caller, "networks:options", {"site": "all" if domain else site}, container)
    server = writable_server(v, "write the DHCP options at")
    plan = site_plan(read_plan(v, secrets, of=site, container=container, server=server), site)
    changes, result, detail, warnings = change(plan)
    done = write_plan(v, secrets, changes, container=container, server=server)
    if site == here:
        save_plan_cache(site_plan(read_plan(v, secrets, of=site, container=container, server=server), site))
    write_audit(actor, event, f"from={v.get('dc_name') or here} site={site} by={allowed['by']} {detail}", source)
    return {"result": result, "warnings": warnings, "done": done, "site": site}
