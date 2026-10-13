from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.plan_cache import save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.options.write_server import write_server
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.write_plan import write_plan
from fabriclib.secrets.load_secrets import load_secrets


def edit_options(v, actor, site, event, change, secrets=None, container="samba", source="cli"):
    """Purpose: one change to the DHCP options in the plan (decision 2.1.10.23, manual 1.10.4.24.2): the site's plan and
             the option sets read, the change checked against them, written as this site's agent at a writable DC
             (this site's, or a read-only DC's writable partner: write_server), the plan read back and kept when it is
             this site's, and audited with the person, this site and the scope. A refusal writes nothing.
    Inputs:  v — fabric vars (site_name, ad_dc_type, ad_join_server); actor — who asks (audit); site — the site whose
             plan the change is about ("" is this site; the organisation's set is read with any site's); event — the
             audit event (e.g. "IPAM_OPTION_SET"); change — function(plan) -> (write_plan changes, result, audit detail
             str, warnings list); secrets — fabric's secrets (default load_secrets()); container — the DC's
             container; source — "cli" or "web".
    Returns: {"result", "warnings", "done" (what the domain changed), "site"}.
    Fails:   ValidationError from the change (a rule, named), write_server (a read-only DC with no writable partner),
             the reads or the write (the DC not answering; AD refusing: "not permitted for this site", the
             organisation's set from a site the top has not added); OSError from the audit log or the kept copy.
    Feeds:   set_plan_option, remove_plan_option, define_plan_option, undefine_plan_option, add_plan_class,
             remove_plan_class, set_netboot, clear_netboot."""
    secrets = secrets if secrets is not None else load_secrets()
    here = v["site_name"]
    site = site or here
    plan = site_plan(read_plan(v, secrets, of=site, container=container), site)
    changes, result, detail, warnings = change(plan)
    done = write_plan(v, secrets, changes, container=container, server=write_server(v))
    if site == here:
        save_plan_cache(site_plan(read_plan(v, secrets, of=site, container=container), site))
    write_audit(actor, event, f"from={here} site={site} {detail}", source)
    return {"result": result, "warnings": warnings, "done": done, "site": site}
