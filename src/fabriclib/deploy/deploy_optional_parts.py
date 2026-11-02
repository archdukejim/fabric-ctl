import shutil

from fabriclib.common.service_user import service_user
from fabriclib.consent.allowed_to_change import allowed_to_change
from fabriclib.consent.plan_time import plan_time
from fabriclib.dhcp.deploy_kea import deploy_kea
from fabriclib.dns_filter.deploy_adguard import deploy_adguard
from fabriclib.dns_filter.deploy_resolver import deploy_resolver
from fabriclib.dns_filter.update_lists import update_lists
from fabriclib.logs.deploy_fluentbit import deploy_fluentbit
from fabriclib.logs.fluentbit_pending import fluentbit_pending
from fabriclib.ntp.deploy_chrony import deploy_chrony
from fabriclib.radius.deploy_freeradius import deploy_freeradius
from fabriclib.samba.deploy_samba import deploy_samba


def deploy_optional_parts(paths, final_vars, secrets, jinja_env, links):
    """Purpose: the parts with a deploy step of their own: Fluent Bit (left to setup's start step while fabric's root
             CA is not made yet, fluentbit_pending), the DNS filter (the BIND resolver and AdGuard
             Home behind it), time
             (chrony), Kea, FreeRADIUS and the Windows domain — each only when it is on (chrony whenever it is
             installed and the `time` host change is approved — manual 1.2.9; an install set up before consent
             existed keeps converging).
    Inputs:  paths — deploy_paths() (federation, config); final_vars — rendered settings; secrets; jinja_env; links —
             dns_links() (the linked sites' zones, which the resolver forwards to BIND).
    Returns: {"restart": set of units to restart, "kea": the names of Kea's files that changed (deploy_kea's: the
             apply reloads them, 2.1.10.45)}.
    Fails:   whatever the parts' deploy functions raise (ValidationError, OSError, CalledProcessError).
    Feeds:   apply_deployment."""
    restart = set()
    # Fluent Bit (optional): its config, destination CAs, credentials, disk buffer; on a fresh install the root CA
    # its destinations are verified with is made later (the PKI step), so setup's start step deploys it then
    if fluentbit_pending(final_vars):
        print("  Fluent Bit: deployed once fabric's root CA is made (setup's start step, after the PKI step)")
    elif final_vars.get("install_fluentbit") and deploy_fluentbit(final_vars, secrets, jinja_env):
        restart.add("fluentbit")
    # DNS filter (manual 1.12.2, 1.12.3): a site's list with no copy yet fetched now (the apply has the internet);
    # the resolver's config and rules zones (a running resolver reloads what changed); AdGuard Home's file, or its API
    # when only what the API changes differs: restarted only for a change outside it
    if final_vars.get("install_resolver"):
        update_lists(final_vars, only_missing=True)
        deploy_resolver(final_vars, secrets, links, jinja_env)
        adguard = deploy_adguard(final_vars, secrets, jinja_env)
        if adguard["restart"]:
            restart.add("adguard-filter")
        if adguard["error"]:
            print(f"  DNS filter: AdGuard Home not made to match yet ({adguard['error']}): it reads its file when it "
                  "answers again")
    # Time (manual 1.13.1): chrony on the host, the upstream site first; installed by setup's host step
    if shutil.which("chronyd"):
        if not allowed_to_change(paths["config"], "time", plan_time(), unasked_install=True):
            print("  time: chrony left as it is (the `time` host change is not approved; "
                  "`sudo fabricctl setup --approve time` allows it)")
        elif deploy_chrony(final_vars, paths["federation"], jinja_env, config_dir=paths["config"]):
            print("  time: chrony configuration updated")
    # Kea (optional): its configs and the DHCP subzone, created once; a changed file is reloaded, not restarted
    kea = set()
    if final_vars.get("install_kea"):
        kea = deploy_kea(final_vars, secrets, jinja_env, *service_user(final_vars, "bind"))
    # FreeRADIUS (optional): config with the client secrets, fabric's policy code, CA bundle
    if final_vars.get("install_freeradius") and deploy_freeradius(final_vars, secrets, jinja_env):
        restart.add("freeradius")
    # the directory (Samba AD, every install): the Administrator's password file (read only when provisioning),
    # the converge code, its resolver (a change restarts it)
    if deploy_samba(final_vars, secrets, jinja_env)["restart"]:
        restart.add("samba")
    return {"restart": restart, "kea": kea}
