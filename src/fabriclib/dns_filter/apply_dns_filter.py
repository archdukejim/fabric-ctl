from fabriclib.common.errors import ValidationError
from fabriclib.common.jinja_env import jinja_env as jinja_env_for
from fabriclib.common.load_vars import load_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.deploy.render_vars import render_vars
from fabriclib.dns_filter.deploy_resolver import deploy_resolver
from fabriclib.dns_filter.sync_adguard import sync_adguard
from fabriclib.federation.dns_links import dns_links
from fabriclib.secrets.load_secrets import load_secrets


def apply_dns_filter(actor, source="web"):
    """Purpose: make a DNS filter change from the console where it lives, in seconds, instead of a full apply (manual
             1.12.3.8): the settings rendered from vars.yaml, the resolver's configuration and rules zones written and
             reloaded (rndc), AdGuard Home made to match through its API. Nothing restarts.
    Inputs:  actor — who asked (audit); source — "web" (default) or "cli".
    Returns: {"resolver": deploy_resolver's result, "adguard": sync_adguard's changes or None, "waiting": None, or why
             the change waits for the next apply (AdGuard not answering, or no apply has run yet)}.
    Fails:   ValidationError when the settings do not render or are refused (check_filter_settings), or fabric's
             secrets cannot be read (OpenBao locked); OSError and jinja2 errors writing the resolver's files.
    Feeds:   agent/post_dns_filter (every change), dns_filter/run_dns_filter_command (`fabricctl dns-filter apply`)."""
    paths = deploy_paths()
    with vars_lock():
        secrets = load_secrets(paths["secrets"])
        if "adguard_api_password" not in secrets:
            write_audit(actor, "DNS_FILTER_APPLY", "waits for an apply", source)
            return {"resolver": None, "adguard": None,
                    "waiting": "no apply has run yet: run sudo fabricctl --apply"}
        jinja_env = jinja_env_for(paths["jinja"])
        final_vars, _ = render_vars(jinja_env, secrets, load_vars(paths["vars"]))
        if not final_vars.get("install_resolver"):
            raise ValidationError("the DNS filter is off (dns_filter: none)")
        links = dns_links(final_vars, secrets, paths["federation"])
        resolver = deploy_resolver(final_vars, secrets, links, jinja_env)
        adguard, waiting = None, None
        try:
            adguard = sync_adguard(final_vars, secrets["adguard_api_password"])
        except ValidationError as e:
            waiting = f"{e}; the change is saved and AdGuard takes it when it answers again (or at the next apply)"
    res = "reloaded" if resolver["reconfigured"] else "unchanged" if not resolver["config"] else "NOT reloaded"
    ag = ", ".join(adguard) if adguard else "unchanged" if adguard is not None else "waiting"
    write_audit(actor, "DNS_FILTER_APPLY", f"resolver {res}; AdGuard {ag}", source)
    return {"resolver": resolver, "adguard": adguard, "waiting": waiting}
