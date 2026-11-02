import os

from fabriclib.common.errors import NotPublished, ValidationError
from fabriclib.common.jinja_env import jinja_env as jinja_env_for
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import FEDERATION_FILE, SECRETS_FILE
from fabriclib.common.service_user import service_user
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.deploy.check_rendered import check_rendered
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.deploy.merge_tsig_keys import merge_tsig_keys
from fabriclib.deploy.render_templates import BIND_CONFIG
from fabriclib.deploy.render_vars import render_vars
from fabriclib.dns.rndc import rndc
from fabriclib.dns_filter.deploy_resolver import deploy_resolver
from fabriclib.dns_filter.flush_published_names import flush_published_names
from fabriclib.ipam.options.watch_state import save_watch_state
from fabriclib.secrets.load_secrets import load_secrets

SECRET_FILES = ("named.conf.keys", "rndc.key")


def _why(res):
    """Purpose: what an rndc call said when it failed.
    Inputs:  res — rndc()'s result (CompletedProcess or None).
    Returns: str: its stderr or stdout, "BIND did not answer (is bind9 running?)" for None.
    Fails:   never.
    Feeds:   publish_zone_list."""
    if res is None:
        return "BIND did not answer (is bind9 running?)"
    return (res.stderr or res.stdout or f"exit {res.returncode}").strip()


def publish_zone_list(added=(), removed=()):
    """Purpose: put the vars' forward zones in front of the running BIND in seconds, not an apply (manual 1.4.1.3):
             render BIND's configuration as apply does (the zone list, and the keys and ACLs it names) and the added
             zones' files into the deploy base, `rndc reconfig`, check BIND serves each added zone, delete the removed
             zones' files and journals; then, when the DNS filter is installed, render and reload the resolver's
             configuration (its forward zones), through deploy_resolver, and make it forget what it cached for
             the added and removed zones (flush_published_names, 2.1.4.9). Nothing restarts. The settings are made
             whole and checked exactly as an apply does them (check_rendered, decisions 2.1.4.7 and 2.1.10.21): the
             address plan, the settings check, so the zone list keeps DHCP's reverse zones, Kea's grants and the
             denies on PTRs set by hand between applies.
    Inputs:  added — zone names whose file is written (a new zone: its SOA, NS and ns record); removed — zone names
             whose files go once BIND has dropped them. Reads vars.yaml, fabric's secrets (read only: nothing is
             generated or saved here), the address plan (read from the DC as an apply reads it, and kept), the
             federation registry and the templates; the caller holds vars_lock.
    Returns: {"bind": True, "resolver": True when the resolver was rendered (installed), else False, "flushed": how
             many zones the resolver forgot, "flush_error": why it did not, or None (a warning: the zone is
             published either way)}.
    Fails:   NotPublished (a ValidationError) saying why, before any file is written: a TSIG key whose secret apply
             has not made yet, settings the apply's check refuses or that do not render; the caller rolls back the
             vars and has nothing to publish again. ValidationError once files are written: secrets that cannot be
             read (OpenBao locked), BIND refusing `rndc reconfig` or not serving an added zone, the resolver not
             taking its configuration; OSError writing the files. The caller rolls back the vars and calls it
             again.
    Feeds:   dns/add_zone, dns/remove_zone (and their rollback)."""
    paths = deploy_paths()
    custom_vars = load_vars()
    secrets = load_secrets(SECRETS_FILE)
    if merge_tsig_keys(custom_vars, secrets)[1]:
        raise NotPublished("a TSIG key in the settings has no secret yet: run an apply first "
                           "(it makes and saves it)")
    jinja_env = jinja_env_for(paths["jinja"])
    try:                                    # as an apply: the plan, the settings check, the zone-list context
        final_vars, context = render_vars(jinja_env, secrets, custom_vars)
        checked = check_rendered(final_vars, secrets, context, FEDERATION_FILE)
    except ValidationError as e:
        raise NotPublished(f"the settings do not pass the apply's check, nothing changed: {e}")
    context.update(final_vars)
    uid, gid = service_user(final_vars, "bind")
    base = final_vars["deploy_base_dir"]
    config, data = os.path.join(base, "bind9", "config"), os.path.join(base, "bind9", "data")

    try:
        # all of BIND's configuration, as apply renders it: the zone list names keys and ACLs that must exist
        conf = {name: jinja_env.get_template(f"bind9/config/{name}.j2").render(**context) for name in BIND_CONFIG}
        files = {}
        for key, records in (final_vars.get("dns") or {}).items():
            zone = final_vars["domain"] if key == "dynamic_zone_var" else key
            if zone in added:
                files[zone] = jinja_env.get_template("bind9/data/zone.j2").render(
                    {**context, "zone_name": zone, "zone_records": records or {}})
    except Exception as e:                  # any template error: say which part
        raise NotPublished(f"BIND's zone configuration did not render: {e}")
    for zone, text in files.items():
        dst = os.path.join(data, f"db.{zone}")
        for stale in (dst + ".jnl", dst + ".jbk"):
            if os.path.exists(stale):
                os.remove(stale)
        write_file_if_changed(dst, text, 0o640, uid, gid)
    for name, text in conf.items():         # the keys and rndc's key are secrets: 0600 (install_bind9_files)
        write_file_if_changed(os.path.join(config, name), text, 0o600 if name in SECRET_FILES else 0o640, uid, gid)
    res = rndc(["reconfig"], timeout=60)
    if res is None or res.returncode != 0:
        raise ValidationError(f"BIND did not take the new zone list: {_why(res)}")
    for zone in files:
        status = rndc(["zonestatus", zone])
        if status is None or status.returncode != 0:
            raise ValidationError(f"BIND does not serve {zone}: {_why(status)}")
    for zone in removed:
        for suffix in ("", ".jnl", ".jbk"):
            path = os.path.join(data, f"db.{zone}{suffix}")
            if os.path.exists(path):
                os.remove(path)
    if checked["dns_digest"] is not None:  # BIND serves this plan's names now: the poll may count DNS current
        save_watch_state("plan-dns", {"dns": checked["dns_digest"]})

    if not final_vars.get("install_resolver"):
        return {"bind": True, "resolver": False, "flushed": 0, "flush_error": None}
    try:
        r = deploy_resolver(final_vars, secrets, context["federation_links"], jinja_env)
    except Exception as e:                  # its settings or its files: say so, the caller rolls back
        raise ValidationError(f"the DNS filter's configuration did not render: {e}")
    if r["config"] and not r["reconfigured"]:
        raise ValidationError("the DNS filter's resolver did not reload its configuration (is it running?)")
    # a name asked before its zone was added was answered NXDOMAIN from the internet (cached for hours), a removed
    # zone's names from BIND: the resolver forgets the whole zone (2.1.4.9); a flush that fails is a warning
    flushed = flush_published_names(final_vars, {"trees": sorted(set(added) | set(removed)), "names": []})
    return {"bind": True, "resolver": True, "flushed": flushed["flushed"], "flush_error": flushed["error"]}
