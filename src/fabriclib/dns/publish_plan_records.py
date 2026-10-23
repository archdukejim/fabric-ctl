import os
import shutil
import tempfile

from fabriclib.common.errors import ValidationError
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
from fabriclib.dns.find_changed_zones import find_changed_zones
from fabriclib.dns.install_zone_file import install_zone_file
from fabriclib.dns.reload_zone import reload_zone
from fabriclib.dns.rndc import rndc
from fabriclib.dns_filter.deploy_resolver import deploy_resolver
from fabriclib.ipam.options.watch_state import save_watch_state
from fabriclib.secrets.load_secrets import load_secrets

SECRET_FILES = ("named.conf.keys", "rndc.key")


def _why(res):
    """Purpose: what an rndc call said when it failed.
    Inputs:  res — rndc()'s result (CompletedProcess or None).
    Returns: str: its stderr or stdout, "BIND did not answer (is bind9 running?)" for None.
    Fails:   never.
    Feeds:   publish_plan_records."""
    if res is None:
        return "BIND did not answer (is bind9 running?)"
    return (res.stderr or res.stdout or f"exit {res.returncode}").strip()


def _render(env, context, final_vars, reverse, out):
    """Purpose: BIND's configuration and every zone file, as an apply renders them (render_templates' BIND part): the
             configuration as text, the zone files into a folder of their own to compare with the deployed ones.
    Inputs:  env — the Jinja environment; context — the render context (check_rendered's, with the settings);
             final_vars — the checked settings (dns, domain); reverse — reverse_zones()'s result; out — the folder.
    Returns: {name: text} for BIND_CONFIG.
    Fails:   ValidationError naming the part that did not render (nothing deployed yet); OSError writing out.
    Feeds:   publish_plan_records."""
    try:
        conf = {name: env.get_template(f"bind9/config/{name}.j2").render(**context) for name in BIND_CONFIG}
        files = {}
        for key, records in (final_vars.get("dns") or {}).items():
            zone = final_vars["domain"] if key == "dynamic_zone_var" else key
            files[zone] = env.get_template("bind9/data/zone.j2").render(
                {**context, "zone_name": zone, "zone_records": records or {}})
        for zone, ptrs in reverse["zones"].items():
            files[zone] = env.get_template("bind9/data/reverse-zone.j2").render(
                **context, reverse_zone_name=zone, ptr_records=ptrs)
    except Exception as e:                  # any template error: say which part, nothing deployed
        raise ValidationError(f"BIND's records did not render, nothing changed: {e}")
    for zone, text in files.items():
        with open(os.path.join(out, f"db.{zone}"), "w") as f:
            f.write(text)
    return conf


def publish_plan_records(secrets=None, rndc_call=rndc, reload=reload_zone, resolver=deploy_resolver):
    """Purpose: the address plan's DNS put in front of the running BIND without an apply (Sync now, decision 2.1.10.29,
             manual 1.10.4.28.1), by the quick path `dns add-zone` takes (publish_zone_list, 2.1.10.21): the settings
             made whole and checked exactly as an apply does them (render_vars, check_rendered: the plan, the settings
             check, the reverse zones, the PTRs set by hand); BIND's configuration written, a new zone's file put in
             place and `rndc reconfig` when the zone list changed; each zone whose records changed swapped in under the
             running BIND (reload_zone: a dynamic zone frozen, swapped and thawed; a reverse zone keeps Kea's PTRs,
             2.1.10.7); the DNS filter's resolver re-rendered when the zone list changed. Nothing restarts. What DNS is
             rendered from is kept for the plan poll once BIND serves it (plan-dns.json, 2.3.10.5.6). The caller holds
             the settings' lock.
    Inputs:  secrets — fabric's secrets (default load_secrets(SECRETS_FILE)); rndc_call, reload, resolver — rndc,
             reload_zone and deploy_resolver (tests give their own). Reads vars.yaml, the address plan (from the DC, as
             an apply reads it), the federation registry, the templates and the deployed zone files.
    Returns: {"zones": the zones whose records changed (new ones included), "new": the zones BIND did not have,
             "config" (bool: the zone list or its keys and ACLs changed), "resolver" (bool: re-rendered)}.
    Fails:   ValidationError, before anything is written: a TSIG key apply has not made yet, settings the apply's check
             refuses, templates that do not render. After files are written: BIND refusing `rndc reconfig` or not
             serving a new zone (plan-dns.json is then left as it was, so the poll still says DNS waits); the resolver
             not taking its configuration (BIND serves the records by then). OSError writing files.
    Feeds:   ipam/sync/sync_plan."""
    paths = deploy_paths()
    custom_vars = load_vars()
    secrets = secrets if secrets is not None else load_secrets(SECRETS_FILE)
    if merge_tsig_keys(custom_vars, secrets)[1]:
        raise ValidationError("a TSIG key in the settings has no secret yet: run an apply first (it makes and saves "
                              "it)")
    env = jinja_env_for(paths["jinja"])
    try:                                    # as an apply: the plan, the settings check, the zone-list context
        final_vars, context = render_vars(env, secrets, custom_vars)
        checked = check_rendered(final_vars, secrets, context, FEDERATION_FILE)
    except ValidationError as e:
        raise ValidationError(f"the settings do not pass the apply's check, nothing changed: {e}")
    context.update(final_vars)
    uid, gid = service_user(final_vars, "bind")
    base = final_vars["deploy_base_dir"]
    config, data = os.path.join(base, "bind9", "config"), os.path.join(base, "bind9", "data")
    out = tempfile.mkdtemp(prefix="fabric-sync-")
    try:
        conf = _render(env, context, final_vars, checked["reverse"], out)
        changed = find_changed_zones(out, data)
        new = [c for c in changed if not os.path.exists(c[2])]
        config_changed = False
        for name, text in conf.items():     # the keys and rndc's key are secrets: 0600 (install_bind9_files)
            if write_file_if_changed(os.path.join(config, name), text, 0o600 if name in SECRET_FILES else 0o640, uid,
                                     gid):
                config_changed = True
        for _zone, src, dst in new:         # a new zone's file first: BIND loads it at the reconfig
            install_zone_file(src, dst, uid, gid)
        if config_changed:
            res = rndc_call(["reconfig"], timeout=60)
            if res is None or res.returncode != 0:
                raise ValidationError(f"BIND did not take the new zone list: {_why(res)}")
        for zone, src, dst in changed:
            if (zone, src, dst) not in new:
                reload(zone, src, dst, uid, gid)
        for zone, _src, _dst in new:
            status = rndc_call(["zonestatus", zone])
            if status is None or status.returncode != 0:
                raise ValidationError(f"BIND does not serve {zone}: {_why(status)}")
    finally:
        shutil.rmtree(out, ignore_errors=True)
    if checked["dns_digest"] is not None:  # BIND serves this plan's names now: the poll may count DNS current
        save_watch_state("plan-dns", {"dns": checked["dns_digest"]})
    done = {"zones": [z for z, _, _ in changed], "new": [z for z, _, _ in new], "config": config_changed,
            "resolver": False}
    if config_changed and final_vars.get("install_resolver"):
        try:
            r = resolver(final_vars, secrets, context["federation_links"], env)
        except Exception as e:              # its settings or its files: say so
            raise ValidationError(f"BIND serves the plan's records, but the DNS filter's configuration did not render: "
                                  f"{e}")
        if r["config"] and not r["reconfigured"]:
            raise ValidationError("BIND serves the plan's records, but the DNS filter's resolver did not reload its "
                                  "configuration (is it running?)")
        done["resolver"] = True
    return done
