import json
import os
import subprocess
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.ipam.common.plan_cache import save_plan_cache
from fabriclib.ipam.common.plan_holds_subnets import plan_holds_subnets
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.options.check_option_set import check_option_set
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.write_plan import write_plan
from fabriclib.samba.writable_server import writable_server

KEYS = ("options", "option_defs", "client_classes")


def _carry(have, moving, key_of):
    """Purpose: one list moved into the site's set: the set's entries kept, the settings' added where the set has none
             of the same identity.
    Inputs:  have — the set's list; moving — the settings' list; key_of — function(entry) -> identity.
    Returns: (merged list, list of the settings' entries not carried).
    Fails:   never.
    Feeds:   move_options_to_plan."""
    keys = {key_of(x) for x in have}
    carried = [x for x in moving if key_of(x) not in keys]
    return list(have) + carried, [x for x in moving if key_of(x) in keys]


def move_options_to_plan(v, secrets, container="samba"):
    """Purpose: the upgrade of the global DHCP options (decision 2.1.10.23, manual 1.10.4.24.4), run after
             move_subnets_to_plan at every apply (1.10.4.37): once the site's subnets live in the plan and vars.yaml
             still carries dhcp.options, dhcp.option_defs or dhcp.client_classes, they move into the site's option set
             in the domain (what the set already holds keeps the set's: "not carried"), the record
             <config>/ipam-options-upgrade-<time>.json (0600) is written, and vars.yaml loses them. Idempotent: settings
             without them change nothing. Until moved they are served above the site's set, so nothing a running site
             serves changes.
    Inputs:  v — rendered settings (site_name, ad_dc_type, ad_join_server); secrets — fabric's secrets
             (ad_agent_password); container — the DC's container. Reads and writes vars.yaml without the vars lock (an
             apply already holds it, as move_subnets_to_plan).
    Returns: list of str to show ([] when there is nothing to move). A move that cannot happen yet (the subnets still
             in the settings, the DC not answering, options the checks refuse, a read-only DC without a writable
             partner) is reported and left for the next apply, the settings untouched.
    Fails:   OSError or yaml errors reading or writing vars.yaml or the record.
    Feeds:   deploy/restart_changed (every apply), wired with area 5 of the port (1.10.4.41), as
             move_subnets_to_plan."""
    path = deploy_paths()["vars"]
    data = load_vars(path)
    d = data.get("dhcp") or {}
    site = v.get("site_name") or data.get("site_name")
    if not site or not any(d.get(k) for k in KEYS) or not plan_holds_subnets(data):
        return []
    try:
        server = writable_server(v, "move the settings' DHCP options into the plan")   # 2.1.10.43
        plan = site_plan(read_plan(v, secrets, of=site, container=container, server=server), site)
        org_defs = list((plan.get("domain_options") or {}).get("option_defs") or [])
        moving = check_option_set({k: d.get(k) for k in KEYS}, org_defs, "the settings' DHCP options")
        have = plan["site_options"]
        defs, kept_defs = _carry(have.get("option_defs") or [], moving["option_defs"],
                                 lambda x: (x["name"], x.get("space", "dhcp4")))
        options, kept_opts = _carry(have.get("options") or [], moving["options"],
                                    lambda x: (x.get("name", x.get("code")), x.get("space", "dhcp4")))
        classes, kept_classes = _carry(have.get("client_classes") or [], moving["client_classes"],
                                       lambda x: x["name"])
        merged = check_option_set({"options": options, "option_defs": defs, "client_classes": classes}, org_defs,
                                  f"site {site}'s DHCP options")
        write_plan(v, secrets, [{"do": "set", "what": "options", "site": site, "key": site, "fields": merged}],
                   container=container, server=server)
        save_plan_cache(site_plan(read_plan(v, secrets, of=site, container=container, server=server), site))
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:
        return [f"DHCP options: the site's global options stay in the settings for now ({e}); the next apply moves "
                "them"]
    record = {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "site": site,
              "moved": {k: moving[k] for k in KEYS},
              "not_carried": {"options": kept_opts, "option_defs": kept_defs, "client_classes": kept_classes},
              "settings_as_they_were": {k: d.get(k) for k in KEYS if k in d}}
    out = os.path.join(os.path.dirname(path), f"ipam-options-upgrade-{time.strftime('%Y%m%d-%H%M%S')}.json")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f, indent=1, default=str)
    data["dhcp"] = {k: x for k, x in d.items() if k not in KEYS}
    save_vars(data, path)
    lines = [f"DHCP options: {len(moving['options'])} option(s), {len(moving['option_defs'])} definition(s) and "
             f"{len(moving['client_classes'])} class(es) moved from the settings into {site}'s options"]
    for kind, items in (("option", kept_opts), ("definition", kept_defs), ("class", kept_classes)):
        lines += [f"  not carried ({site}'s options already have it): {kind} "
                  f"{x.get('name', x.get('code'))}" for x in items]
    lines.append(f"  the record: {out}")
    return lines
