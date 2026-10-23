import copy
import json
import os
import subprocess
import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp
from fabriclib.ipam.common.plan_cache import save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.ipam.subnets_to_plan import subnets_to_plan
from fabriclib.ipam.suggestions import suggest_block
from fabriclib.ipam.write_plan import write_plan
from fabriclib.samba.writable_server import writable_server


def move_subnets_to_plan(v, secrets, container="samba"):
    """Purpose: the upgrade from 0.7 and 0.8.0 (manual 1.10.4.10, 1.10.4.15, 1.10.4.37), run after convergence at every
             start and apply: a site whose settings still carry `dhcp.subnets` moves them into its plan in the domain
             once (subnets_to_plan: nothing it serves changes), gives the site its number when it has none
             (suggest_block), keeps the plan read back, writes the record <config>/ipam-upgrade-<time>.json (what moved,
             the VLAN IDs fabric chose, what could not be carried, the subnets as they were) and removes `dhcp.subnets`
             from vars.yaml, which keeps dhcp.interfaces and the global defaults (during setup, from fabric.yaml and
             from the vars.yaml its deploy installed, so neither reads as the settings' own afterwards). Idempotent: a
             subnet the plan has is left alone, and settings without subnets change nothing.
    Inputs:  v — rendered settings (site_name, ad_dc_type, ad_join_server); secrets — fabric's secrets
             (ad_agent_password); container — the DC's container. Reads and writes vars.yaml at deploy_paths()["vars"]
             without the vars lock: an apply started from the console or a command already holds it
             (system/apply_changes).
    Returns: list of str to show ([] when there is nothing to move). A move that cannot happen yet (the DC not
             answering, settings Kea's checks refuse, a read-only DC with no writable DC known) is reported and
             left for the next run, the settings untouched. A site with a read-only DC reads and writes its plan at
             the writable DC it replicates from (samba/writable_server, decision 2.1.10.43).
    Fails:   OSError or yaml errors reading or writing vars.yaml or the record.
    Feeds:   deploy/restart_changed (every apply) and setup/start_services (setup): Kea renders from the plan
             (load_address_plan), so the next apply serves what was moved."""
    path = deploy_paths()["vars"]
    data = load_vars(path)
    raw = (data.get("dhcp") or {}).get("subnets")
    site = v.get("site_name") or data.get("site_name")
    if not raw or not site:
        return []
    try:
        server = writable_server(v, "move this site's DHCP subnets into the address plan")   # 2.1.10.43
        subnets = normalize_dhcp({**data, "install_kea": True})["subnets"]
        read = read_plan(v, secrets, of=site, container=container, server=server)
        plan = site_plan(read, site)
        moved = subnets_to_plan(subnets, plan, site)
        changes = list(moved["changes"])
        block = plan["block"]
        if block is None:
            block = suggest_block(read["sites"], site)
            if block:
                changes.append({"do": "set", "what": "block", "site": site, "fields": {"block": block}})
        write_plan(v, secrets, changes, container=container, server=server)
        save_plan_cache(site_plan(read_plan(v, secrets, of=site, container=container, server=server), site))
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:     # the DC not answering
        return [f"address plan: the DHCP subnets stay in the settings for now ({e}); the next apply moves them"]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    record = {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "site": site, "block": block, "moved": moved["moved"],
              "vlans_assigned": moved["assigned"], "already_in_plan": moved["kept"],
              "not_carried": moved["not_carried"], "subnets_as_they_were": copy.deepcopy(raw)}
    out = os.path.join(os.path.dirname(path), f"ipam-upgrade-{stamp}.json")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(record, f, indent=1, default=str)
    data["dhcp"] = {k: val for k, val in (data.get("dhcp") or {}).items() if k != "subnets"}
    save_vars(data, path)
    installed = os.path.join(deploy_paths()["config"], "vars.yaml")
    if os.path.realpath(installed) != os.path.realpath(path) and os.path.exists(installed):
        # setup works from fabric.yaml; the vars.yaml its deploy installed still carries them (2.3.10.10.4)
        kept = load_vars(installed)
        if "subnets" in (kept.get("dhcp") or {}):
            kept["dhcp"] = {k: val for k, val in kept["dhcp"].items() if k != "subnets"}
            save_vars(kept, installed)
    lines = [f"address plan: {len(moved['moved'])} DHCP subnet(s) moved from the settings into {site}'s plan "
             f"(site number {block})"]
    lines += [f"  {a['subnet']} had no VLAN: it is VLAN {a['vlan']} now (check it: fabricctl ipam show)"
              for a in moved["assigned"]]
    lines += [f"  not carried: {item}" for item in moved["not_carried"]]
    lines.append(f"  the record: {out}")
    return lines
