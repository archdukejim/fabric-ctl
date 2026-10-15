import copy
import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.jinja_env import jinja_env
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.dhcp.check_kea_config import check_kea_config
from fabriclib.dhcp.common.kea_image import kea_image
from fabriclib.dhcp.normalize_dhcp import normalize_dhcp
from fabriclib.federation.network_conflicts import network_conflicts
from fabriclib.federation.read_address_plan import read_address_plan
from fabriclib.federation.site_networks import site_networks
from fabriclib.ipam.common.plan_holds_subnets import MOVED, MOVED_OPTIONS, plan_holds_subnets
from fabriclib.ipam.planned_subnets import planned_subnets


def _check_address_plan(before, data):
    """Purpose: refuse a change that makes a subnet overlap another site's network (manual 1.10.2.6), checked against
                the address plan in the domain (1.10.2.8). Overlaps that were there before the change
             do not block it (`fabricctl federation networks` lists them). Not federated, or the DC not answering
             (`fabricctl federation networks` shows any overlap once it is back): nothing to check.
    Inputs:  before — the settings before the change; data — with the new dhcp block (site_name, lan_cidr,
             dhcp).
    Returns: None.
    Fails:   ValidationError naming each new overlap without an allow_overlap reason.
    Feeds:   edit_dhcp."""
    if not os.path.exists(deploy_paths()["federation"]) or not data.get("site_name"):
        return
    try:
        plan = read_address_plan(data)
    except (ValidationError, RuntimeError):
        return
    def key(c):
        return c["cidr"], c["other_site"], c["other_cidr"]
    old = {key(c) for c in network_conflicts(site_networks(before), plan, data["site_name"])}
    bad = [c for c in network_conflicts(site_networks(data), plan, data["site_name"])
           if not c["allowed"] and key(c) not in old]
    if bad:
        raise ValidationError("; ".join(f"{c['cidr']} ({c['name']}) overlaps {c['other_cidr']} ({c['other_name']}) "
                                        f"of site {c['other_site']}" for c in bad)
                              + ". Choose another network, or give a reason with --allow-overlap if the two are "
                                "never routed together")


def edit_dhcp(actor, event, change, source="cli", global_level=False):
    """Purpose: one change to `dhcp:` in vars.yaml, the way every DHCP command makes it: under the vars lock, on
             the normalized settings (so every subnet keeps a stored id), the whole block checked again — by fabric
             and, when DHCP is on, by Kea itself on the configuration it would get — before it is saved, then
             audited. Applied by the next apply.
    Inputs:  actor — who asks (audit); event — the audit event (e.g. "DHCP_SUBNET_ADD"); change — function(dhcp)
             that changes the dict in place and returns (result, audit detail str); source — "cli" or "web";
             global_level — the change is to the global options or a client class (not a subnet or reservation):
             once the subnets live in the plan it is refused with MOVED_OPTIONS before `change` runs, so the refusal
             names the commands that make it (`ipam option`, `ipam class`) whatever `change` would have said (a
             class the settings do not hold: 2.3.10.10.4).
    Returns: (result of change, the saved dhcp block).
    Fails:   ValidationError from change, normalize_dhcp or Kea's check (check_kea_config: an option Kea does not
             know, data that does not fit, a class expression it cannot parse) or the address plan (a subnet
             overlapping another site's network without allow_overlap) — nothing is saved then, so a
             refused change never breaks the next apply; MOVED once the subnets live in the address plan and the
             change touches one; MOVED_OPTIONS once the subnets live in the plan and the change touches the global
             options, definitions or client classes (they are the plan's too since 0.8.0, 2.1.10.23); OSError or
             yaml.YAMLError from vars_lock / load_vars / save_vars / write_audit.
    Feeds:   dhcp/add_subnet, update_subnet, remove_subnet, set_option, unset_option, add_client_class,
             remove_client_class."""
    with vars_lock():
        data = load_vars()
        planned = plan_holds_subnets(data)
        if planned and global_level:          # the plan's since 0.8.0 (2.1.10.23, manual 1.10.4.24.4)
            raise ValidationError(MOVED_OPTIONS)
        if planned:                          # checked with the plan's subnets, saved without them (1.10.4.9)
            data["dhcp"] = {**(data.get("dhcp") or {}), "subnets": planned_subnets(data)}
        before = copy.deepcopy(data)
        dhcp = normalize_dhcp({**data, "dhcp": copy.deepcopy(data.get("dhcp") or {}), "install_kea": True})
        kept = copy.deepcopy(dhcp["subnets"])
        globals_before = copy.deepcopy(dhcp)
        result, detail = change(dhcp)
        data["dhcp"] = normalize_dhcp({**data, "dhcp": dhcp, "install_kea": True})
        if planned and data["dhcp"]["subnets"] != kept:
            raise ValidationError(MOVED)
        if planned and any(data["dhcp"].get(k) != globals_before.get(k)
                           for k in ("options", "option_defs", "client_classes")):
            raise ValidationError(MOVED_OPTIONS)
        _check_address_plan(before, data)
        if data.get("install_kea"):         # vars.yaml holds the rendered settings: render Kea's file from them
            env = jinja_env(deploy_paths()["jinja"])
            text = env.get_template("kea/kea-dhcp4.conf.j2").render(**data)
            check_kea_config(kea_image(env, data), "kea-dhcp4.conf", text)
        if planned:
            data["dhcp"] = {k: val for k, val in data["dhcp"].items() if k != "subnets"}
        save_vars(data)
    write_audit(actor, event, detail, source)
    return result, data["dhcp"]
