from fabriclib.consent.groups import GROUPS
from fabriclib.consent.plan_accounts import plan_accounts
from fabriclib.consent.plan_firewall import plan_firewall
from fabriclib.consent.plan_member import plan_member
from fabriclib.consent.plan_own_rules import plan_own_rules
from fabriclib.consent.plan_packages import plan_packages
from fabriclib.consent.plan_ports import plan_ports
from fabriclib.consent.plan_resolver import plan_resolver
from fabriclib.consent.plan_runtime import plan_runtime
from fabriclib.consent.plan_services import plan_services
from fabriclib.consent.plan_time import plan_time
from fabriclib.consent.plan_trust import plan_trust


def plan_host_changes(v, deploy_base, config_dir, jinja_dir, steps=None):
    """Purpose: every change this setup run would make outside fabric's own tree, by group (manual 2.7.1.3-3), for the
                questions asked before the first step.
    Inputs:  v — the planned settings (planned_vars); deploy_base, config_dir, jinja_dir — install paths;
             steps — the setup steps that will run (None: all), so `--step firewall` asks only about the firewall.
    Returns: {group: [change, ...]} in GROUPS order, groups with nothing to change left out.
    Fails:   SetupError from plan_accounts (an id taken by another account); errors of the plan_* functions.
    Feeds:   setup/run_setup (ask_consent)."""
    plans = {
        "packages": lambda: plan_packages()["text"],
        "runtime": lambda: plan_runtime(v),
        "services": plan_services,
        "accounts": lambda: [a["text"] for a in plan_accounts(v)],
        "resolver": lambda: plan_resolver(v),
        "ports": lambda: plan_ports(v, config_dir),
        "firewall": lambda: plan_firewall(v, config_dir),
        "own_rules": lambda: plan_own_rules(v, config_dir),
        "trust": lambda: plan_trust(v),
        "time": plan_time,
        "member": lambda: plan_member(v),
    }
    out = {}
    for group, meta in GROUPS.items():
        if steps is not None and meta["step"] not in steps:
            continue
        changes = plans[group]()
        if changes:
            out[group] = changes
    return out
