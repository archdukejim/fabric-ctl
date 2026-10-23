"""The last plan this site read from its DC (manual 1.10.4.14): what an apply renders from while the DC does not answer,
and what the firewall and the Kea tab read between applies."""
import json
import os

from fabriclib.deploy.deploy_paths import deploy_paths

NAME = "address-plan.json"


def plan_cache_path():
    """Purpose: where the last plan read is kept.
    Inputs:  none (deploy_paths: DEPLOY_BASE_DIR).
    Returns: str, <config>/address-plan.json.
    Fails:   never.
    Feeds:   load_plan_cache, save_plan_cache, plan_holds_subnets."""
    return os.path.join(deploy_paths()["config"], NAME)


def load_plan_cache():
    """Purpose: the last plan this site read from its DC.
    Inputs:  none.
    Returns: the site's plan ({"site", "block", "vlans", "subnets", "networks", "read"}), or None when none was kept.
    Fails:   OSError other than a missing file; json.JSONDecodeError for a damaged file.
    Feeds:   load_address_plan (the DC not answering), planned_subnets."""
    try:
        with open(plan_cache_path()) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_plan_cache(plan):
    """Purpose: keep the plan just read (no secret in it; root's, readable by root only like the settings).
    Inputs:  plan — the site's plan with "site", "block" and "read" (when).
    Returns: None.
    Fails:   OSError writing the file.
    Feeds:   load_address_plan, move_subnets_to_plan, common/edit_plan, common/edit_options."""
    path = plan_cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(plan, f, indent=1, sort_keys=True)
    os.replace(tmp, path)
