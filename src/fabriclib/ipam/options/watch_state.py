"""What the plan poll keeps between runs (manual 1.10.4.26): <config>/plan-watch.json (the USN and what Kea was last
rendered from) and <config>/plan-dns.json (what DNS was last rendered from, written by an apply). No secret in either;
root's, 0600, like the plan kept beside them."""
import json
import os

from fabriclib.deploy.deploy_paths import deploy_paths


def load_watch_state(name):
    """Purpose: one of the poll's kept states.
    Inputs:  name — "plan-watch" or "plan-dns".
    Returns: dict ({} when none was kept, or the file is damaged: the next run starts over).
    Fails:   OSError other than a missing file.
    Feeds:   poll_plan."""
    try:
        with open(os.path.join(deploy_paths()["config"], f"{name}.json")) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def save_watch_state(name, data):
    """Purpose: keep one of the poll's states (written whole, then moved into place).
    Inputs:  name — "plan-watch" or "plan-dns"; data — dict (JSON-able).
    Returns: None.
    Fails:   OSError writing the file.
    Feeds:   poll_plan, load_address_plan (plan-dns, at an apply)."""
    path = os.path.join(deploy_paths()["config"], f"{name}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, path)
