import json

from fabriclib.settings.constants import WIZARD_KEYS
from fabriclib.settings.read_settings import read_settings


def plan_is_current(plan, v, have_gb=None):
    """Purpose: whether a plan still matches what is installed (manual 1.8.5.5): every wizard setting as it was when the
             plan was made (DHCP's first subnet only when the plan turns DHCP on: the address plan's copy changes
             with every poll). Someone else applying first makes it stale; it is refused at Apply and made again.
    Inputs:  plan — plan_settings' result ("base", "keys"); v — the settings as saved now; have_gb — the host's GB
             (None: measured), as read_settings takes it.
    Returns: bool.
    Fails:   never for a plan from plan_settings.
    Feeds:   apply_settings (under the settings' lock), agent/post_settings (before the apply job starts)."""
    now = read_settings(v, have_gb)
    keys = [k for k in WIZARD_KEYS if k != "dhcp" or "install_kea" in plan["keys"]]
    return all(json.dumps(now[k], sort_keys=True) == json.dumps(plan["base"].get(k), sort_keys=True) for k in keys)
