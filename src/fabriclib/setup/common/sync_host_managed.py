import json
import os

from fabriclib.directory.constants import FABRIC_MANAGED
from fabriclib.common.errors import ValidationError
from fabriclib.consent.plan_member import RECORD
from fabriclib.setup.common.apply_host_managed import apply_host_managed
from fabriclib.setup.common.find_computer import find_computer
from fabriclib.setup.errors import SetupError


def sync_host_managed(v, config_dir):
    """Purpose: keep fabric's management of the fabric host in step with its account's membership of
             `fabric-managed` (decision 2.1.6.49, manual 1.6.11.11): asked of the DC (its own database, inside
             the samba container), applied while the account is in the group, removed when it is not.
    Inputs:  v — rendered vars (host_join_domain, and what apply_host_managed reads); config_dir — the
             install's config folder (RECORD names the host's own account).
    Returns: {"account": "FAB1", "managed": bool, "changes": [str, …]}.
    Fails:   ValidationError when this host is not a member of its domain with its own account (host_join_domain
             false, or setup never made it one, or it was undone): nothing to keep in step, nothing changed;
             SetupError when the DC cannot be read (nothing changed) or from apply_host_managed.
    Feeds:   samba/run_domain_command (`fabricctl domain host-managed`, the fabric-host-managed timer)."""
    path = os.path.join(config_dir, RECORD)
    account = None
    if v.get("host_join_domain", True) is not False and os.path.exists(path):
        with open(path) as f:
            account = json.load(f).get("account")
    if not account:
        raise ValidationError("this host is not a member of its domain with an account of its own (manual 1.6.11.8): "
                              "`sudo fabricctl setup --step member` makes it one")
    found = find_computer(account)
    if found is None:
        raise SetupError(f"the domain has no computer {account}$ (removed in the web console?): "
                         "`sudo fabricctl setup --step member` makes it again; nothing was changed")
    group = f"cn={FABRIC_MANAGED},"
    managed = any(g.lower().startswith(group) for g in found.get("member_of", []))
    return {"account": account, "managed": managed, "changes": apply_host_managed(v, managed)}
