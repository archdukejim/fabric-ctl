import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.samba.check_logon_policies import check_logon_policies
from fabriclib.samba.host_logon_default import HOSTS_OU, host_logon_default
from fabriclib.samba.logon_ou_path import logon_ou_path
from fabriclib.secrets.load_secrets import load_secrets


def set_logon_policy(v, actor, ou, console=None, remote=None, source="cli", secrets=None, container="samba"):
    """Purpose: who may sign in to the machines in one OU (manual 1.6.11.4): its console and remote groups saved in
             `logon_policies`; the next apply writes the OU's GPO. The first edit while the setting is null makes the
             site's log-on rights of today (legacy_logon_groups, read in the domain) the site OU's policy, then applies
             the edit, so nothing changes for anyone but what was edited (2.1.6.44).
    Inputs:  v — fabric vars (site_name, webui_admin_group); actor — str, for the audit; ou — the OU's path below
             the site's OU ("site" or "" for the site's OU); console, remote — lists of group names, None to keep
             that right as the OU has it (empty for an OU without a policy); source — audit source; secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"ou", "console", "remote"} as saved for that OU, and "policies": the whole saved map.
    Fails:   ValidationError: an OU path or group name refused, a group not in the domain ("no group … in the
             domain"), neither right given, the site's OU or OU=machines left granting nobody (check_logon_policies),
             or the directory's errors (run_op: the DC not running). Nothing is saved then. OSError or
             yaml.YAMLError from the settings or the audit log.
    Feeds:   samba/run_domain_command (`fabricctl domain logon set`), agent/post_domain (POST /v1/domain/logon/set,
             gpo:admin).
    Notes:   audited as LOGON_POLICY_SET."""
    path = logon_ou_path(ou)
    if console is None and remote is None:
        raise ValidationError("give the groups allowed at the console, remotely, or both")
    named = list(console or []) + list(remote or [])
    # the names' form, before asking the domain (break-glass beside them: an empty list is the OU's to decide)
    check_logon_policies({"": {"console": ["fabric-break-glass"], "remote": named}})
    with vars_lock():
        data = load_vars()
        policies = copy.deepcopy(data.get("logon_policies"))
        found = run_op(v, secrets if secrets is not None else load_secrets(), "logon_groups",
                       {"names": named, "admin_group": v.get("webui_admin_group") or "admins"}, container)
        if found["missing"]:
            raise ValidationError("no group " + ", ".join(found["missing"]) + " in the domain")
        if policies is None:                  # the first edit: today's rights become the site OU's policy
            policies = {"": {"console": list(found["legacy"]), "remote": list(found["legacy"])}}
        policies = check_logon_policies(policies)
        now = policies.get(path) or (host_logon_default(v.get("site_name", "")) if path == HOSTS_OU
                                     else {"console": [], "remote": []})
        policies[path] = {"console": now["console"] if console is None else list(console),
                          "remote": now["remote"] if remote is None else list(remote)}
        policies = check_logon_policies(policies)
        data["logon_policies"] = policies
        save_vars(data)
    entry = policies[path]
    write_audit(actor, "LOGON_POLICY_SET", f"ou={path or 'site'} console={','.join(entry['console'])} "
                f"remote={','.join(entry['remote'])}", source)
    return {"ou": path, **entry, "policies": policies}
