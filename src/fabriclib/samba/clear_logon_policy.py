import copy

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.samba.check_logon_policies import check_logon_policies
from fabriclib.samba.logon_ou_path import logon_ou_path
from fabriclib.samba.refuse_at_read_only_dc import refuse_at_read_only_dc


def clear_logon_policy(actor, ou, source="cli", v=None):
    """Purpose: one OU's log-on policy removed from `logon_policies` (manual 1.6.11.4): the OU takes its parent's again;
             the next apply removes its GPO.
    Inputs:  actor — str, for the audit; ou — the OU's path below the site's OU ("site" or "" for the site's OU);
             source — audit source; v — fabric vars (ad_dc_type), default: the saved settings.
    Returns: {"ou", "policies": the whole saved map}.
    Fails:   ValidationError: at a site whose DC is read-only (make the change at the site above, 2.1.6.52); an OU
             path refused; the OU has no policy of its own (the site's log-on rights of before
             0.9 included: they are changed with set); clearing it would leave the site's machines without a policy
             (neither the site's OU nor OU=machines would have one: check_logon_policies). Nothing is saved then.
             OSError or yaml.YAMLError from the settings or the audit log.
    Feeds:   samba/run_domain_command (`fabricctl domain logon clear`), agent/post_domain (POST
             /v1/domain/logon/clear, gpo:admin).
    Notes:   audited as LOGON_POLICY_CLEAR."""
    refuse_at_read_only_dc(v if v is not None else load_vars(), "who may sign in is")
    path = logon_ou_path(ou)
    with vars_lock():
        data = load_vars()
        policies = check_logon_policies(copy.deepcopy(data.get("logon_policies")))
        if policies is None:
            raise ValidationError("this site has no per-OU log-on policies yet (its log-on rights are those of before "
                                  "0.9, on the site's OU): change them with set")
        if path not in policies:
            raise ValidationError(f"the OU {path or 'site'} has no log-on policy of its own")
        del policies[path]
        try:
            policies = check_logon_policies(policies)
        except ValidationError as e:
            raise ValidationError(f"clearing {path or 'site'} is refused: {e}") from None
        data["logon_policies"] = policies
        save_vars(data)
    write_audit(actor, "LOGON_POLICY_CLEAR", f"ou={path or 'site'}", source)
    return {"ou": path, "policies": policies}
