from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.add_machine import add_machine
from fabriclib.directory.remove_machine import remove_machine
from fabriclib.directory.set_machine_enabled import set_machine_enabled
from fabriclib.samba.clear_gpo_policy import clear_gpo_policy
from fabriclib.samba.gpo_overview import gpo_overview
from fabriclib.samba.read_policy_changes import read_policy_changes
from fabriclib.samba.set_domain_password_policy import set_domain_password_policy
from fabriclib.samba.set_gpo_policy import set_gpo_policy


def post_domain(route, actor, data):
    """Purpose: the domain section of the Directory tab (manual 1.6.5.21 S7.4): the site's machines, POST
             /v1/machines/..., its admin settings GPO, POST /v1/gpo/..., and the domain's password policy, POST
             /v1/domain/password-policy (1.6.5.25, 2.1.2.22).
    Inputs:  route — ["machines"] (body: name), ["machines", <name>, "enable"|"disable"|"delete"], ["gpo", "search"]
             (body: match), ["gpo", "set"] (body: policy, values {element: text}, enabled, control), ["gpo",
             "clear"] (body: policy), ["domain", "password-policy"]
             (body: the policy keys to change, read_policy_changes); actor — str; data — the JSON body.
    Returns: machines: {"password"} (the one-time join password, shown once); enable/disable: {"name", "enabled",
             "changed"}; delete: {"name"}; gpo/search: gpo_overview with the matching policies; gpo/set and
             gpo/clear: {"changed": [what changed]}; domain/password-policy: {"policy": the saved policy}
             (the next apply writes it into the domain).
    Fails:   ValidationError("unknown operation") for another route, "values: an object of element: text", or
             from fabriclib (-> 400), the password policy's checks among them (check_samba_settings).
    Feeds:   agent/post_route.py (POST machines/..., gpo/..., domain/...)."""
    if route == ["domain", "password-policy"]:
        return {"policy": set_domain_password_policy(actor, read_policy_changes(data), source="web")}
    v = load_vars()
    if route == ["machines"]:
        return {"password": add_machine(v, actor, read_text(data, "name"), source="web",
                                        type=read_text(data, "type") or None,
                                        managed=read_text(data, "managed") != "no")}
    if len(route) == 3 and route[0] == "machines" and route[2] in ("enable", "disable"):
        return set_machine_enabled(v, actor, route[1], route[2] == "enable", source="web")
    if len(route) == 3 and route[0] == "machines" and route[2] == "delete":
        return remove_machine(v, actor, route[1], source="web")
    if route == ["gpo", "search"]:
        return gpo_overview(v, str(data.get("match") or "")[:100])
    if route == ["gpo", "set"]:
        values = data.get("values") or {}
        if not isinstance(values, dict) or not all(isinstance(k, str) and isinstance(x, str)
                                                   for k, x in values.items()):
            raise ValidationError("values: an object of element: text")
        return {"changed": set_gpo_policy(v, actor, read_text(data, "policy"), values,
                                          data.get("enabled", True) is not False, source="web",
                                          control=data.get("control") is True)}
    if route == ["gpo", "clear"]:
        return {"changed": clear_gpo_policy(v, actor, read_text(data, "policy"), source="web",
                                            control=data.get("control") is True)}
    raise ValidationError("unknown operation")
