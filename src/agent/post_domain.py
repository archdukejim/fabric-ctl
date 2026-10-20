from agent.post_grants import post_grants
from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory.add_machine import add_machine
from fabriclib.directory.remove_machine import remove_machine
from fabriclib.directory.set_machine_enabled import set_machine_enabled
from fabriclib.domain.keytab_command import keytab_command
from fabriclib.domain.move_machine import move_machine
from fabriclib.domain.set_machine_site import set_machine_site
from fabriclib.domain.set_machine_type import set_machine_type
from fabriclib.samba.clear_gpo_policy import clear_gpo_policy
from fabriclib.samba.gpo_overview import gpo_overview
from fabriclib.samba.read_policy_changes import read_policy_changes
from fabriclib.samba.set_domain_password_policy import set_domain_password_policy
from fabriclib.samba.set_gpo_policy import set_gpo_policy
from fabriclib.samba.set_kerberos_policy import set_kerberos_policy

KERBEROS_KEYS = ("ticket_hours", "renew_days", "skew_minutes")


def post_domain(route, actor, data, caller=None, perms=None):
    """Purpose: the domain section of the Directory tab (manual 1.6.5.21 S7.4): the site's machines, POST
             /v1/machines/..., its admin settings GPO, POST /v1/gpo/..., and the domain's password policy, POST
             /v1/domain/password-policy (1.6.5.25, 2.1.2.22), and the grants, POST /v1/domain/grants/... (post_grants,
             1.6.13.7).
    Inputs:  route — ["machines"] (body: name), ["machines", <name>, "enable"|"disable"|"delete"], ["gpo", "search"]
             (body: match), ["gpo", "set"] (body: policy, values {element: text}, enabled, control), ["gpo",
             "clear"] (body: policy), ["domain", "password-policy"]
             (body: the policy keys to change, read_policy_changes), ["domain", "kerberos", "policy"] (body:
             ticket_hours, renew_days, skew_minutes), ["machines", <name>, "move"|"type"|"sites"|"keytab"] (body:
             path; type, move; action add|remove, site; service, user, path); actor — str; data — the JSON body;
             caller — the token's user (fabric-agent's check of each change, check_access), or None for a root peer;
             perms — the token's permissions (None for a root peer): moving a computer also needs `ous:admin`.
    Returns: machines: {"password"} (the one-time join password, shown once); enable/disable: {"name", "enabled",
             "changed"}; delete: {"name"}; gpo/search: gpo_overview with the matching policies; gpo/set and
             gpo/clear: {"changed": [what changed]}; domain/password-policy: {"policy": the saved policy}
             (the next apply writes it into the domain); domain/kerberos/policy: {"policy"} (likewise);
             machines/<name>/move:
             {"name", "path", "changed"}; type: {"name", "type", "changed", "kept_folder"}; sites: {"name", "site",
             "member", "changed"}; keytab: {"machine", "command", "spns"} (nothing changed).
    Fails:   ValidationError("unknown operation") for another route, "moving a computer needs ous:admin too",
             "<key> must be a whole number", "values: an object of element: text", or
             from fabriclib (-> 400), the password policy's checks among them (check_samba_settings).
    Feeds:   agent/post_route.py (POST machines/..., gpo/..., domain/...)."""
    if route[:2] == ["domain", "grants"]:
        return post_grants(route, actor, data, caller)
    if route == ["domain", "password-policy"]:
        return {"policy": set_domain_password_policy(actor, read_policy_changes(data), source="web", caller=caller)}
    if route == ["domain", "kerberos", "policy"]:
        changes = {k: data[k] for k in KERBEROS_KEYS if k in data}
        if any(isinstance(x, bool) or not isinstance(x, int) for x in changes.values()) \
                or set(data) - set(KERBEROS_KEYS) - {"actor"}:
            raise ValidationError(f"the ticket policy's keys ({', '.join(KERBEROS_KEYS)}), each a whole number")
        return {"policy": set_kerberos_policy(actor, changes, caller=caller, source="web")}
    v = load_vars()
    if route == ["machines"]:
        return {"password": add_machine(v, actor, read_text(data, "name"), source="web",
                                        type=read_text(data, "type") or None,
                                        managed=read_text(data, "managed") != "no", caller=caller)}
    if len(route) == 3 and route[0] == "machines" and route[2] in ("enable", "disable"):
        return set_machine_enabled(v, actor, route[1], route[2] == "enable", source="web", caller=caller)
    if len(route) == 3 and route[0] == "machines" and route[2] == "delete":
        return remove_machine(v, actor, route[1], source="web", caller=caller)
    if len(route) == 3 and route[0] == "machines" and route[2] == "move":
        if perms is not None and "ous:admin" not in perms:
            raise ValidationError("moving a computer needs ous:admin too (manual 1.6.12.11)")
        return move_machine(v, actor, route[1], read_text(data, "path"), caller=caller)
    if len(route) == 3 and route[0] == "machines" and route[2] == "type":
        return set_machine_type(v, actor, route[1], read_text(data, "type"), data.get("move") is True, caller=caller)
    if len(route) == 3 and route[0] == "machines" and route[2] == "sites":
        if data.get("action") not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        return set_machine_site(v, actor, route[1], read_text(data, "site"), data["action"] == "add", caller=caller)
    if len(route) == 3 and route[0] == "machines" and route[2] == "keytab":
        return keytab_command(v, route[1], read_text(data, "service"), read_text(data, "user"), read_text(data, "path"))
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
