from agent.job_store import JOBS
from agent.post_account import post_account
from agent.post_directory import post_directory
from agent.post_dhcp import post_dhcp
from agent.post_domain import post_domain
from agent.post_host_access import post_host_access
from agent.post_dns import post_dns
from agent.post_dns_filter import post_dns_filter
from agent.post_groups import post_groups
from agent.post_network import post_network
from agent.post_ous import post_ous
from agent.post_people import post_people
from agent.post_pki import post_pki
from agent.post_security import post_security
from agent.post_settings import post_settings
from agent.post_vault import post_vault
from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.images.apply_image_action import apply_image_action
from fabriclib.setup.doctor_report import doctor_report
from fabriclib.system.apply_changes import apply_changes

EVENT_ACTIONS = {"LOGIN", "LOGOUT", "LOGIN_DENIED"}


def post_route(route, actor, data, perms, session=None):
    """Purpose: answer POST /v1/<route>: route each change to the module of its area.
    Inputs:  route — segments after /v1/ (already authorized); actor — the user recorded in the audit log; data — the
             JSON body; perms — the token's permissions (None for a root peer); session — the token's `sid` (a
             person's own password change keeps that session). The token's user is the caller fabric-agent checks
             (check_access: the tiers, the grants, a group's managers), None for a root peer.
    Returns: the operation's JSON-serialisable result. apply: {"ok", "output"}; people/...: post_people's;
             groups/...: post_groups'; ous/...: post_ous'; account/...: post_account's;
             jobs/doctor and jobs/images (body: action update|rollback, service): {"id"} of a job read with GET
             /v1/jobs/<id> by the person who started it;
             events: {} after the login audit line; dns-filter/...: post_dns_filter's result; settings/plan,
             settings/apply, settings/dismiss: post_settings' result (the setup wizard, 1.8.5).
    Fails:   ValidationError (-> 400) for an unsupported event or what fabriclib refuses; RouteNotFound (-> 404).
    Feeds:   agent/handler.py (dispatch).
    Notes:   POST apply only needs dns:write (rbac/required_permission), though it runs the whole deployment."""
    area = route[:1]
    caller = actor if perms is not None else None       # the signed-in person; None: a root peer (the host)
    if area in (["zones"], ["tsig"]):
        return post_dns(route, actor, data)
    if area == ["dhcp"]:
        return post_dhcp(route, actor, data)
    if area == ["radius"]:
        return post_network(route, actor, data)
    if area == ["pki"] and len(route) == 2:
        return post_pki(route[1], actor, data)
    if area == ["vault"]:
        return post_vault(route[1:], actor, data)
    if area in (["devices"], ["roles"]):
        return post_directory(route, actor, data)
    if area in (["machines"], ["gpo"], ["domain"]):
        return post_domain(route, actor, data, caller, perms)
    if area in (["host-groups"], ["sudo"]):
        return post_host_access(route, actor, data, caller)
    if area == ["security"]:
        return post_security(route, actor, data)
    if area == ["dns-filter"]:
        return post_dns_filter(route, actor, data)
    if route == ["apply"]:
        ok, output = apply_changes(actor, source="web")
        return {"ok": ok, "output": output}
    if area == ["people"]:
        return post_people(route, actor, data, caller)
    if area == ["groups"]:
        return post_groups(route, actor, data, caller)
    if area == ["ous"]:
        return post_ous(route, actor, data)
    if area == ["account"]:
        return post_account(route, caller, data, session)
    owner = actor if perms is not None else None    # a job is read by whoever started it (root: any)
    if area == ["settings"]:                        # the setup wizard (1.8.5): a plan, its apply as a job
        return post_settings(route, actor, data, owner)
    if route == ["jobs", "doctor"]:              # doctor's checks take seconds to a minute: a job the page follows
        base = load_vars()["deploy_base_dir"]
        return JOBS.start("doctor", owner, lambda: doctor_report(base))
    if route == ["jobs", "images"]:
        action, service, base = read_text(data, "action"), read_text(data, "service"), load_vars()["deploy_base_dir"]
        if action not in ("update", "rollback") or not service:
            raise ValidationError("action: update or rollback, and a service")
        return JOBS.start("images", owner, lambda: apply_image_action(action, service, actor, base))
    if route == ["events"]:
        action = data.get("action")
        if action not in EVENT_ACTIONS:
            raise ValidationError("unsupported event")
        write_audit(actor, action, str(data.get("detail", ""))[:200], source="web")
        return {}
    raise RouteNotFound()
