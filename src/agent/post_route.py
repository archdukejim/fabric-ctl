from agent.job_store import JOBS
from agent.post_directory import post_directory
from agent.post_dhcp import post_dhcp
from agent.post_domain import post_domain
from agent.post_host_access import post_host_access
from agent.post_ipam_scan import post_ipam_scan
from agent.post_dns import post_dns
from agent.post_dns_filter import post_dns_filter
from agent.post_network import post_network
from agent.post_networks import post_networks
from agent.post_options import post_options
from agent.post_pki import post_pki
from agent.post_security import post_security
from agent.post_vault import post_vault
from agent.read_text import read_text
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.create_person import create_person
from fabriclib.directory.remove_person import remove_person
from fabriclib.directory.reset_sign_in import reset_sign_in
from fabriclib.directory.set_person_enabled import set_person_enabled
from fabriclib.directory.set_person_group import set_person_group
from fabriclib.images.apply_image_action import apply_image_action
from fabriclib.setup.doctor_report import doctor_report
from fabriclib.system.apply_changes import apply_changes

EVENT_ACTIONS = {"LOGIN", "LOGOUT", "LOGIN_DENIED"}


def post_route(route, actor, data, perms):
    """Purpose: answer POST /v1/<route>: route each change to the module of its area.
    Inputs:  route — segments after /v1/ (already authorized); actor — the user recorded in the audit log; data — the
             JSON body; perms — the token's permissions (None for a root peer).
    Returns: the operation's JSON-serialisable result. apply: {"ok", "output"}; people: {"password"} (one-time,
             shown once); people/<uid>/reset: {"password"} — fabric-group members only with system:admin (or root);
             people/<uid>/disable|enable: {"uid", "enabled", "changed"}; people/<uid>/delete (body: confirm, the
             user name typed back): {"uid", "revoked"}; people/<uid>/groups (body: action add|remove, group):
             {"uid", "group", "member", "changed"} — each a fabric-group member's only with system:admin (or root);
             jobs/doctor and jobs/images (body: action update|rollback, service): {"id"} of a job read with GET
             /v1/jobs/<id> by the person who started it;
             events: {} after the login audit line; dns-filter/...: post_dns_filter's result; networks/<site>/...:
             post_networks' result (the address plan, 1.10.4.21); ipam/scan[/record]: post_ipam_scan's result;
             ipam/... (the rest): post_options' result (the DHCP options in the plan, 1.10.4.24.6).
    Fails:   ValidationError (-> 400) for an unsupported event or what fabriclib refuses; RouteNotFound (-> 404).
    Feeds:   agent/handler.py (dispatch).
    Notes:   POST apply only needs dns:write (rbac/required_permission), though it runs the whole deployment."""
    area = route[:1]
    if area in (["zones"], ["tsig"]):
        return post_dns(route, actor, data)
    if area == ["dhcp"]:
        return post_dhcp(route, actor, data)
    if route[:2] == ["ipam", "scan"]:
        return post_ipam_scan(route, actor, data)
    if area == ["networks"]:
        return post_networks(route, actor, data)
    if area == ["ipam"]:
        return post_options(route, actor, data)
    if area == ["radius"]:
        return post_network(route, actor, data)
    if area == ["pki"] and len(route) == 2:
        return post_pki(route[1], actor, data)
    if area == ["vault"]:
        return post_vault(route[1:], actor, data)
    if area in (["devices"], ["roles"]):
        return post_directory(route, actor, data)
    if area in (["machines"], ["gpo"], ["domain"]):
        return post_domain(route, actor, data)
    if area in (["host-groups"], ["sudo"]):
        return post_host_access(route, actor, data)
    if area == ["security"]:
        return post_security(route, actor, data)
    if area == ["dns-filter"]:
        return post_dns_filter(route, actor, data)
    if route == ["apply"]:
        ok, output = apply_changes(actor, source="web")
        return {"ok": ok, "output": output}
    if route == ["people"]:
        return {"password": create_person(load_vars(), actor, read_text(data, "uid"), read_text(data, "first"),
                                          read_text(data, "last"), read_text(data, "email"))}
    if len(route) == 3 and route[0] == "people" and route[2] == "reset":
        privileged = perms is None or "system:admin" in perms     # root, or the admin bundle
        return {"password": reset_sign_in(load_vars(), actor, route[1], privileged)}
    if len(route) == 3 and route[0] == "people" and route[2] in ("disable", "enable"):
        privileged = perms is None or "system:admin" in perms
        return set_person_enabled(load_vars(), actor, route[1], route[2] == "enable", privileged)
    if len(route) == 3 and route[0] == "people" and route[2] == "delete":
        privileged = perms is None or "system:admin" in perms
        return remove_person(load_vars(), actor, route[1], read_text(data, "confirm"), privileged)
    if len(route) == 3 and route[0] == "people" and route[2] == "groups":
        privileged = perms is None or "system:admin" in perms
        action = data.get("action")
        if action not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        return set_person_group(load_vars(), actor, read_text(data, "group"), route[1], action == "add", privileged)
    owner = actor if perms is not None else None    # a job is read by whoever started it (root: any)
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
