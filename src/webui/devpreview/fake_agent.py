from webui.devpreview.fabric_rules import ValidationError, required_permission
from webui.devpreview.fake_account import fake_account
from webui.devpreview.fake_directory import fake_directory
from webui.devpreview.fake_dns import fake_dns
from webui.devpreview.fake_groups import fake_groups
from webui.devpreview.fake_machines import fake_machines
from webui.devpreview.fake_ous import fake_ous
from webui.devpreview.fake_misc import fake_misc
from webui.devpreview.fake_network import fake_network
from webui.devpreview.fake_pending import fake_pending
from webui.devpreview.fake_reads import fake_reads


def _read_groups(state, who, route, body):
    """Purpose: The groups' reads (fake_groups with no body: GET).
    Inputs:  as fake_groups'.
    Returns: fake_groups' answer, or None.
    Fails:   ValidationError (no such group).
    Feeds:   fake_agent."""
    return fake_groups(state, who, route, None)


def _read_machines(state, who, route, body):
    """Purpose: The computers' reads (fake_machines with no body: GET).
    Inputs:  as fake_machines'.
    Returns: fake_machines' answer, or None.
    Fails:   ValidationError "no machine <name> in the domain".
    Feeds:   fake_agent."""
    return fake_machines(state, who, route, None)


def _read_ous(state, who, route, body):
    """Purpose: The OU tree's read (fake_ous with no body: GET).
    Inputs:  as fake_ous'.
    Returns: fake_ous' answer, or None.
    Fails:   never.
    Feeds:   fake_agent."""
    return fake_ous(state, who, route, None)


def fake_agent(state, who, method, route, body):
    """Purpose: The dev preview's stand-in for fabric-agent: one /v1/ request answered from the in-memory sample data,
             with the agent's own permission check (fabriclib's table) against the preview's person, so a page shown
             `--as` a bundle is refused as the real agent refuses it.
    Inputs:  state — DevState; who — {"user", "perms"}; method — "GET" or "POST"; route — the segments after /v1/;
             body — dict (the JSON body).
    Returns: (status, answer): 200 with the route's answer; 400 {"error"} for a refusal (ValidationError); 403
             {"error": "you need the permission …"} or "not allowed"; 404 {"error": "not found"}.
    Fails:   never for refusals; a bug in a fake area propagates (the preview's request fails, shown in its log).
    Feeds:   fake_connection.FakeConnection.request."""
    need = required_permission(method, route) if required_permission else "session"
    if need is None:
        return 403, {"error": "not allowed"}
    if need != "session" and need not in who["perms"]:
        return 403, {"error": f"you need the permission {need}"}
    def run(change, change_body):          # a held change at Apply: the same fake route as a direct call
        for area in (fake_account, fake_dns, fake_machines, fake_ous, fake_directory, fake_groups, fake_network,
                     fake_misc):
            answer = area(state, who, change, change_body)
            if answer is not None:
                return answer
        raise ValidationError("not found")

    try:
        held = fake_pending(state, who, method, route, body, run)
        if held is not None:
            return 200, held
        for area in ((fake_account, fake_reads, _read_groups, _read_machines, _read_ous) if method == "GET"
                     else (fake_account, fake_dns, fake_machines, fake_ous, fake_directory, fake_groups, fake_network,
                           fake_misc)):
            answer = area(state, who, route, body)
            if answer is not None:
                return 200, answer
    except ValidationError as exc:
        return 400, {"error": str(exc)}
    return 404, {"error": "not found"}
