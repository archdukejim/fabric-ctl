from webui.devpreview.fabric_rules import ValidationError, required_permission
from webui.devpreview.fake_directory import fake_directory
from webui.devpreview.fake_dns import fake_dns
from webui.devpreview.fake_misc import fake_misc
from webui.devpreview.fake_network import fake_network
from webui.devpreview.fake_pending import fake_pending
from webui.devpreview.fake_reads import fake_reads


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
        for area in (fake_dns, fake_directory, fake_network, fake_misc):
            answer = area(state, who, change, change_body)
            if answer is not None:
                return answer
        raise ValidationError("not found")

    try:
        held = fake_pending(state, who, method, route, body, run)
        if held is not None:
            return 200, held
        for area in ((fake_reads,) if method == "GET" else (fake_dns, fake_directory, fake_network, fake_misc)):
            answer = area(state, who, route, body)
            if answer is not None:
                return 200, answer
    except ValidationError as exc:
        return 400, {"error": str(exc)}
    return 404, {"error": "not found"}
