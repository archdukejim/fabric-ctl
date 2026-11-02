from fabriclib.security.refresh_firewall import refresh_firewall
from fabriclib.system.apply_changes import apply_changes

ELSEWHERE = "written to that site's plan: its Kea takes it within 30 s (its plan poll)"


def apply_plan_change(v, actor, out, apply=True):
    """Purpose: after a change to a plan made from the console (manual 1.10.4.35): this install's site's applied at
             once with the host firewall brought in line, as the CLI does; another site's left to that site's plan
             poll, saying so.
    Inputs:  v — fabric vars (site_name); actor — the signed-in user (the apply's audit); out — edit_plan's or
             edit_options' result ({"result", "warnings", "site"}); apply — False for a change nothing is rendered
             from (a site's number).
    Returns: {"result", "warnings", "site", "own" (bool: this site's plan), "applied" (bool, or None when nothing was
             applied here), "output" (the last 2000 characters of the apply and the firewall, or what happens
             instead)}.
    Fails:   subprocess.TimeoutExpired and OSError from apply_changes or refresh_firewall.
    Feeds:   agent/post_networks, agent/post_options, agent/post_ipam_scan."""
    own = out["site"] == v.get("site_name")
    reply = {"result": out["result"], "warnings": out["warnings"], "site": out["site"], "own": own,
             "applied": None, "output": "" if own else ELSEWHERE}
    if own and apply:
        ok, output = apply_changes(actor, source="web")
        if ok:
            ok, more = refresh_firewall()
            output += "\n" + more
        reply.update(applied=ok, output=output[-2000:])
    return reply
