STEPS = ("token", "demote", "leftover", "set_aside", "join", "done")
WHAT = {
    "token": "redeem the change token at {by}'s federation endpoint for a temporary join account (one hour)",
    "demote": "demote this site's domain controller {dc} at {writable} (samba-tool domain demote)",
    "leftover": "delete the demoted DC's leftover computer account at {writable}, so the same name can join again",
    "set_aside": "stop the DC and set its data aside (samba/data.before-dc-type-<time>, kept, never reused)",
    "join": "join again as a {word} domain controller under the same name ({dc}), through setup (fabricctl setup "
            "--yes), the join account removed afterwards",
    "done": "remove the request from the domain and record the change",
}


def plan_dc_type_change(v, pending, token, writable, replication, fsmo, done=()):
    """Purpose: what `fabricctl federation dc-type accept` will do at this site, or why it may not (decision 2.1.9.23,
             manual 1.9.8.22.2): every check before anything changes, and the steps left (those already done, by an
             earlier run, are skipped).
    Inputs:  v — fabric vars: site_name, dc_name, ad_dc_type; pending — the request in AD ({"to", "by", "actor", "at",
             "id"}) or None; token — the decoded change token ({"id", "site", "to", "by", "root_ok": bool}) or None
             (not given yet: checked when given); writable — (server or None, why): the writable DC that answers
             (samba/writable_server over the list), or why none; replication — (ok, why) from replication_healthy;
             fsmo — list of the FSMO roles this DC holds; done — the steps already done (the record).
    Returns: {"refused": "" or why, "noop": bool (already of the requested type: only the request is removed),
             "to", "steps": [names left], "lines": [what each step does, in order]}.
    Fails:   never.
    Feeds:   federation/change_dc_type."""
    out = {"refused": "", "noop": False, "to": (pending or {}).get("to", ""), "steps": [], "lines": []}
    me = v.get("site_name")
    if not pending:
        out["refused"] = f"no change of this site's DC type is requested (site {me}): ask from the site above"
        return out
    to = pending["to"]
    now_type = "rodc" if v.get("ad_dc_type") == "rodc" else "writable"
    if token is not None:
        if token.get("site") != me or token.get("to") != to or token.get("id") != pending.get("id"):
            out["refused"] = (f"the change token is for site {token.get('site')} to become {token.get('to')}, but "
                              f"the request in the domain is for {me} to become {to}: ask for a new one")
            return out
        if not token.get("root_ok"):
            out["refused"] = "the change token names another organisation's root CA: it is not for this fabric"
            return out
    if now_type == to and "join" not in done:
        out["noop"], out["steps"] = True, ["done"]
        out["lines"] = [f"this site's DC is already {'writable' if to == 'writable' else 'read-only'}: "
                        + WHAT["done"]]
        return out
    left = [s for s in STEPS if s not in done]
    if "demote" in left:            # nothing changed yet: every check applies
        server, why = writable
        if not server:
            out["refused"] = why
            return out
        ok, why = replication
        if not ok:
            out["refused"] = f"this site's replication is not healthy, so its DC is not changed: {why}"
            return out
        if to == "rodc" and fsmo:
            out["refused"] = (f"the DC holds an FSMO role ({', '.join(fsmo)}): move it to another writable DC "
                              "first (samba-tool fsmo transfer), then accept again")
            return out
    fields = {"by": pending.get("by", "?"), "dc": v.get("dc_name", "?"), "writable": writable[0] or "?",
              "word": "writable" if to == "writable" else "read-only"}
    out["steps"] = left
    out["lines"] = [WHAT[s].format(**fields) for s in left]
    return out
