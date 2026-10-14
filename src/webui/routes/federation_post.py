import time
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.constants import STEP_UP
from webui.session.page_context import page_context

STEP_UP_AGAIN = {"rodc-lost": "handling a lost read-only DC", "dc-type": "asking a site to change its DC type"}


def _roles(h, form):
    """Purpose: the role form (POST /federation/roles, manual 1.9.8.20, decision 2.1.9.21): one fabric-agent call that
             grants a role at a site below this one, takes it back, or makes the site's group again.
    Inputs:  h — the request handler (redirect); form — dict: site, role ("admins" too for remake), member ("" for the
             site's own admins), action grant|revoke|remake (the site's group made again, 2.3.9.2.8).
    Returns: 303 to /federation with msg or err.
    Fails:   AgentError, PermissionDenied (no federation:admin) and AuthError propagate.
    Feeds:   federation_post."""
    try:
        done = actions.site_role_change(form.get("site", ""), form.get("role", ""), form.get("member", ""),
                                        form.get("action", ""))
    except actions.ValidationError as exc:
        return h.redirect("/federation?" + urllib.parse.urlencode({"err": str(exc)}))
    if form.get("action") == "remake":
        what = ("replaced (the site had made it itself)" if done.get("remade") else "made (it was missing)"
                if done.get("made") else "left as it is (fabric made it)")
        return h.redirect("/federation?" + urllib.parse.urlencode({"msg": f"group {done['group']} {what}."}))
    msg = (f"{done['role']} at {done['site']} {'granted to' if done['granted'] else 'revoked from'} {done['member']}"
           + ("." if done["changed"] else " (no change).")
           + (" The group the site had made itself was replaced." if done.get("remade") else ""))
    return h.redirect("/federation?" + urllib.parse.urlencode({"msg": msg}))


def _dc_type(h, sess, site, form):
    """Purpose: ask a site below to change its DC type (decision 2.1.9.23, revised 2026-10-14; manual 4.9.1.4): one
             fabric-agent call; the change token it answers is shown on this one page (never put in a URL, never
             stored by the console), for the admin to hand to the site's own admin, who accepts at the site.
    Inputs:  h — the request handler (send, redirect); sess — the session; site — str (the form's); form — to
             (writable|rodc).
    Returns: 200 the Federation tab with the token; 303 to /federation with err when no site is chosen or the agent
             refuses.
    Fails:   AgentError, PermissionDenied (no federation:admin) and AuthError propagate.
    Feeds:   federation_post."""
    if not site.strip():
        return h.redirect("/federation?" + urllib.parse.urlencode({"err": "Choose the site whose DC type changes."}))
    try:
        req = actions.dc_type_request(site, form.get("to", ""))
    except actions.ValidationError as exc:
        return h.redirect("/federation?" + urllib.parse.urlencode({"err": str(exc)}))
    msg = (f"Site {req['site']}'s DC ({req['was']}) is asked to become {req['to']}. Hand the change token below to "
           f"{req['site']}'s admin, who accepts it at the site.")
    return h.send(200, views.federation(page_context(sess), actions.federation_overview(), msg, "", None, req))


def _rodc_lost(h, site, form):
    """Purpose: a site's read-only DC lost or stolen (decision 2.1.6.58, manual 4.9.1.3): every account it held reset
             and the DC removed, one fabric-agent call, the site's name typed as confirmation.
    Inputs:  h — the request handler (redirect); site — str; form — confirm (the site's name).
    Returns: 303 to /federation with msg (done) or, with the list again, err.
    Fails:   AgentError, PermissionDenied (no federation:admin) and AuthError propagate.
    Feeds:   federation_post."""
    try:
        res = actions.rodc_lost(site, form.get("confirm", ""))
    except actions.ValidationError as exc:
        return h.redirect("/federation?" + urllib.parse.urlencode({"rodc_lost": site, "err": str(exc)}))
    msg = (f"Site {site}: {len(res['reset'])} account(s) reset; read-only DC(s) removed: "
           f"{', '.join(res['removed']) or 'none left'}. Site {site} has no DC until a new one joins."
           if res["changed"] else " ".join(res["plan"]["lines"]))
    return h.redirect("/federation?" + urllib.parse.urlencode({"msg": msg}))


def federation_post(h, sess, parts, form):
    """Purpose: the Federation tab's changes, each for federation:admin (the agent checks it): a role at a site below
             (/federation/roles, 2.1.9.21); a site below asked to change its DC type (/federation/dc-type, 2.1.9.23,
             its change token shown once); a site's lost read-only DC handled
             (/federation/rodc-lost/<site>, 2.1.6.58). The DC type change and the lost DC need a recent sign-in.
    Inputs:  h — the request handler (redirect, send, deny); sess — dict from find_session (user, auth_at); parts —
             path segments after /federation/: ['roles'], ['dc-type'] or ['rodc-lost', <site>]; form — the posted
             fields (dc-type: site, to).
    Returns: what _roles, _dc_type or _rodc_lost return; 303 to /login?next=/federation… when a step-up change's last
             sign-in is older than STEP_UP (300 s).
    Fails:   404 for any other path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/federation/…).
    Notes:   The step-up is checked before the site, as for the vault's and the SSH page's changes."""
    if parts == ["roles"]:
        return _roles(h, form)
    if parts != ["dc-type"] and not (len(parts) == 2 and parts[0] == "rodc-lost" and parts[1]):
        return h.deny(404, "Not found.")
    if time.time() - sess.get("auth_at", 0) > STEP_UP:
        return h.redirect("/login?" + urllib.parse.urlencode({"next": "/federation?msg=" + urllib.parse.quote(
            f"Signed in again. Repeat the step: {STEP_UP_AGAIN[parts[0]]} needs a sign-in from the last 5 "
            "minutes.")}))
    if parts == ["dc-type"]:
        return _dc_type(h, sess, form.get("site", ""), form)
    return _rodc_lost(h, parts[1], form)
