import time
import urllib.parse

from webui import agentclient as actions
from webui.constants import STEP_UP

BACK = "/settings/backups"


def backups_post(h, sess, parts, form):
    """Purpose: the Backups page's forms (manual 1.3.7.9): Back up now and Restore one section, each a job followed on
             its page, and the schedule saved or turned off. A Domain Admin only, after a sign-in from the last 5
             minutes (1.3.7.12); fabric-agent checks both again.
    Inputs:  h — the request handler (back, redirect, deny); sess — dict from find_session (auth_at, domain_admin);
             parts — segments after /settings/backups/: ['now'], ['schedule'], ['restore'], ['reinstall']; form —
             now: passphrase, passphrase_again, use_schedule; schedule: time, keep, public_key, action (save|off);
             restore: file, section, key, confirm; reinstall: file, key, confirm.
    Returns: 303 to /login?next=/settings/backups?signed_in=1 when the sign-in is older than STEP_UP; now and restore:
             303 to the job's page; schedule: 303 back with what was saved; reinstall: 303 back saying it started;
             a refusal: 303 back (a restore: to its section or the whole bundle's step) with why, nothing changed.
    Fails:   403 for someone the sign-in did not find a Domain Admin; 404 for another path; AgentError,
             PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/settings/backups/…)."""
    if not sess.get("domain_admin"):
        return h.deny(403, "Only the domain's Domain Admins may use backups.")
    if time.time() - sess.get("auth_at", 0) > STEP_UP:
        return h.redirect("/login?next=/settings/backups%3Fsigned_in%3D1")
    back = BACK
    try:
        if parts == ["now"]:
            if form.get("use_schedule") == "1":
                job = actions.backup_now(scheduled_key=True)
            else:
                if form.get("passphrase", "") != form.get("passphrase_again", ""):
                    return h.back(BACK, err="The two passphrases differ: nothing was made.")
                job = actions.backup_now(passphrase=form.get("passphrase", ""))
            return h.redirect("/jobs/" + urllib.parse.quote(job, safe=""))
        if parts == ["schedule"]:
            if form.get("action") == "off":
                actions.backup_schedule(off=True)
                return h.back(BACK, msg="The schedule is off. Scheduled bundles already made are kept.")
            out = actions.backup_schedule(form.get("time", ""), form.get("keep", ""), form.get("public_key", ""))
            return h.back(BACK, msg=f"Schedule saved: {out['schedule']}, keeping {out['keep']} scheduled bundles.")
        if parts == ["restore"]:
            back = BACK + "?" + urllib.parse.urlencode({"restore": form.get("file", ""),
                                                        "section": form.get("section", "")})
            job = actions.backup_restore(form.get("file", ""), form.get("section", ""), form.get("key", ""),
                                         form.get("confirm", ""))
            return h.redirect("/jobs/" + urllib.parse.quote(job, safe=""))
        if parts == ["reinstall"]:
            back = BACK + "?" + urllib.parse.urlencode({"restore": form.get("file", ""), "whole": "1"})
            actions.backup_reinstall(form.get("file", ""), form.get("key", ""), form.get("confirm", ""))
            return h.back(BACK, msg=f"The whole restore of {form.get('file', '')} has started on the host. This "
                                    "console goes down in a moment and comes back from the bundle in some minutes: "
                                    "then sign in again, and this page shows how it went.")
    except (actions.ValidationError, actions.NotFound) as exc:
        return h.back(back, err=f"Refused, nothing changed: {exc}")
    return h.deny(404, "Not found.")
