import base64
import re

from webui import agentclient as actions
from webui import views
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context

SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


def enrol_post(h, sess, op, form):
    """Purpose: Step-CA → Enrol a device (manual 1.5.3): each form maps to one fabric-agent operation.
    Inputs:  h — the request handler (send, deny); sess — dict from find_session; op — str after /stepca/enrol/:
             'apple' (name, device, ssid, wired), 'p12' (name, device, legacy), '<id>/withdraw'; form — dict from
             read_form.
    Returns: apple: 200 with the .mobileconfig as a download (application/x-apple-aspen-config, never stored by the
             console); p12: the result page with the .p12 and its password, shown once; withdraw: the enrol view with
             what was withdrawn.
    Fails:   404 for an unknown op; ValidationError → the enrol view again with status 400 and the error; AgentError,
             PermissionDenied and AuthError propagate to handle_request.
    Feeds:   stepca_post (/stepca/enrol/…).
    """
    ctx, user = page_context(sess), sess["user"]
    parts = op.split("/")
    if op not in ("apple", "p12") and not (len(parts) == 2 and parts[0] and parts[1] == "withdraw"):
        return h.deny(404, "Not found.")
    try:
        if op == "apple":
            r = actions.enrol_apple(user, form.get("name", ""), form.get("device", ""), form.get("ssid", ""),
                                    form.get("wired") == "on")
            filename = SAFE_FILENAME.sub("_", r["filename"])
            return h.send(200, base64.b64decode(r["profile_b64"]), "application/x-apple-aspen-config",
                          [("Content-Disposition", f'attachment; filename="{filename}"')])
        if op == "p12":
            r = actions.enrol_p12(user, form.get("name", ""), form.get("device", ""), form.get("legacy") == "on")
            return h.send(200, views.pki_result(ctx, "enrol", r))
        done = actions.withdraw_enrolment(user, parts[0])
        return stepca_page(h, ctx, "enrol", msg=f"Withdrew the profile for {done['cn']}: its challenge is refused "
                                                f"from now on.")
    except actions.ValidationError as exc:
        return stepca_page(h, ctx, "enrol", status=400, err=str(exc))
