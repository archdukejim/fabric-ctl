import re
import secrets
import urllib.parse

from webui import views
from webui.devpreview.sample_data import SAMPLE_CA, SAMPLE_ENROLMENTS
from webui.devpreview.sample_result import sample_result

NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")       # the agent's rule (fabriclib/pki/scep/constants)


def dev_post_enrol(h, path, form):
    """Purpose: Step-CA → Enrol a device, acted out in memory (manual 1.5.3): a .p12 result page with a throwaway
             password, an Apple profile refused (the preview has no CA to put in it), withdrawing a sample profile.
    Inputs:  h — the dev handler (send, ctx); path — /stepca/enrol/p12, /stepca/enrol/apple,
             /stepca/enrol/<id>/withdraw; form — dict (name, legacy).
    Returns: True when the path was handled; None otherwise.
    Fails:   never (bad names answer 400 with the agent's message, as production does).
    Feeds:   dev_post_action."""
    if not path.startswith("/stepca/enrol/"):
        return None
    parts = [urllib.parse.unquote(p) for p in path.split("/")[3:]]
    ctx, name = h.ctx, form.get("name", "").strip().lower()
    if parts in (["p12"], ["apple"]) and not NAME.match(name):
        h.send(400, views.stepca(ctx, "enrol", SAMPLE_CA, enrolments=SAMPLE_ENROLMENTS,
                                 err="the name must be 1 to 63 letters, digits and dashes (e.g. alice-iphone)"))
    elif parts == ["p12"]:
        r = dict(sample_result("enrol"), name=name, p12_b64=sample_result("issue")["p12_b64"],
                 p12_password=secrets.token_urlsafe(15), legacy=form.get("legacy") == "on", device="")
        h.send(200, views.pki_result(ctx, "enrol", r))
    elif parts == ["apple"]:
        h.send(400, views.stepca(ctx, "enrol", SAMPLE_CA, enrolments=SAMPLE_ENROLMENTS,
                                 err="DEV PREVIEW: no profile here (no CA to put in it); a real install downloads "
                                     f"{name}.mobileconfig"))
    elif len(parts) == 2 and parts[1] == "withdraw":
        before = len(SAMPLE_ENROLMENTS["challenges"])
        SAMPLE_ENROLMENTS["challenges"][:] = [c for c in SAMPLE_ENROLMENTS["challenges"] if c["id"] != parts[0]]
        if len(SAMPLE_ENROLMENTS["challenges"]) == before:
            h.send(400, views.stepca(ctx, "enrol", SAMPLE_CA, enrolments=SAMPLE_ENROLMENTS,
                                     err=f"no open profile {parts[0]!r}"))
        else:
            h.send(200, views.stepca(ctx, "enrol", SAMPLE_CA, enrolments=SAMPLE_ENROLMENTS,
                                     msg="Withdrew the profile (dev preview)."))
    else:
        h.send(404, views.error_page(404, "Not found."))
    return True
