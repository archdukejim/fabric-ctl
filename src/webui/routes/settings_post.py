import time
import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.constants import STEP_UP
from webui.routes.relaxations import relaxations
from webui.session.page_context import page_context
from webui.views.constants import WIZARD_FIELDS

STALE = ("Someone else applied first, so this plan was refused and nothing changed. Below is the plan made again "
         "against today's settings: review it and apply again.")


def _file_text(form):
    """Purpose: an imported settings file's text: the uploaded file (UTF-8), else the pasted text.
    Inputs:  form — dict from read_form (file: bytes, text: str).
    Returns: str ("" when neither was given or the file is not UTF-8 text).
    Fails:   never.
    Feeds:   settings_post (import)."""
    data = form.get("file")
    if isinstance(data, bytes) and data:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    text = form.get("text", "")
    return text if isinstance(text, str) else ""


def settings_post(h, sess, parts, form):
    """Purpose: the setup wizard's forms (manual 1.8.5.3-1.8.5.5): Back and Next between its steps (nothing saved), the
             plan from what was typed or from an imported settings file, Apply (one apply job, after a sign-in from
             the last 5 minutes), Dismiss.
    Inputs:  h — the request handler (send, redirect, deny); sess — dict from find_session (auth_at); parts —
             segments after /settings/: ['step'] (go: the step to show), ['plan'], ['import'] (file or text),
             ['apply'] (plan: its id), ['dismiss']; form — the wizard's fields (WIZARD_FIELDS) and the rest.
    Returns: step: 200 that step with what was typed; plan and import: 200 the plan, or the wizard (plan: the Review
             step with what was typed; import: the first step) saying why it was refused; apply: 303 to the job's
             page, 303 to /login?next=/settings?signed_in=1 when the last sign-in is older than STEP_UP (300 s),
             200 the plan made again when someone applied first, or 303 to /settings with the refusal as its message
             (no such plan); dismiss: 303 to /.
    Fails:   404 for another path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/settings/…)."""
    typed = {f: form[f] for f in WIZARD_FIELDS if isinstance(form.get(f), str)}
    if parts == ["step"]:
        ctx = page_context(sess)
        return h.send(200, views.settings(ctx, actions.settings_overview(), form.get("go", ""), typed,
                                          signin_old=time.time() - sess.get("auth_at", 0) > STEP_UP,
                                          relaxed=relaxations(ctx)))
    if parts == ["plan"]:
        try:
            plan = actions.settings_plan(form=typed)
        except actions.ValidationError as exc:
            return h.send(200, views.settings(page_context(sess), actions.settings_overview(), "review", typed,
                                              err=f"Refused, nothing changed: {exc}"))
        return h.send(200, views.settings_plan(page_context(sess), plan))
    if parts == ["import"]:
        text = _file_text(form)
        if not text.strip():
            return h.back("/settings", err="Choose a settings file (UTF-8 YAML) or paste it.")
        try:
            plan = actions.settings_plan(file=text)
        except actions.ValidationError as exc:
            return h.back("/settings", err=f"The file was refused, nothing changed: {exc}")
        return h.send(200, views.settings_plan(page_context(sess), plan))
    if parts == ["apply"]:
        if time.time() - sess.get("auth_at", 0) > STEP_UP:
            return h.redirect("/login?next=/settings%3Fsigned_in%3D1")
        try:
            res = actions.settings_apply(form.get("plan", ""))
        except actions.ValidationError as exc:
            return h.back("/settings", err=str(exc))
        if res.get("stale"):
            return h.send(200, views.settings_plan(page_context(sess), res["plan"], err=STALE))
        return h.redirect("/jobs/" + urllib.parse.quote(res["id"], safe=""))
    if parts == ["dismiss"]:
        actions.settings_dismiss()
        return h.redirect("/")
    return h.deny(404, "Not found.")
