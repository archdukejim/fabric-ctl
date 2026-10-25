from agent.job_store import JOBS
from agent.plan_store import PLANS
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.settings.apply_settings import apply_settings
from fabriclib.settings.mark_wizard_finished import mark_wizard_finished
from fabriclib.settings.parse_settings_file import parse_settings_file
from fabriclib.settings.plan_is_current import plan_is_current
from fabriclib.settings.plan_settings import plan_settings
from fabriclib.settings.read_settings import read_settings
from fabriclib.settings.settings_from_form import settings_from_form


def _applied(plan, actor):
    """Purpose: the apply job's work: the plan applied; an apply that did not finish fails the job with its output.
    Inputs:  plan — the plan; actor — who.
    Returns: {"message", "keys", "output"}.
    Fails:   ValidationError (the job's error): stale, or the apply did not finish (its message and last output).
    Feeds:   post_settings (apply, as a job)."""
    res = apply_settings(plan, actor)
    if not res["ok"]:
        raise ValidationError(res["message"] + " " + res["output"][-1200:])
    return {"message": res["message"], "keys": res["keys"], "output": res["output"][-2000:]}


def post_settings(route, actor, data, owner):
    """Purpose: the setup wizard's changes (manual 1.8.5.5, decision 2.1.8.7): POST /v1/settings/plan (body: "form",
             the wizard's fields, or "file", a settings file's text) makes the plan and keeps it for its Apply;
             POST /v1/settings/apply (body: "plan", its id) starts one apply job, or, when someone applied first,
             answers the plan made again; POST /v1/settings/dismiss records the wizard dismissed. Each needs
             settings:admin (rbac/required_permission).
    Inputs:  route — segments after /v1/; actor — the verified user; data — the body; owner — who may read the
             plan and the job (None for root).
    Returns: plan: the plan with its "id" (plan_settings); apply: {"id"} of a job read with GET /v1/jobs/<id>, or
             {"stale": True, "plan": the plan made again}; dismiss: {"how", "by", "at"}.
    Fails:   ValidationError (-> 400, nothing changed): neither or both of form and file; what parse_settings_file,
             settings_from_form or plan_settings refuse; an unknown, expired or another person's plan. RouteNotFound
             for another route.
    Feeds:   agent/post_route."""
    if route == ["settings", "plan"]:
        form, text = data.get("form"), data.get("file")
        if (form is None) == (text is None):
            raise ValidationError("give the wizard's fields or a settings file")
        v = load_vars()
        if text is not None:
            parsed = parse_settings_file(str(text), known=v)
            return PLANS.put(owner, plan_settings(v, parsed["settings"], parsed["ignored"], source="file"))
        if not isinstance(form, dict):
            raise ValidationError("form: the wizard's fields")
        given = settings_from_form({str(k): str(val) for k, val in form.items()}, read_settings(v))
        return PLANS.put(owner, plan_settings(v, given, source="web"))
    if route == ["settings", "apply"]:
        plan = PLANS.take(data.get("plan"), owner)
        v = load_vars()
        if not plan_is_current(plan, v):
            return {"stale": True, "plan": PLANS.put(owner, plan_settings(v, plan["given"], plan["ignored"],
                                                                          source=plan["source"]))}
        return JOBS.start("settings", owner, lambda: _applied(plan, actor))
    if route == ["settings", "dismiss"]:
        return mark_wizard_finished("dismissed", actor, "web")
    raise RouteNotFound()
