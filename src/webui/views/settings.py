from webui.views.constants import WIZARD_FIELDS, WIZARD_STEPS
from webui.views.render_page import render_page


def settings(ctx, overview, step="parts", form=None, msg="", err="", signin_old=False, relaxed=()):
    """Purpose: the setup wizard (manual 1.8.5.3): one step of Optional parts, Memory, Passwords and sign-in, the DNS
             filter's upstreams and Review; every other step's fields carried as hidden fields, so Back and Next keep
             what was typed and nothing changes before the plan. The first step shows the console-only settings read
             only, with the command that changes each; every step shows today's value beside what was typed. Export,
             Import and (until the wizard is finished) Dismiss are on every step.
    Inputs:  ctx — page context; overview — settings_overview(); step — a WIZARD_STEPS step (another: the first);
             form — {field: text} typed so far (None: today's, overview["form"]); msg, err — flash texts;
             signin_old — True when the last sign-in is older than the 5 minutes Apply needs (said up front);
             relaxed — routes/relaxations' answer (the relaxations that are on, 2.1.8.20; None: not readable).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/settings_page (/settings), settings_post (/settings/step, a refused plan or import)."""
    steps = [s for s, _, _ in WIZARD_STEPS]
    step = step if step in steps else steps[0]
    today = overview.get("form") or {}
    typed = {f: str((form if form is not None else today).get(f, today.get(f, ""))) for f in WIZARD_FIELDS}
    at = steps.index(step)
    changed = [(f, today.get(f, ""), typed[f]) for f in WIZARD_FIELDS if typed[f] != today.get(f, "")]
    return render_page("settings", ctx=ctx, page="/settings", ov=overview, step=step, steps=WIZARD_STEPS,
                       fields=dict((s, fl) for s, _, fl in WIZARD_STEPS)[step], typed=typed, today=today,
                       prev=steps[at - 1] if at else "", next=steps[at + 1] if at + 1 < len(steps) else "",
                       changed=changed, msg=msg, err=err, signin_old=signin_old, relaxed=relaxed)
