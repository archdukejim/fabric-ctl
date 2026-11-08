import re

ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BRACKET = re.compile(r"\s*\[([^\]]*)\]\s*:?\s*$")
PLAN_CHOICES = [("p", "Proceed (allows the host changes listed)"), ("q", "Cancel: change nothing")]
YES_NO = [("y", "Yes"), ("n", "No")]


def question_view(qid, prompt, secret):
    """Purpose: a question as the page shows it: the terminal's own words, its "[default]" taken out as the field's
             value, its colour codes gone, yes-or-no and the plan as buttons (manual 1.3.6.4).
    Inputs:  qid — the question's stable ID; prompt — str as given to ask(); secret — bool.
    Returns: dict: qid, label, default (str), permanent (bool), secret, choices (list of [value, label], or []). The
             plan offers Proceed and Cancel: Advanced's menu stays in the terminal (1.3.6.1).
    Fails:   never.
    Feeds:   setup/site/guided_site."""
    label = ANSI.sub("", prompt).strip()
    choices, default = [], ""
    if qid == "setup.plan":
        can_proceed = "roceed" in label          # a plan with a problem offers no Proceed: the notes say why
        label = "Proceed with this plan?" if can_proceed else "Setup cannot proceed with this plan."
        choices = PLAN_CHOICES if can_proceed else PLAN_CHOICES[1:]
    else:
        found = _BRACKET.search(label)
        if found:
            label, default = label[:found.start()], found.group(1)
        label = label.rstrip(": ").strip()
        if default.lower() == "y/n":
            default, choices = "", (YES_NO if found.group(1)[0] == "Y" else YES_NO[::-1])
    permanent = "⚠ Permanent" in label
    return {"qid": qid, "label": label.replace("⚠ Permanent", "").strip(), "default": default, "permanent": permanent,
            "secret": secret, "choices": [list(c) for c in choices]}
