import secrets

from fabriclib.setup.site.listener.finish_html import finish_html
from fabriclib.setup.site.listener.notes_html import notes_html
from fabriclib.setup.site.listener.render_page import escape, render_page

LOG_SHOWN = 400


def _log_text(state):
    """Purpose: the run's log as a page opens with it; /events adds what follows.
    Inputs:  state — SiteState.
    Returns: str, the last LOG_SHOWN lines.
    Fails:   never.
    Feeds:   page_for."""
    return "\n".join(state.log[-LOG_SHOWN:])


def _field(q):
    """Purpose: the input of one question, or its buttons.
    Inputs:  q — the question message: choices [(value, label)], secret, default.
    Returns: str, HTML.
    Fails:   never.
    Feeds:   _question."""
    if q.get("choices"):
        return "".join(f'<button name="value" value="{escape(v)}"{" class=secondary" if i else ""}>{escape(t)}</button>'
                       for i, (v, t) in enumerate(q["choices"]))
    kind = 'type="password" autocomplete="new-password"' if q.get("secret") else 'type="text" autocomplete="off"'
    value = "" if q.get("secret") else escape(q.get("default") or "")
    return (f'<input id="value" name="value" {kind} value="{value}" autofocus spellcheck="false" '
            'autocapitalize="off"><button>Continue</button>')


def _question(state):
    """Purpose: the page of the question setup is asking now.
    Inputs:  state — SiteState.
    Returns: str, the page.
    Fails:   never.
    Feeds:   page_for."""
    q = state.question
    plan = q["qid"] == "setup.plan"
    return render_page(state, "plan" if plan else "question", "The plan" if plan else "A question",
                       step=2 if plan else 1,
                       label=q.get("label", ""), csrf=state.csrf, seq=q["seq"],
                       raw_permanent='<span class="permanent">⚠ Permanent</span>' if q.get("permanent") else "",
                       raw_notes=notes_html(q.get("notes") or []), raw_field=_field(q))


def _finish(state):
    """Purpose: the finish page (manual 1.3.6.6).
    Inputs:  state — SiteState: finish, fingerprint, csrf.
    Returns: str, the page.
    Fails:   KeyError for finish data missing a key (setup's own).
    Feeds:   page_for."""
    f = state.finish
    new_cert = ("" if state.temporary else
                '<p>This page now runs on a certificate from fabric\'s own CA.</p>')
    kept = f"<p class=warning>{escape(f['kept_temporary'])}</p>" if f.get("kept_temporary") else ""
    return render_page(state, "finish", "fabric is installed", step=4, csrf=state.csrf, port=state.port,
                       root_fingerprint=f["root_fingerprint"], certs_url=f["certs_url"], console_url=f["console_url"],
                       console_name=f["console_name"], kit=f["kit"], nonce=secrets.token_hex(8),
                       raw_new_cert=new_cert + kept, **finish_html(f))


def page_for(state):
    """Purpose: what a signed-in person sees now.
    Inputs:  state — SiteState: phase and what goes with it.
    Returns: str, the page.
    Fails:   never for a phase setup sends.
    Feeds:   listener/request_handler."""
    phase = state.phase
    if phase == "question" and state.question:
        return _question(state)
    if phase == "running":
        return render_page(state, "progress", "Installing", step=3, refresh=None, raw_noscript=(
            '<noscript><meta http-equiv="refresh" content="5"></noscript>'), log=_log_text(state), logged=state.logged)
    if phase == "failed":
        return render_page(state, "failed", "Setup stopped", step=3, why=state.why, log=_log_text(state),
                           csrf=state.csrf, logged=state.logged)
    if phase == "restarting":
        return render_page(state, "restarting", "A new certificate", step=4, refresh=12, stream=False,
                           new_fingerprint=state.why)
    if phase == "finish":
        return _finish(state)
    if phase == "closed":
        return render_page(state, "closed", "The site has closed", stream=False, why=state.why)
    return render_page(state, "working", "One moment", step=1, refresh=2, stream=False)
