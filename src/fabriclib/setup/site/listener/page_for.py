import secrets

from fabriclib.setup.site.listener.finish_html import finish_html
from fabriclib.setup.site.listener.notes_html import notes_html
from fabriclib.setup.site.listener.render_page import escape, render_page

LOG_SHOWN = 400
# What a restore moved, named as its questions name it: a copy of ask_restore.LABELS, which the listener cannot
# import (it runs from its own folder, 1.3.6); tests/setup/site/ask_restore_test.py keeps the two the same.
LABELS = {"host_ip": "The host's address", "lan_cidr": "Its subnet", "lan_gateway": "The subnet's gateway",
          "dns_server": "The upstream DNS server"}


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


def _upload_form(state, q):
    """Purpose: Restore from a backup's other way to give the bundle: upload it from this computer (manual 1.3.7.10).
             The hidden fields come first, so the browser sends the token before the file.
    Inputs:  state — SiteState (csrf); q — the bundle's question (seq).
    Returns: str, HTML.
    Fails:   never.
    Feeds:   _question."""
    return (f'<form method="post" action="/upload" enctype="multipart/form-data" class="question upload">'
            f'<input type="hidden" name="csrf" value="{escape(state.csrf)}">'
            f'<input type="hidden" name="seq" value="{escape(str(q["seq"]))}">'
            '<label for="bundle">Or upload one from this computer: up to 8 GiB, with the name it was downloaded '
            'with. Keep this page open while it is sent.</label>'
            '<div class="row"><input id="bundle" name="bundle" type="file" accept=".tar" required>'
            '<button class="secondary">Upload</button></div></form>')


def _question(state):
    """Purpose: the page of the question setup is asking now.
    Inputs:  state — SiteState.
    Returns: str, the page.
    Fails:   never.
    Feeds:   page_for."""
    q = state.question
    plan = q["qid"] in ("setup.plan", "restore.plan")
    return render_page(state, "plan" if plan else "question", "The plan" if plan else "A question",
                       step=2 if plan else 1,
                       label=q.get("label", ""), csrf=state.csrf, seq=q["seq"],
                       raw_permanent='<span class="permanent">⚠ Permanent</span>' if q.get("permanent") else "",
                       raw_notes=notes_html(q.get("notes") or []), raw_field=_field(q),
                       raw_upload=_upload_form(state, q) if q["qid"] == "restore.bundle" else "")


def _restored(restored):
    """Purpose: what a Restore from a backup moved, for its finish (manual 1.3.7.10 step 5).
    Inputs:  restored — {"changed": {key: [old, new]}, "leftover": [[setting, value]]}, or None for a new install.
    Returns: str, HTML ("" for a new install).
    Fails:   never.
    Feeds:   _finish."""
    if not restored:
        return ""
    moved = "".join(f"<li>{escape(LABELS.get(k, k))}: {escape(str(old))} → {escape(str(new))}</li>"
                    for k, (old, new) in restored.get("changed", {}).items())
    left = "".join(f"<li><code>{escape(str(s))}</code> = {escape(str(v))}</li>"
                   for s, v in restored.get("leftover", []))
    return ("<h2>Restored from the bundle</h2>"
            + (f"<p>What moved:</p><ul>{moved}</ul>" if moved else "<p>Everything is back at the bundle's addresses."
                                                                    "</p>")
            + (f"<p class=warning>Your own settings still name the old address or subnet: change them in the "
               f"console.</p><ul>{left}</ul>" if left else ""))


def _finish(state):
    """Purpose: the finish page (manual 1.3.6.6), with what a restore moved (1.3.7.10).
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
                       raw_new_cert=new_cert + kept + _restored(f.get("restored")), **finish_html(f))


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
