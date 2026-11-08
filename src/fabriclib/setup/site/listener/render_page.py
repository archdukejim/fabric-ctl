import html
import string

STEPS = ("Sign in", "Questions", "Plan", "Install", "Finish")
TEMPORARY = ("Temporary certificate in use. Its SHA-256 fingerprint is <code>{fp}</code>: compare it with the host's "
             "terminal. If you skip that, someone on your LAN could intercept this page; the one-time code does not "
             "prevent that.")


def escape(value):
    """Purpose: a value as text in a page (manual 1.1.5.7).
    Inputs:  value — anything; str() of it is used.
    Returns: str, escaped, quotes included.
    Fails:   never.
    Feeds:   this file and the page builders."""
    return html.escape(str(value), quote=True)


def fill(template, values):
    """Purpose: fill one template file. Values are escaped unless their name starts with raw_.
    Inputs:  template — str, $name placeholders; values — dict.
    Returns: str.
    Fails:   never: an unknown placeholder stays as it is.
    Feeds:   render_page, the page builders."""
    safe = {k: (v if k.startswith("raw_") else escape(v)) for k, v in values.items()}
    return string.Template(template).safe_substitute(safe)


def _steps(current):
    """Purpose: the row of steps at the top of each page.
    Inputs:  current — int, the step's position, or None: no step lit.
    Returns: str, HTML.
    Fails:   never.
    Feeds:   render_page."""
    return "".join(f'<li{" aria-current=step" if n == current else ""}>{name}</li>' for n, name in enumerate(STEPS))


def render_page(state, name, title, step=None, refresh=None, stream=True, **values):
    """Purpose: one whole page: the template in base.html's frame, the temporary certificate said for as long as it is
             in use (deviation 2.1.1.93).
    Inputs:  state — SiteState (files, fingerprint, temporary, version); name — template file; title — str; step —
             STEPS' position; refresh — seconds, reloading without script; stream — whether the page follows
             /events; values — the template's values.
    Returns: str, the page.
    Fails:   KeyError for a template that is not there.
    Feeds:   listener/page_for, listener/request_handler."""
    banner = ""
    if state.temporary:
        banner = '<p class="relaxed" role="status">' + TEMPORARY.format(fp=escape(state.fingerprint)) + "</p>"
    head = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
    return fill(state.files["base.html"], {
        "title": title, "raw_head": head + values.pop("raw_noscript", ""), "raw_steps": _steps(step),
        "raw_banner": banner,
        "version": state.version, "stream": "1" if stream else "0",
        "raw_body": fill(state.files[name + ".html"], values)})
