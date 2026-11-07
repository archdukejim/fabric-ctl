from fabriclib.setup.site.listener.render_page import escape


def _guide(guide):
    """Purpose: one operating system's illustrated steps and copyable commands.
    Inputs:  guide — dict: os, picture (a file under /static/), alt, steps (list of str), commands (list of str).
    Returns: str, HTML: a <details>, which opens without script.
    Fails:   KeyError for a guide missing a key (setup's own data).
    Feeds:   finish_html."""
    steps = "".join(f"<li>{escape(s)}</li>" for s in guide["steps"])
    commands = "\n".join(guide["commands"])
    block = (f'<div class="copy"><pre><code>{escape(commands)}</code></pre>'
             '<button type="button" class="copy-button" hidden>Copy</button></div>') if commands else ""
    return (f'<details><summary>{escape(guide["os"])}</summary><img src="/static/{escape(guide["picture"])}" '
            f'alt="{escape(guide["alt"])}" width="640" height="186"><ol>{steps}</ol>{block}</details>')


def finish_html(finish):
    """Purpose: the guides of the finish page (manual 1.3.6.6): trust, then DNS, each per operating system.
    Inputs:  finish — dict: trust, dns (lists of guides).
    Returns: {"raw_trust": HTML, "raw_dns": HTML}.
    Fails:   KeyError for data without them.
    Feeds:   listener/page_for."""
    return {"raw_trust": "".join(_guide(g) for g in finish["trust"]),
            "raw_dns": "".join(_guide(g) for g in finish["dns"])}
