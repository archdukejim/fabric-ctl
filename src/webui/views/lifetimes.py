from webui.views.render_page import render_page


def lifetimes(ctx, life, unavailable=""):
    """Purpose: PKI → Lifetimes (decision 2.1.5.14, manual 1.5.1.10): fabric's own certificates' lifetime and renew
             at, the ACME lifetime, the hand-issued default and maximum, each change held for PKI's Apply.
    Inputs:  ctx — page context; life — read_lifetimes' dict, or None when it cannot be read; unavailable — why not.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/lifetimes_page; devserver."""
    return render_page("lifetimes", ctx=ctx, page="/pki/lifetimes", life=life, unavailable=unavailable)
