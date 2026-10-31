from webui.views.render_page import render_page


def person_result(ctx, uid, what, password):
    """Purpose: The page that shows a person's one-time password once, after creating them or resetting their sign-in.
    Inputs:  ctx — page context; uid — user name; what — 'created' or 'reset'; password — the one-time password str.
    Returns: HTML str.
    Fails:   never in practice (plain values).
    Feeds:   src/webui/routes/directory_post; devserver.
    """
    return render_page("person_result", ctx=ctx, page="/directory/people", uid=uid, what=what, password=password)
