from webui.views.render_page import render_page


def machine_result(ctx, name, password):
    """Purpose: The page that shows a pre-created machine's one-time join password once.
    Inputs:  ctx — page context; name — the machine's host name; password — the one-time join password str.
    Returns: HTML str.
    Fails:   never in practice (plain values).
    Feeds:   src/webui/routes/directory_post; devserver.
    """
    return render_page("machine_result", ctx=ctx, page="/directory/machines", name=name, password=password)
