from webui.views.render_page import render_page


def apply_result(ctx, ok, output):
    """Purpose: The page after Apply: whether it worked and its output.
    Inputs:  ctx — page context; ok — bool; output — str from apply_changes().
    Returns: HTML str.
    Fails:   never in practice (plain values).
    Feeds:   src/webui/routes/post_action (/apply); devserver.
    """
    return render_page("apply", ctx=ctx, page="/dns/zones", ok=ok, output=output)
