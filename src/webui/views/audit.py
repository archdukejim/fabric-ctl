from webui.views.render_page import render_page


def audit(ctx, lines):
    """Purpose: The audit log page, newest first.
    Inputs:  ctx — page context; lines — iterable of str from read_audit(), printed one after the other as is (each
             carries its own line break).
    Returns: HTML str.
    Fails:   never in practice (plain values).
    Feeds:   src/webui/routes/get_page (/audit); devserver.
    """
    return render_page("audit", ctx=ctx, page="/audit", lines=lines)
