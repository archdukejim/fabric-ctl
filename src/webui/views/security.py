from webui.views.render_page import render_page


def security(ctx, layers, msg="", err=""):
    """Purpose: the Security page (manual 2.3.6.2.6.4, 2.1.6.24): each sign-in layer, its state, and the raises it
             offers; lowering is shown as the host command, never as a button.
    Inputs:  ctx — page context; layers — security_layers(); msg, err — flash texts.
    Returns: HTML str.
    Fails:   never in practice (plain values).
    Feeds:   src/webui/routes/get_page (/security); devserver.
    """
    return render_page("security", ctx=ctx, page="/settings/sign-in", layers=layers, msg=msg, err=err)
