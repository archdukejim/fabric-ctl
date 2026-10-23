from webui.views.b64 import b64
from webui.views.render_page import render_page


def tsig_result(ctx, name, secret, ini, action):
    """Purpose: The page that shows a TSIG key's secret and RFC2136 client settings once.
    Inputs:  ctx — page context; name — key name; secret — str; ini — RFC2136 ini text (also offered as a download);
             action — 'created' or 'rotated'.
    Returns: HTML str.
    Fails:   AttributeError if ini is not a str (from _b64); otherwise never in practice.
    Feeds:   src/webui/routes/tsig_post; devserver.
    """
    return render_page("tsig_result", ctx=ctx, page="/dns/zones", key_name=name, secret=secret, ini=ini,
                       ini_b64=b64(ini),
                   action=action)
