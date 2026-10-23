from webui.views.render_page import render_page


def radius_secret(ctx, name, secret, action, host_ip, applied=True, output=""):
    """Purpose: The page that shows a RADIUS client's shared secret once, after adding it or making a new one.
    Inputs:  ctx — page context; name — client name; secret — str; action — 'added' or 'rotated'; host_ip — the
             RADIUS server address to enter on the device; applied — bool, whether applying worked; output — apply
             output, only its last 300 characters are shown.
    Returns: HTML str.
    Fails:   TypeError if output is not a str (it is sliced); otherwise never in practice.
    Feeds:   src/webui/routes/radius_post; devserver.
    """
    return render_page("radius_secret", ctx=ctx, page="/8021x", client=name, secret=secret, action=action,
                   host_ip=host_ip, applied=applied, output=output[-300:])
