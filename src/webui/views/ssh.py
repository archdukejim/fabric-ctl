from webui.views.b64 import b64
from webui.views.render_page import render_page


def ssh(ctx, ov, signed=None, msg="", err="", hosts=None):
    """Purpose: the SSH page (manual 1.6.11.9.5): whether SSH certificates are on (with the toggle for system:admin),
             the CA's public key and fingerprint, and the form a fabric admin pastes a public key into.
    Inputs:  ctx — page context; ov — ssh_overview() ({on, public_key, fingerprint, may_sign, why_not, hours});
             signed — sign_ssh_key()'s result, shown once with a download, or None; msg, err — flash texts; hosts —
             ssh_hosts()'s result (the host CA and each machine's host certificate, 1.6.11.9.11), {"error"}, or None
             (not shown: the person may not see the domain's machines).
    Returns: HTML str.
    Fails:   jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/get_page (/ssh), src/webui/routes/ssh_post; devserver.
    """
    cert_b64 = b64(signed["certificate"] + "\n") if signed else ""
    return render_page("ssh", ctx=ctx, tab="ssh", ov=ov, signed=signed, cert_b64=cert_b64, msg=msg, err=err,
                       hosts=hosts)
