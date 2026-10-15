import os

from fabriclib.common.errors import ValidationError
from fabriclib.dns.common.landing_names import landing_names
from fabriclib.pki.common.cert_names import cert_names
from fabriclib.setup.context import SetupContext
from fabriclib.setup.renew_service_certs import renew_service_certs


def renew_landing_cert(paths, final_vars, renew=renew_service_certs):
    """Purpose: the end of an apply on a running install: when the landing page's names (landing_names: the host's own
             name, <domain> and the admin's aliases of the host) are not exactly the names its certificate holds, the
             certificate is issued again at once rather than at its renewal (decision 2.1.4.8, manual 1.4.2.6): a
             renamed alias gets HTTPS with this apply, the old name is no longer served with it. The one it replaces
             is not revoked: it expires (2.1.4.8, revised 2026-10-12).
    Inputs:  paths — deploy_paths() (base); final_vars — the applied settings (hostname_landing names the
             certificate's folder); renew — renew_service_certs (a test passes its own).
    Returns: True when the certificate was issued again (nginx has taken it), False when its names were current or
             it does not exist yet (setup's `certs` step issues the first one).
    Fails:   ValidationError when the certificate could not be issued: the apply says so instead of passing
             quietly; the renewal record holds it too (status, doctor).
    Feeds:   deploy/apply_deployment."""
    folder = os.path.join(paths["base"], "nginx", "certs", str(final_vars.get("hostname_landing") or ""))
    have = cert_names(os.path.join(folder, "fullchain.pem"))
    if have is None or have == set(landing_names(final_vars)):
        return False
    print("The landing page's names changed: issuing its certificate again (2.1.4.8)...")
    ctx = SetupContext(deploy_base=paths["base"])
    if renew(ctx) != 0:
        raise ValidationError("the landing page's certificate could not be issued again for its new names "
                              "(see `sudo fabricctl status`)")
    return True
