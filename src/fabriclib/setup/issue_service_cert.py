import os

from fabriclib.pki.install_cert import install_cert
from fabriclib.pki.mint_cert import mint_cert


def issue_service_cert(ctx, cn, sans, dests):
    """Purpose: issue one service certificate from Step-CA and install it in each of its destinations; the key never
             stays anywhere else (manual 2.1.5.4).
    Inputs:  ctx — SetupContext (vars, path, uid); cn — its name; sans — its other names; dests — [(folder, service
             user)], "freeradius:eap" for FreeRADIUS' EAP-TLS server certificate (server.pem, server.key).
    Returns: None. The services that use it pick it up only when the caller says so (pick_up_cert).
    Fails:   SetupError from mint_cert (Step-CA refused or is down); OSError/CalledProcessError installing it.
    Feeds:   setup/mint_service_certs.run, pki/replace_service_cert."""
    root_ca = ctx.path("stepca", "data", "certs", "root_ca.crt")
    crt, key = mint_cert(ctx, cn, sans, cn.replace(".", "-"))
    try:
        for dest, user in dests:
            if user == "freeradius:eap":
                install_cert(crt, key, root_ca, dest, *ctx.uid("freeradius"), names=("server.pem", "server.key", None))
            else:
                install_cert(crt, key, root_ca, dest, *ctx.uid(user))
    finally:
        os.remove(key)
        os.remove(crt)
