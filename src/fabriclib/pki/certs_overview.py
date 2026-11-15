from fabriclib.pki.list_certs import list_certs


def certs_overview(v):
    """Purpose: the PKI page's Issued list (decision 2.1.5.13, manual 1.5.1.9.1): every certificate the console can
             revoke, with each 802.1X machine certificate's device and its roles from the directory.
    Inputs:  v — settings (deploy_base_dir; the directory's, for the devices).
    Returns: list_certs' result, plus "directory_error": why the devices could not be read ("" when they were: a
             row then keeps its device's name without its roles).
    Fails:   as list_certs (OSError).
    Feeds:   agent route GET /v1/pki/certs, agent route POST /v1/pki/lookup."""
    from fabriclib.directory.list_devices import list_devices       # imported here: the directory is optional
    from fabriclib.setup.context import SetupContext
    ctx = SetupContext(deploy_base=v["deploy_base_dir"])
    ctx.vars = v
    devices, error = None, ""
    try:
        devices = {d["name"]: d for d in list_devices(v)}
    except Exception as exc:                 # the directory down or not set up: said on the page, rows keep names
        error = str(exc) or type(exc).__name__
    out = list_certs(v, ctx, devices=devices)
    out["directory_error"] = error
    return out
