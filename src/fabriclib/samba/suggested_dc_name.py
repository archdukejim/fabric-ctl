def suggested_dc_name(hostname):
    """Purpose: the domain controller's name setup suggests (2.1.6.45, manual 1.6.5.23): `dc-` and the host's name, so
             the name says which machine the DC lives on, cut to 15 characters (a NetBIOS name) and never ending in
             a hyphen the cut left.
    Inputs:  hostname — str, the host's name (one label).
    Returns: str, lower case (pi-core -> dc-pi-core; raspberrypi-4b -> dc-raspberrypi); "" without a host name.
    Fails:   never.
    Feeds:   setup/ask_dc_name; vars.yaml.j2 makes the same default (tests/render.py checks they agree)."""
    name = str(hostname or "").strip().lower()
    return ("dc-" + name)[:15].rstrip("-") if name else ""
