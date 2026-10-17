def suggested_dc_name(hostname):
    """Purpose: the domain controller's name setup suggests (2.1.6.45 as revised by 2.1.6.60, manual 1.6.5.23): the
             host's name and `-dc`, so the name says which machine the DC lives on; the host's part cut so the whole
             fits 15 characters (a NetBIOS name), never ending in a hyphen the cut left. Any valid name may be given
             instead.
    Inputs:  hostname — str, the host's name (one label).
    Returns: str, lower case (pi-core -> pi-core-dc; raspberrypi-4b -> raspberrypi-dc); "" without a host name.
    Fails:   never.
    Feeds:   setup/ask_dc_name; vars.yaml.j2 makes the same default (tests/render.py checks they agree)."""
    name = str(hostname or "").strip().lower()
    return name[:12].rstrip("-") + "-dc" if name else ""
