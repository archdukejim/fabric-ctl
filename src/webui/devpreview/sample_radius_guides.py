from webui.devpreview.sample_data import SAMPLE_RADIUS, SAMPLE_ROOT_PEM


def sample_radius_guides():
    """Purpose: The FreeRADIUS setup guides as fabric-agent fills them in, built from the sample RADIUS data and the
             dev preview's own throwaway CA (SAMPLE_ROOT_PEM). Sample only; nothing is read from a host.
    Inputs:  none (reads SAMPLE_RADIUS and SAMPLE_ROOT_PEM).
    Returns: fabriclib.radius.radius_guides' dict ({"host_ip", "server_name", "people", "windows": {...}, ...}) from a
             checkout; without fabriclib (the webui image) a placeholder dict with the same keys the page reads.
    Fails:   never on a missing fabriclib (ImportError is caught); anything radius_guides raises propagates.
    Feeds:   Handler.do_GET for /freeradius (views "switches" and "windows").
    """
    try:
        from fabriclib.radius.radius_guides import radius_guides
    except ImportError:          # the webui image carries no fabriclib: placeholder scripts
        return {"host_ip": "192.168.1.2", "server_name": "radius.home.arpa", "people": ["staff"],
                "windows": {m: {"filename": f"fabric-8021x-{m}.ps1",
                                "script": "# dev preview: run devserver.py from a checkout for the real script"}
                            for m in ("tls", "ttls")}}
    return radius_guides({"host_ip": "192.168.1.2", "hostname_radius": "radius.home.arpa", "domain": "home.arpa",
                          "hostname_landing": "info.home.arpa", "radius_clients": SAMPLE_RADIUS["clients"],
                          "radius_people": SAMPLE_RADIUS["people"]}, root_pem=SAMPLE_ROOT_PEM)
