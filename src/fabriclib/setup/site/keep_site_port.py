import subprocess

from fabriclib.setup.site.constants import PORT_RECORD
from fabriclib.setup.site.read_port_record import read_port_record
from fabriclib.setup.site.site_rule import site_rule


def keep_site_port(record=PORT_RECORD, run=subprocess.run):
    """Purpose: setup's own firewall step turns ufw on with incoming denied, which would cut the running site off from
             its browser: while a site runs, its port stays allowed (manual 1.3.6.7). The plan lists this rule, so
             Proceed allowed it (consent/plan_firewall); close_site_port removes it when the site stops.
    Inputs:  record — the site's record; run — subprocess.run.
    Returns: the port (int), or None when no site runs.
    Fails:   subprocess.CalledProcessError when ufw refuses.
    Feeds:   setup/configure_firewall."""
    site = read_port_record(record)
    if not site:
        return None
    run(["ufw", "allow", *site_rule(site["port"], site.get("cidr"))], check=True, capture_output=True)
    return site["port"]
