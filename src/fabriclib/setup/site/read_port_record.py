import json
import os

from fabriclib.setup.site.constants import PORT_RECORD


def read_port_record(path=PORT_RECORD):
    """Purpose: the site's port, if a site is running now (write_port_record).
    Inputs:  path — the record.
    Returns: {"port", "cidr", "pid"} when the record exists and the process holding the site still runs; None otherwise
             (no site, a damaged record, or one left by a process that was killed).
    Fails:   never.
    Feeds:   setup/site/keep_site_port, setup/site/close_site_port, consent/plan_firewall."""
    try:
        with open(path) as f:
            record = json.load(f)
        os.kill(int(record["pid"]), 0)
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return record
