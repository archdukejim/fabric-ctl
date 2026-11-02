import os
import re

from fabriclib.dns.merge_dynamic_records import KEPT_HEAD

SERIAL_RE = re.compile(r"^\s*\d+\s*;\s*Serial.*$", re.MULTILINE)


def zone_content_changed(src, dst):
    """Purpose: tell whether a rendered zone file differs from the deployed one, ignoring the SOA serial (which changes
             on every render) and, in a reverse zone, the records kept from DHCP's registrations that
             install_zone_file appended (merge_dynamic_records: they are Kea's, never rendered).
    Inputs:  src — rendered zone file path; dst — deployed zone file path.
    Returns: True if dst is missing or the records differ, else False.
    Fails:   OSError if src (or an existing dst) cannot be read.
    Feeds:   find_changed_zones."""
    if not os.path.exists(dst):
        return True
    with open(src) as a, open(dst) as b:
        new, old = a.read(), b.read()
    if KEPT_HEAD in old:                    # fabric's part of the file, as merge_dynamic_records put it
        new, old = new.rstrip("\n"), old.split(KEPT_HEAD, 1)[0]
    return SERIAL_RE.sub("", new) != SERIAL_RE.sub("", old)
