import os

from fabriclib.dns.reload_zone import file_serial
from fabriclib.dns.zone_content_changed import zone_content_changed


def _not_loaded(zone, dst, served):
    """Purpose: whether BIND serves a zone at a serial below its deployed file's: a file BIND never loaded (it refused
             it, and kept its older copy: 2.3.10.11.16), which no change of fabric's records would ever swap again.
             A dynamic zone's served serial only grows past its file's (each update raises it), so it never counts.
    Inputs:  zone — its name; dst — the deployed file; served — callable(zone) -> BIND's serial (str) or None.
    Returns: bool; False when BIND does not answer, the file is missing or either serial is unreadable.
    Fails:   never (an unreadable file reads as no serial).
    Feeds:   find_changed_zones."""
    if served is None or not os.path.exists(dst):
        return False
    try:
        mine = file_serial(dst)
    except OSError:
        return False
    theirs = served(zone)
    return bool(mine and theirs and int(theirs) < int(mine))


def find_changed_zones(src_dir, dst_dir, served=None):
    """Purpose: find the rendered zone files (db.<zone>) whose records differ from the deployed ones, and the zones
             BIND serves older than their deployed file (it did not load it).
    Inputs:  src_dir — rendered bind9/data directory; dst_dir — deployed bind9/data directory; served —
             callable(zone) -> the serial BIND serves (dns/served_serial), or None to compare files only.
    Returns: [(zone, src, dst)] for each changed zone, sorted by file name; [] if src_dir does not exist.
    Fails:   OSError if a file cannot be read (from zone_content_changed).
    Feeds:   deploy/install_bind9_files (the zones installed or reloaded later), dns/publish_plan_records (Sync now);
             tests/zone_test.py.
    Notes:   copies nothing: installing is done by install_zone_file / reload_zone."""
    changed = []
    if not os.path.isdir(src_dir):
        return changed
    for fname in sorted(os.listdir(src_dir)):
        if not fname.startswith("db."):
            continue
        src, dst = os.path.join(src_dir, fname), os.path.join(dst_dir, fname)
        if zone_content_changed(src, dst) or _not_loaded(fname[3:], dst, served):
            changed.append((fname[3:], src, dst))
    return changed
