import hashlib
import json


def lists_version(rows):
    """Purpose: the version of the site's lists as a page showed them (manual 1.12.3.17): a SHA-256 of each list on
             the site and whether it is ticked, so an Apply sent from a page whose lists changed since (another
             person, the CLI) is refused instead of undoing that change.
    Inputs:  rows — filter_lists' rows (url, on_site, enabled), or the console's sample of them.
    Returns: 64 hex characters (the same for the same lists in any order).
    Fails:   never.
    Feeds:   dns_filter/filter_overview (the page's hidden version), agent/pending_filter (the Apply's check), the dev
             preview's read."""
    site = sorted((str(r.get("url") or ""), bool(r.get("enabled"))) for r in rows or [] if r.get("on_site"))
    return hashlib.sha256(json.dumps(site).encode()).hexdigest()
