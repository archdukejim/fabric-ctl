import hashlib


def list_id(url):
    """Purpose: a list's id (manual 1.12.3.5): the first 12 hex digits of the SHA-256 of its URL, so renaming or
             reordering lists never touches one. Its copy is <base>/dnsfilter/lists/<id>.txt; AdGuard Home knows it
             by the same number (int(id, 16), 48 bits).
    Inputs:  url — the list's URL (str), as in dns_filter_lists.
    Returns: str, e.g. "3f2a9c1b7d4e".
    Fails:   never.
    Feeds:   dns_filter/update_lists, deploy_adguard, sync_adguard, filter_overview; common/list_zone (the query
             log's name for a list)."""
    return hashlib.sha256(url.strip().encode()).hexdigest()[:12]
