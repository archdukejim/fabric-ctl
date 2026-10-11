from fabriclib.dns_filter.common.list_id import list_id


def list_zone(url):
    """Purpose: a list's name in the query log and its statistics (manual 1.12.2.13, 1.12.3.7): `<id>.list.rpz`, as
             when the lists were response policy zones (1.12.2.6), so the log's older rows still lead to their list.
    Inputs:  url — the list's URL (str), as in dns_filter_lists.
    Returns: str, e.g. "3f2a9c1b7d4e.list.rpz".
    Fails:   never.
    Feeds:   dns_filter/ingest_dns_log, read_query_log, dns_filter_stats."""
    return list_id(url) + ".list.rpz"
