import json

from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.adguard_api import adguard_api
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.fetch_catalogue import fetch_catalogue
from fabriclib.dns_filter.sync_adguard import sync_adguard
from fabriclib.dns_filter.update_lists import update_lists


def refresh_lists(v, password):
    """Purpose: the lists job (manual 1.12.3.5): AdGuard's catalogue read again, a copy of every list (the site's and
             the catalogue's) fetched, then AdGuard Home made to match (a list ticked before its copy arrived is added
             now) and asked to reread the copies that changed. Nothing restarts.
    Inputs:  v — rendered vars; password — adguard_api_password.
    Returns: update_lists' result, plus "catalogue": the number of lists in it (None when it could not be fetched: the
             last copy is used), "synced": sync_adguard's changes (None when AdGuard was not answering), "error": why
             AdGuard could not be reached or refused, or None.
    Fails:   OSError from update_lists writing its files.
    Feeds:   dns_filter/run_dns_filter_command (`fabricctl dns-filter lists`, the fabric-dns-lists timer and the
             console's Fetch now / a list ticked with no copy yet, through start_list_fetch)."""
    count = None
    try:
        catalogue = fetch_catalogue(v)
        count = len(catalogue["lists"])
    except (OSError, ValueError):
        try:
            with open(adguard_paths(v)["catalogue"]) as f:
                catalogue = json.load(f)
        except (OSError, ValueError):
            catalogue = {"lists": []}
    result = update_lists(v, catalogue=catalogue.get("lists") or [])
    result.update({"catalogue": count, "synced": None, "error": None})
    try:
        result["synced"] = sync_adguard(v, password)
        if result["changed"]:
            adguard_api(v, password, "POST", "/control/filtering/refresh", {"whitelist": False}, timeout=600)
    except ValidationError as e:
        result["error"] = str(e)
    return result
