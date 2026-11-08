from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns_filter.apply_dns_filter import apply_dns_filter
from fabriclib.dns_filter.common.adguard_desired import adguard_desired
from fabriclib.dns_filter.start_list_fetch import start_list_fetch


def apply_filter_now(actor, ticked=None):
    """Purpose: make the DNS filter's saved settings where they live, once (manual 1.12.3.8): the resolver reloaded,
             AdGuard Home through its API (apply_dns_filter); and one start of the lists job when a list ticked has
             no copy yet (it has the internet; fabric-agent has not), which adds it to AdGuard when its copy
             arrives.
    Inputs:  actor — who asked (audit); ticked — the URLs of the lists just ticked or added; "all": every list
             ticked on the site (the tab's Apply, whose changes are read from vars.yaml); None or []: no list.
    Returns: {"waiting": why the settings are saved but not in use yet (AdGuard not answering, the lists job not
             starting) or None, "fetching": True when the lists job was started}.
    Fails:   ValidationError from apply_dns_filter (the settings do not render, OpenBao locked).
    Feeds:   agent/post_dns_filter (a direct change), agent/pending_filter (the tab's Apply, its last step)."""
    done = apply_dns_filter(actor, "web")
    waiting, fetching = done["waiting"], False
    if ticked:
        v = load_vars()
        have = {f["source"] for f in adguard_desired(v)["filters"]}
        if ticked == "all":
            ticked = [str(i.get("url") or "").strip() for i in v.get("dns_filter_lists") or []
                      if isinstance(i, dict) and i.get("enabled", True) is not False]
        if any(url not in have for url in ticked):
            try:
                fetching = start_list_fetch()
            except ValidationError as e:    # the change is saved and made: only its first copy waits (2.3.1.20.4)
                waiting = waiting or f"{e}; run sudo fabricctl dns-filter lists to fetch it"
    return {"waiting": waiting, "fetching": fetching}
