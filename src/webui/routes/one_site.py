"""The console shows only its own site (decision 2.1.8.68, manual 1.8.6.14)."""

# what an address naming another site, or a view of several sites, answers (with 404)
ONE_SITE = "This console shows only this site; another site's is its own console"


def other_site(named, here):
    """Purpose: whether a request names a site other than the one this console runs at (1.8.6.14).
    Inputs:  named — the site the request names ("" or None: none, which means this one); here — this site's name.
    Returns: True for another site; False for none or this one (case and spaces aside), so old links naming this
             site keep working.
    Fails:   never.
    Feeds:   networks_page, networks_post, options_page, options_post."""
    named = str(named or "").strip().lower()
    return bool(named) and named != str(here or "").strip().lower()
