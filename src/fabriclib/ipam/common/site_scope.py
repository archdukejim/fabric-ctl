from fabriclib.common.errors import ValidationError
from fabriclib.ipam.visible_sites import visible_sites


def site_scope(v, site):
    """Purpose: the site a console request names, refused unless it is this install's own or one that joined below it
             (manual 1.10.4.21, decision 2.1.10.27): a house's console never reads or writes its parent's or another
             house's plan, whatever the request says.
    Inputs:  v — fabric vars (site_name); site — str as requested ("" this site).
    Returns: str, the site's name.
    Fails:   ValidationError "site <s> is not this site or one below it"; what visible_sites raises.
    Feeds:   networks_overview, networks_csv, agent/post_networks (every change)."""
    want = str(site or "").strip() or (v.get("site_name") or "")
    names = [s["name"] for s in visible_sites(v)]
    found = next((n for n in names if n.lower() == want.lower()), None)
    if found is None:
        raise ValidationError(f"site {want!r} is not this site or one below it: this console shows "
                              + ", ".join(names))
    return found
