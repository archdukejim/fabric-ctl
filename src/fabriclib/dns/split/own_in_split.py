from fabriclib.common.errors import ValidationError
from fabriclib.dns.common.own_names import own_names


def own_in_split(v, key, name):
    """Purpose: refuse one of fabric's own names in a split (decision 2.1.4.18, manual 1.4.1.13): they live in the
             All networks tab and answer in every tab, so the console, the CA and DHCP work from any network.
    Inputs:  v — settings (as own_names reads them); key — the zone's key (only the site's zone holds them); name —
             the record's name.
    Returns: None.
    Fails:   ValidationError naming the service, when the name is one of fabric's own.
    Feeds:   dns/add_record, dns/update_record (a record in a split)."""
    if key != "dynamic_zone_var":
        return
    for (_, own), (_, service, setting) in own_names(v).items():
        if own == str(name or ""):
            raise ValidationError(f"{name} is provided by fabric ({service}, from the setting {setting}) and answers "
                                  f"in every tab: it is never given a split's own answer")
