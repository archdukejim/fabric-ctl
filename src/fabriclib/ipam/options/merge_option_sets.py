from fabriclib.ipam.options.option_label import option_label

EMPTY = {"options": [], "option_defs": [], "client_classes": []}


def merge_option_sets(*sets):
    """Purpose: what one site's Kea gets at its global level out of the option sets in force, lowest first: the
             domain's, the site's, then any the settings still carry (manual 1.10.4.24.3). A later level's option
             replaces an earlier one's (the same option by name or code), a definition or class of the same name
             likewise; the rest are kept in order, earlier levels first.
    Inputs:  sets — option sets ({"options", "option_defs", "client_classes"}) or None, lowest level first.
    Returns: {"options", "option_defs", "client_classes"}: lists of the entries (each a copy), merged.
    Fails:   never.
    Feeds:   plan_to_dhcp, effective_options."""
    defs = []
    for one in sets:
        for d in (one or EMPTY).get("option_defs") or []:
            defs = [x for x in defs if (x["name"], x.get("space", "dhcp4")) != (d["name"], d.get("space", "dhcp4"))]
            defs.append(dict(d))
    options, classes = [], []
    for one in sets:
        for o in (one or EMPTY).get("options") or []:
            key = option_label(o, defs)["key"]
            options = [x for x in options if option_label(x, defs)["key"] != key]
            options.append(dict(o))
        for c in (one or EMPTY).get("client_classes") or []:
            classes = [x for x in classes if x["name"] != c["name"]]
            classes.append(dict(c))
    return {"options": options, "option_defs": defs, "client_classes": classes}
