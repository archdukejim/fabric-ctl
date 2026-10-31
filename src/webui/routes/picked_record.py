def picked_record(form):
    """Purpose: The record a form names: the select's "<type>|<index>|<name>", else its type, index and name fields.
    Inputs:  form — dict.
    Returns: (type, index as str, name).
    Fails:   never.
    Feeds:   zone_post; landing_post."""
    if form.get("record"):
        rtype, _, rest = form["record"].partition("|")
        index, _, name = rest.partition("|")
        return rtype, index, name
    return form.get("type", ""), str(form.get("index", "")), form.get("name", "")
