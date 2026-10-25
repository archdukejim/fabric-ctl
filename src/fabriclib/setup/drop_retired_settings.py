from fabriclib.setup.common.retired_settings import OLD_DEFAULT_GROUPS, OLD_FILE_MARKS, OLD_FILE_ONLY, RETIRED_SETTINGS


def drop_retired_settings(given):
    """Purpose: take a settings file of an older fabric as it is (2.1.1.60, manual 3.3.5.3): every key 0.8.0 no
             longer takes (RETIRED_SETTINGS) is taken out and listed with why, never refused. A 0.7.x file (one
             holding a key of OLD_FILE_MARKS) has its OLD_FILE_ONLY keys ignored too (dc_name, its image pins), where
             in a newer file they are settings (one naming the DC refused, refuse_named_dc, 2.1.6.65); its
             ldap_groups lose the entries that are exactly 0.7.x's own groups (OLD_DEFAULT_GROUPS: 0.8.0 lays out
             its own), keeping any the admin added.
    Inputs:  given — the file's settings (dict; not changed).
    Returns: (kept — a new dict without the ignored keys and groups, ignored — [(key, why)] in the file's order,
             ldap_groups last when some of its entries went).
    Fails:   never — dict operations only.
    Feeds:   setup/collect_vars (`fabricctl setup --file`, a checkout's custom-vars.yaml), which prints and logs the
             list."""
    old = any(k in given for k in OLD_FILE_MARKS)
    kept, ignored = {}, []
    for key, value in given.items():
        if key in RETIRED_SETTINGS and (key not in OLD_FILE_ONLY or old):
            ignored.append((key, RETIRED_SETTINGS[key]))
        else:
            kept[key] = value
    groups = kept.get("ldap_groups")
    if old and isinstance(groups, list):
        mine = [g for g in groups if g not in OLD_DEFAULT_GROUPS]
        gone = [str(g.get("name")) for g in groups if g in OLD_DEFAULT_GROUPS]
        if gone:
            if mine:
                kept["ldap_groups"] = mine
            else:
                del kept["ldap_groups"]
            ignored.append(("ldap_groups", f"0.7.x's own groups ({', '.join(gone)}): 0.8.0 lays out its own "
                                           "(2.1.6.81); groups the admin added are kept"))
    return kept, ignored
