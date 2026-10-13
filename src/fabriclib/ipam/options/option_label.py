from fabriclib.ipam.common.option_codes import CATALOGUE, CODES, FABRIC_PROVIDED


def option_label(option, defs=None):
    """Purpose: an option as the address manager names it: its code and its standard name (Kea's), or the name a
             definition gives it, whichever way it was set (manual 1.10.4.6.1).
    Inputs:  option — {"name"} or {"code"} (and "space"; normalize_options' form); defs — option definitions in force
             (the organisation's and the site's, [{name, code, space}]), or None.
    Returns: {"code": int or None, "name": str ("" when only a code Kea has no name for), "space": str, "key": the
             option's identity for comparisons ((code or name, space)), "provided": bool (one fabric provides)}.
    Fails:   never.
    Feeds:   check_option_set (a known code stored by its name), effective_options, show_options, plan_to_dhcp
             (merging the levels)."""
    space = option.get("space", "dhcp4")
    name, code = option.get("name"), option.get("code")
    for d in defs or []:
        if d.get("space", "dhcp4") == space and (d["name"] == name or d["code"] == code):
            name, code = d["name"], d["code"]
    if space == "dhcp4":
        if name and code is None:
            code = CODES.get(name)
        if code is not None and not name:
            name = CATALOGUE.get(code, "")
    key = (code if code is not None else name, space)
    return {"code": code, "name": name or "", "space": space, "key": key,
            "provided": space == "dhcp4" and code in FABRIC_PROVIDED}
