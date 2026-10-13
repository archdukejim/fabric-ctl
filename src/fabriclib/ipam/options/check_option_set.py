from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.normalize_client_classes import normalize_client_classes
from fabriclib.dhcp.normalize_option_defs import normalize_option_defs
from fabriclib.dhcp.normalize_options import normalize_options
from fabriclib.ipam.options.catalogue import CATALOGUE, CODES

PRESET_PREFIX = "fabric-nb-"          # fabric's netboot classes (2.1.10.25): no admin class takes the prefix


def _named(options, defs, where):
    """Purpose: every option of a list by a name Kea knows: a standard option given by its code is kept by its name
             (shown by name everywhere, 1.10.4.6.1), a defined one likewise; a name neither knows is refused.
    Inputs:  options — normalize_options' list; defs — the definitions in force; where — for messages.
    Returns: the list, codes of known options turned into their names.
    Fails:   ValidationError naming an unknown option name.
    Feeds:   check_option_set."""
    out = []
    for o in options:
        space = o.get("space", "dhcp4")
        mine = {d["name"]: d["code"] for d in defs if d.get("space", "dhcp4") == space}
        if "code" in o:
            name = next((n for n, c in mine.items() if c == o["code"]), None)
            if name is None and space == "dhcp4":
                name = CATALOGUE.get(o["code"])
            if name:
                o = {**{k: x for k, x in o.items() if k != "code"}, "name": name}
        elif o["name"] not in mine and not (space == "dhcp4" and o["name"] in CODES):
            raise ValidationError(f"{where}: option {o['name']!r} is not one Kea knows by name: give its code, or "
                                  "define it first (fabricctl ipam option define)")
        out.append(o)
    return out


def check_option_set(entry, defs=None, where="the options"):
    """Purpose: an option set (the organisation's or a site's, 2.1.10.23) or one level's option list checked before it
             is written (manual 1.10.4.24.2): options as normalize_options checks them and by a name Kea knows or a
             definition gives; definitions as normalize_option_defs; client classes as normalize_client_classes, none
             named with fabric's netboot prefix, their options by known names too.
    Inputs:  entry — {"options", "option_defs", "client_classes"} (any may be missing); defs — further definitions in
             force (the organisation's, for a site's set; the set's own are added); where — for messages.
    Returns: the set normalized: {"options", "option_defs", "client_classes"} (lists, empty when none).
    Fails:   ValidationError: what the normalizers refuse; an unknown option name; a class named fabric-nb-….
    Feeds:   ipam/options/set_plan_option, remove_plan_option, define_plan_option, undefine_plan_option,
             add_plan_class, remove_plan_class, move_options_to_plan."""
    own = normalize_option_defs(entry.get("option_defs"))
    known = own + [d for d in defs or [] if (d["name"], d.get("space", "dhcp4")) not in
                   {(x["name"], x.get("space", "dhcp4")) for x in own}]
    options = _named(normalize_options(entry.get("options"), where), known, where)
    classes = normalize_client_classes(entry.get("client_classes"))
    for c in classes:
        if c["name"].lower().startswith(PRESET_PREFIX):
            raise ValidationError(f"client class {c['name']}: names starting {PRESET_PREFIX} are fabric's netboot "
                                  "classes")
        c["options"] = _named(c.get("options") or [], known, f"client class {c['name']}")
    return {"options": options, "option_defs": own, "client_classes": classes}
