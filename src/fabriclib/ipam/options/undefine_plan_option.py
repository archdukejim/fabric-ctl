from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.set_owner import set_owner


def undefine_plan_option(v, actor, scope, name, space=None, site="", secrets=None, container="samba", source="cli"):
    """Purpose: remove an option definition from the organisation's or a site's set (manual 1.10.4.24.5), refused
             while an option of that set (or of one of its classes) still names it.
    Inputs:  v — fabric vars; actor — who asks (audit); scope — "org" or "site"; name — the definition's name; space —
             its option space or None (dhcp4); site — whose set ("" this site's); secrets, container, source — as
             edit_options.
    Returns: edit_options' result; result = the definition removed.
    Fails:   ValidationError: no such definition there; an option still names it (remove it first); what set_owner or
             edit_options refuses.
    Feeds:   run_option_command (option undefine), agent routes POST /v1/ipam/option-defs and /option-defs/org."""
    want, wspace = str(name or "").strip().lower(), space or "dhcp4"

    def change(plan):
        owner = set_owner(plan, scope)
        defs = owner["set"]["option_defs"]
        found = next((d for d in defs if d["name"] == want and d.get("space", "dhcp4") == wspace), None)
        if found is None:
            raise ValidationError(f"{owner['label']} defines no option {want}")
        users = [o for o in owner["set"]["options"] if o.get("name") == want and o.get("space", "dhcp4") == wspace]
        users += [o for c in owner["set"]["client_classes"] for o in c.get("options") or []
                  if o.get("name") == want and o.get("space", "dhcp4") == wspace]
        if users:
            raise ValidationError(f"option {want} is still set in {owner['label']}: remove it first")
        kept = [d for d in defs if d is not found]
        return (owner["write"]({"option_defs": kept}), found, f"scope={owner['label']} undefine {want}", [])
    return edit_options(v, actor, site, "IPAM_OPTION_UNDEFINE", change, secrets, container, source)
