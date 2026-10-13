from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.catalogue import option_label
from fabriclib.ipam.options.scope_options import scope_options


def remove_plan_option(v, actor, scope, target, option, site="", org_class=False, space=None, secrets=None,
                       container="samba", source="cli"):
    """Purpose: remove one DHCP option from a level of the plan (manual 1.10.4.24.5), named by its name or its code.
    Inputs:  v — fabric vars; actor — who asks (audit); scope, target, site, org_class — as set_plan_option; option —
             a name or a code; space — an option space or None (dhcp4); secrets, container, source — as edit_options.
    Returns: edit_options' result; result = {"where", "code", "name"}.
    Fails:   ValidationError: what scope_options refuses; the option is not set there (a fabric-provided option
             nobody overrode cannot be removed: it is fabric's, 1.10.4.6.2); what edit_options refuses.
    Feeds:   run_option_command (option remove), agent routes POST /v1/ipam/options and /v1/ipam/options/org."""
    text = str(option or "").strip()
    wanted = {"code": int(text)} if text.isdigit() else {"name": text.lower()}
    if space:
        wanted["space"] = space

    def change(plan):
        where = scope_options(plan, scope, target, org_class)
        label = option_label(wanted, where["defs"])
        kept = [o for o in where["options"] if option_label(o, where["defs"])["key"] != label["key"]]
        if len(kept) == len(where["options"]):
            raise ValidationError(f"{where['label']} has no option {text} set"
                                  + (" (fabric provides it: set it to override)" if label["provided"] else ""))
        result = {"where": where["label"], "code": label["code"], "name": label["name"]}
        return where["write"](kept), result, f"scope={where['label']} {label['name'] or label['code']}", []
    return edit_options(v, actor, site, "IPAM_OPTION_REMOVE", change, secrets, container, source)
