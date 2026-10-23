from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.option_label import option_label
from fabriclib.ipam.options.check_option_set import check_option_set
from fabriclib.ipam.options.scope_options import scope_options


def set_plan_option(v, actor, scope, target, option, data, site="", domain_class=False, always_send=None,
                    csv_format=None, space=None, secrets=None, container="samba", source="cli",
                    caller=None):
    """Purpose: set one DHCP option at a level of the plan (decision 2.1.10.23, manual 1.10.4.24.5): the domain,
             the site, a subnet, a client class or a reservation; the same option there (by name or code) is replaced.
    Inputs:  v — fabric vars; actor — who asks (audit); scope — domain (or 0.8's org), site, subnet, class or address;
             target — the subnet, class or address ("" for org and site); option — a name ("boot-file-name") or a code
             ("67"); data — its value in Kea's text form; site — whose plan ("" this site's); domain_class — the class
             is the domain's; always_send, csv_format — bool or None (Kea's default); space — an option space or None
             (dhcp4); secrets, container, source, caller — as edit_options.
    Returns: edit_options' result; result = {"where", "option": the option as stored (a known code by its name),
             "code", "name"}.
    Fails:   ValidationError: what scope_options or check_option_set refuses (an unknown name, bad data), or what
             edit_options refuses (no grant giving networks options at all, for the domain's set).
    Feeds:   run_option_command (option set), the agent's routes (1.10.4.41, area 7)."""
    text = str(option or "").strip()
    entry = {"code": int(text)} if text.isdigit() else {"name": text}
    entry["data"] = data
    for key, value in (("always_send", always_send), ("csv_format", csv_format), ("space", space)):
        if value is not None:
            entry[key] = value

    def change(plan):
        where = scope_options(plan, scope, target, domain_class)
        new = check_option_set({"options": [entry]}, where["defs"], where["label"])["options"][0]
        label = option_label(new, where["defs"])
        kept = [o for o in where["options"] if option_label(o, where["defs"])["key"] != label["key"]]
        checked = check_option_set({"options": kept + [new]}, where["defs"], where["label"])["options"]
        result = {"where": where["label"], "option": new, "code": label["code"], "name": label["name"]}
        shown = label["name"] or label["code"]
        return where["write"](checked), result, f"scope={where['label']} {shown}={new['data']}", []
    return edit_options(v, actor, site, "IPAM_OPTION_SET", change, secrets, container, source,
                        caller=caller, domain=scope in ("domain", "org") or (scope == "class" and domain_class))
