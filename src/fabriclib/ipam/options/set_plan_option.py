from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.catalogue import option_label
from fabriclib.ipam.options.check_option_set import check_option_set
from fabriclib.ipam.options.scope_options import scope_options


def set_plan_option(v, actor, scope, target, option, data, site="", org_class=False, always_send=None,
                    csv_format=None, space=None, secrets=None, container="samba", source="cli"):
    """Purpose: set one DHCP option at a level of the plan (decision 2.1.10.23, manual 1.10.4.24.5): the organisation,
             the site, a subnet, a client class or a reservation; the same option there (by name or code) is replaced.
    Inputs:  v — fabric vars; actor — who asks (audit); scope — org, site, subnet, class or address; target — the
             subnet, class or address ("" for org and site); option — a name ("boot-file-name") or a code ("67");
             data — its value in Kea's text form; site — whose plan ("" this site's); org_class — the class is the
             organisation's; always_send, csv_format — bool or None (Kea's default); space — an option space or None
             (dhcp4); secrets, container, source — as edit_options.
    Returns: edit_options' result; result = {"where", "option": the option as stored (a known code by its name),
             "code", "name"}.
    Fails:   ValidationError: what scope_options or check_option_set refuses (an unknown name, bad data), or what
             edit_options refuses (AD: the organisation's set from a site the top has not added).
    Feeds:   run_option_command (option set), agent routes POST /v1/ipam/options and /v1/ipam/options/org."""
    text = str(option or "").strip()
    entry = {"code": int(text)} if text.isdigit() else {"name": text}
    entry["data"] = data
    for key, value in (("always_send", always_send), ("csv_format", csv_format), ("space", space)):
        if value is not None:
            entry[key] = value

    def change(plan):
        where = scope_options(plan, scope, target, org_class)
        new = check_option_set({"options": [entry]}, where["defs"], where["label"])["options"][0]
        label = option_label(new, where["defs"])
        kept = [o for o in where["options"] if option_label(o, where["defs"])["key"] != label["key"]]
        checked = check_option_set({"options": kept + [new]}, where["defs"], where["label"])["options"]
        result = {"where": where["label"], "option": new, "code": label["code"], "name": label["name"]}
        shown = label["name"] or label["code"]
        return where["write"](checked), result, f"scope={where['label']} {shown}={new['data']}", []
    return edit_options(v, actor, site, "IPAM_OPTION_SET", change, secrets, container, source)
