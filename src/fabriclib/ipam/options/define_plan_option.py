from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.common.option_codes import CATALOGUE, CODES
from fabriclib.ipam.options.check_option_set import check_option_set
from fabriclib.ipam.options.set_owner import set_owner


def define_plan_option(v, actor, scope, name, code, kind, array=False, record_types="", space=None, site="",
                       secrets=None, container="samba", source="cli",
                       caller=None):
    """Purpose: define a DHCP option Kea has no name for (a vendor's or a site-specific code), in the domain's or
             a site's set (decision 2.1.10.23, manual 1.10.4.24.5), so options can then name it.
    Inputs:  v — fabric vars; actor — who asks (audit); scope — "domain" (or 0.8's "org") or "site"; name — the option's
             name (letters, digits, dashes); code — int or digits, 1-254; kind — Kea's type (string, uint8,
             ipv4-address, …, record); array — bool; record_types — for a record ("uint8, string"); space — an option
             space or None (dhcp4); site — whose set ("" this site's); secrets, container, source, caller — as
             edit_options.
    Returns: edit_options' result; result = the definition as stored.
    Fails:   ValidationError: a scope other than org or site; a code that is not a number; a name or code of a
             standard DHCPv4 option (Kea refuses redefining one); one already defined there; what
             normalize_option_defs refuses; what edit_options refuses.
    Feeds:   run_option_command (option define), agent/post_options (1.10.4.24.6)."""
    text = str(code).strip()
    if not text.isdigit():
        raise ValidationError(f"option definition {name}: code is a number from 1 to 254")
    entry = {"name": str(name or "").strip().lower(), "code": int(text), "type": kind}
    if array:
        entry["array"] = True
    if record_types:
        entry["record_types"] = record_types
    if space:
        entry["space"] = space
    if entry.get("space", "dhcp4") == "dhcp4" and (entry["name"] in CODES or entry["code"] in CATALOGUE):
        raise ValidationError(f"option {entry['name']} (code {entry['code']}): a standard DHCPv4 option is already "
                              f"defined by Kea ({CATALOGUE.get(entry['code']) or entry['name']})")

    def change(plan):
        owner = set_owner(plan, scope)
        defs = list(owner["set"].get("option_defs") or [])
        if any(d["name"] == entry["name"] and d.get("space", "dhcp4") == entry.get("space", "dhcp4") for d in defs):
            raise ValidationError(f"option {entry['name']} is already defined in {owner['label']}: undefine it first")
        checked = check_option_set({**owner["set"], "option_defs": defs + [entry]}, owner["defs"], owner["label"])
        stored = checked["option_defs"][-1]
        return (owner["write"]({"option_defs": checked["option_defs"]}), stored,
                f"scope={owner['label']} define {stored['name']} code {stored['code']} {stored['type']}", [])
    return edit_options(v, actor, site, "IPAM_OPTION_DEFINE", change, secrets, container, source,
                        caller=caller, domain=scope in ("domain", "org"))
