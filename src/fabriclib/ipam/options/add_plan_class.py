from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.check_option_set import check_option_set
from fabriclib.ipam.options.set_owner import set_owner


def add_plan_class(v, actor, scope, name, test, next_server="", server_hostname="", boot_file_name="", site="",
                   secrets=None, container="samba", source="cli",
                   caller=None):
    """Purpose: add a DHCP client class to the domain's or a site's set (decision 2.1.10.23, manual
             1.10.4.24.5): clients a Kea expression matches get the class's options (set with `option set class`) and
             network-boot fields. A site's class of the same name as the domain's replaces it at that site.
    Inputs:  v — fabric vars; actor — who asks (audit); scope — "domain" (or 0.8's "org") or "site"; name — the class's
             name; test — a Kea expression ("option[93].hex == 0x0007"); next_server — the boot server's IPv4 address or
             ""; server_hostname, boot_file_name — or ""; site — whose set ("" this site's); secrets, container, source,
             caller — as edit_options.
    Returns: edit_options' result; result = the class as stored.
    Fails:   ValidationError: a class of that name in the set already; what normalize_client_classes refuses (a bad
             or reserved name, no test, a bad next server); a name starting fabric-nb- (fabric's netboot classes);
             what set_owner or edit_options refuses. Kea checks the expression at the apply.
    Feeds:   run_option_command (class add), agent/post_options (1.10.4.24.6)."""
    entry = {"name": str(name or "").strip(), "test": test, "options": []}
    for key, value in (("next_server", next_server), ("server_hostname", server_hostname),
                       ("boot_file_name", boot_file_name)):
        if value:
            entry[key] = value

    def change(plan):
        owner = set_owner(plan, scope)
        classes = owner["set"]["client_classes"]
        if any(c["name"] == entry["name"] for c in classes):
            raise ValidationError(f"client class {entry['name']} exists in {owner['label']}")
        checked = check_option_set({**owner["set"], "client_classes": classes + [entry]}, owner["defs"],
                                   owner["label"])
        stored = checked["client_classes"][-1]
        return (owner["write"]({"client_classes": checked["client_classes"]}), stored,
                f"scope={owner['label']} class {stored['name']} test={stored['test']}", [])
    return edit_options(v, actor, site, "IPAM_CLASS_ADD", change, secrets, container, source,
                        caller=caller, domain=scope in ("domain", "org"))
