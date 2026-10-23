from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.edit_dhcp import edit_dhcp


def add_client_class(actor, name, test, next_server=None, boot_file_name=None, server_hostname=None, source="cli"):
    """Purpose: add a DHCP client class: clients matching a Kea expression (e.g. UEFI PXE, a switch vendor for ZTP)
             get their own options and network-boot fields (manual 1.10.2.3). Options are added with
             `set_option(client_class=…)`. Applied by the next apply; Kea checks the expression then.
    Inputs:  actor — who asks (audit); name — class name; test — Kea expression ("option[93].hex == 0x0007");
             next_server — IPv4 address of the boot server or None; boot_file_name, server_hostname — or None;
             source — "cli" or "web".
    Returns: the saved class (normalized).
    Fails:   ValidationError: a class of that name exists; errors of normalize_client_classes; OSError /
             yaml.YAMLError from edit_dhcp.
    Feeds:   run_dhcp_command (class add), agent route POST /v1/dhcp/classes."""
    def change(dhcp):
        classes = dhcp.setdefault("client_classes", [])
        if any(c["name"] == name for c in classes):
            raise ValidationError(f"client class {name} exists")
        entry = {"name": name, "test": test, "options": []}
        for key, value in (("next_server", next_server), ("boot_file_name", boot_file_name),
                           ("server_hostname", server_hostname)):
            if value:
                entry[key] = value
        classes.append(entry)
        return name, f"class={name} test={test}"
    _, dhcp = edit_dhcp(actor, "DHCP_CLASS_ADD", change, source, global_level=True)
    return next(c for c in dhcp["client_classes"] if c["name"] == name)
