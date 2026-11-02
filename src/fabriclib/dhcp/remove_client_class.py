from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.edit_dhcp import edit_dhcp


def remove_client_class(actor, name, source="cli"):
    """Purpose: remove a DHCP client class and its options. Applied by the next apply.
    Inputs:  actor — who asks (audit); name — the class; source — "cli" or "web".
    Returns: None.
    Fails:   ValidationError "no client class …"; OSError / yaml.YAMLError from edit_dhcp.
    Feeds:   run_dhcp_command (class remove), agent route POST /v1/dhcp/classes/<name>/delete."""
    def change(dhcp):
        classes = dhcp.get("client_classes") or []
        if not any(c["name"] == name for c in classes):
            raise ValidationError(f"no client class {name!r}")
        dhcp["client_classes"] = [c for c in classes if c["name"] != name]
        return None, f"class={name}"
    edit_dhcp(actor, "DHCP_CLASS_REMOVE", change, source, global_level=True)
