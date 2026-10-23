from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.common.edit_dhcp import edit_dhcp
from fabriclib.dhcp.common.option_target import option_target


def unset_option(actor, option, subnet=None, client_class=None, mac=None, source="cli"):
    """Purpose: remove an option the admin set (manual 1.10.2.5); an option fabric sets itself
             (DNS, time, domain) comes back to fabric's value. Applied by the next apply.
    Inputs:  actor — who asks (audit); option — its name or code; subnet / client_class / mac — where (none:
             every subnet); source — "cli" or "web".
    Returns: label of the place.
    Fails:   ValidationError: the option is not set there; errors of option_target; OSError / yaml.YAMLError.
    Feeds:   run_dhcp_command (option unset), agent route POST /v1/dhcp/options/delete."""
    text = str(option).strip().lower()
    key = int(text) if text.isdigit() else text

    def change(dhcp):
        target, label = option_target(dhcp, subnet, client_class, mac)
        kept = [o for o in target.get("options") or [] if o.get("name", o.get("code")) != key]
        if len(kept) == len(target.get("options") or []):
            raise ValidationError(f"option {option} is not set for {label}")
        target["options"] = kept
        return label, f"{label}: {key} removed"
    return edit_dhcp(actor, "DHCP_OPTION_UNSET", change, source,
                     global_level=not subnet and not mac)[0]
