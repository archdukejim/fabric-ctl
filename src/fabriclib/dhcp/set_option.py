from fabriclib.dhcp.common.edit_dhcp import edit_dhcp
from fabriclib.dhcp.common.option_target import option_target
from fabriclib.dhcp.normalize_options import normalize_options


def set_option(actor, option, data, subnet=None, client_class=None, mac=None, always_send=None, source="cli"):
    """Purpose: set any DHCP option (PXE, ZTP, NTP, vendor options…) for every subnet, one subnet, one client class
             or one reservation (manual 1.10.2.3, §4); an option of the same name there is replaced.
             Kea checks the name and data at the next apply (deploy_kea) and refuses what it cannot send.
    Inputs:  actor — who asks (audit); option — a Kea option name ("tftp-server-name") or code ("66", 1-254);
             data — its value (Kea's text form, e.g. "192.168.4.30" or "a, b"); subnet / client_class / mac — where
             (none: every subnet); always_send — send even when the client did not ask (None: Kea's default);
             source — "cli" or "web".
    Returns: (label of the place, the saved option).
    Fails:   ValidationError from option_target or normalize_options (bad name, code or data); OSError /
             yaml.YAMLError from edit_dhcp.
    Feeds:   run_dhcp_command (option set), agent route POST /v1/dhcp/options."""
    text = str(option).strip()
    entry = {"code": int(text)} if text.isdigit() else {"name": text}
    entry["data"] = data
    if always_send is not None:
        entry["always_send"] = bool(always_send)
    new = normalize_options([entry], "the option")[0]

    def change(dhcp):
        target, label = option_target(dhcp, subnet, client_class, mac)
        key = new.get("name", new.get("code"))
        target["options"] = [o for o in target.get("options") or [] if o.get("name", o.get("code")) != key] + [new]
        return label, f"{label}: {key}={new['data']}"
    return edit_dhcp(actor, "DHCP_OPTION_SET", change, source,
                     global_level=not subnet and not mac)[0], new
