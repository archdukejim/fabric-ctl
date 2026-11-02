from fabriclib.ipam.common.plan_holds_subnets import plan_holds_subnets
from fabriclib.settings.constants import CONSOLE_ONLY
from fabriclib.settings.form_from_settings import form_from_settings
from fabriclib.settings.read_settings import read_settings
from fabriclib.settings.wizard_finished import wizard_finished
from fabriclib.system.host_networks import host_networks
from fabriclib.system.host_ram_gb import host_ram_gb


def settings_overview(v, have_gb=None, networks=None, config_dir=None):
    """Purpose: what the console's Settings wizard shows (manual 1.8.5.3): today's wizard settings and its fields
             filled in with them, the console-only settings read only with the command that changes each, whether the
             wizard has been applied once or dismissed, and what the DHCP and memory steps need from the host.
    Inputs:  v — the settings as saved (vars.yaml); have_gb — the host's GB (None: measured); networks —
             host_networks() (None: this host's); config_dir — where the wizard's record is (None: vars.yaml's).
    Returns: {"settings": read_settings, "form": form_from_settings, "console_only": [{"key", "what", "value",
             "command"}], "finished": wizard_finished, "host_gb": int (0: unknown), "interfaces": [names],
             "dhcp_first_subnet": bool (turning DHCP on asks its first subnet: DHCP has none, in the settings or the
             address plan)}.
    Fails:   never for a readable settings dict.
    Feeds:   agent/get_route (GET /v1/settings)."""
    have_gb = host_ram_gb() if have_gb is None else have_gb
    settings = read_settings(v, have_gb)
    return {"settings": settings, "form": form_from_settings(settings),
            "console_only": [{"key": k, "what": what, "value": str(v.get(k) if v.get(k) is not None else ""),
                              "command": cmd} for k, what, cmd in CONSOLE_ONLY],
            "finished": wizard_finished(config_dir), "host_gb": have_gb,
            "interfaces": sorted(host_networks() if networks is None else networks),
            "dhcp_first_subnet": not (v.get("dhcp") or {}).get("subnets") and not plan_holds_subnets(v)}
