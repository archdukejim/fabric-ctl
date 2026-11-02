from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.kea_command import kea_command
from fabriclib.setup.errors import SetupError
from fabriclib.setup.start_unit import start_unit

DAEMONS = {"kea-dhcp4.conf": "dhcp4", "kea-dhcp-ddns.conf": "ddns"}     # each file's daemon (its control socket)


def reload_kea(v, changed, command=kea_command, restart=start_unit):
    """Purpose: Kea made to take its changed configuration without a restart (decision 2.1.10.45, manual 1.10.4.42):
             `config-reload` over the control socket of each daemon whose file changed (kea-dhcp4 keeps its leases
             and keeps serving; kea-dhcp-ddns its queue). A daemon that does not answer or refuses the reload is
             restarted instead (start_unit: the `kea` unit, health-checked), so the new file is always what Kea runs.
    Inputs:  v — the rendered vars (deploy_base_dir); changed — the names of Kea's files that changed (deploy_kea's
             result); command — kea_command; restart — function(unit, container, restart=True) (start_unit; tests give
             their own).
    Returns: {"reloaded": [the daemons reloaded], "restarted": bool, "why": what made the restart needed, or ""}.
    Fails:   ValidationError "Kea did not come back healthy after its restart …" when the fallback restart fails
             (SetupError from start_unit).
    Feeds:   deploy/restart_changed (an apply), ipam/options/render_kea (the plan poll), dhcp/kea_key/drop_old_key's
             caller (the key's replacement: kea-dhcp-ddns on the new key)."""
    done = []
    for name in sorted(changed, key=lambda n: n != "kea-dhcp4.conf"):     # kea-dhcp4 first, as Kea starts
        daemon = DAEMONS[name]
        try:
            command(v, "config-reload", daemon=daemon)
        except ValidationError as exc:
            why = f"kea-{daemon} did not reload its configuration ({exc})"
            print(f"  {why}: restarting Kea")
            try:
                restart("kea", "kea-dhcp4", restart=True)
            except SetupError as err:
                raise ValidationError(f"Kea did not come back healthy after its restart ({why}): {err}. "
                                      "Run `sudo fabricctl doctor`.")
            return {"reloaded": done, "restarted": True, "why": why}
        done.append(daemon)
    return {"reloaded": done, "restarted": False, "why": ""}
