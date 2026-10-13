import os

from fabriclib.common.paths import VARS_FILE
from fabriclib.keycloak.signin_levels import admin_level
from fabriclib.security.hardened_daemon_settings import DAEMON_JSON, hardened_daemon_settings
from fabriclib.security.signin_layers import read_lowered


def relaxed_settings(vars_, config_dir=None, daemon_json=DAEMON_JSON):
    """Purpose: the security relaxations this host has turned on, so `fabricctl status` and the web UI can show them
             while they are active (global Rule 10; manual 1.2.8). Host changes the admin declined are listed by
             consent_status instead; Docker's userland proxy is listed here too while the DNS filter has client
             groups, because it hides their addresses (1.12.2.15).
    Inputs:  vars_ — the host's vars (image_signature_check, host_join_domain, ssh_certificates, the sign-in settings,
             install_resolver, dns_filter_groups); config_dir — the install's config folder (LOWERED_FILE: sign-in
             layers lowered with `fabricctl security lower`; default vars.yaml's); daemon_json — Docker's daemon
             settings file.
    Returns: list of {"setting": str, "effect": str}; [] when none is relaxed.
    Fails:   OSError / ValueError for an unreadable LOWERED_FILE.
    Feeds:   system/show_relaxed_settings (`fabricctl status`); fabric-agent GET /v1/relaxed-settings (the web UI's
             Overview)."""
    relaxed = []
    if not vars_.get("image_signature_check", True):
        relaxed.append({"setting": "image_signature_check: false",
                        "effect": "fabric's published images are used without checking their signatures (1.14.3.4)"})
    if vars_.get("host_join_domain", True) is False:                     # 2.1.6.34: a member by default
        relaxed.append({"setting": "host_join_domain: false",
                        "effect": "this host is not a member of its domain: fabric admins sign in to it with local "
                                  "accounts only, and sudo here does not follow the domain's rules (1.6.11.8)"})
    if vars_.get("ssh_certificates") is True:                         # 2.1.6.39: an option, shown while on
        relaxed.append({"setting": "ssh_certificates: true",
                        "effect": "fabric admins may sign in to managed machines with 8-hour SSH certificates from "
                                  "OpenBao, beside Kerberos (1.6.11.9)"})
    if vars_.get("install_keycloak") and admin_level(vars_) == "none":     # 2.1.6.23: a password only, by default
        relaxed.append({"setting": "signin_admin_second_factor: none",
                        "effect": "the web console and OpenBao ask for a password only; raise a "
                                  "second factor in the web console's Security page (2.3.6.2.6)"})
    if vars_.get("install_resolver") and vars_.get("dns_filter_groups"):
        try:
            daemon, _ = hardened_daemon_settings(daemon_json)
        except (OSError, ValueError):
            daemon = {}
        if daemon.get("userland-proxy", True) is not False:   # Docker's default is on (1.12.2.15, 2.3.12.1.22)
            relaxed.append({"setting": "Docker's userland-proxy is on",
                            "effect": "client addresses hidden: the DNS filter answers every client as everyone, "
                                      "so its client groups do not apply (accept the runtime host change)"})
    for layer, entry in read_lowered(config_dir or os.path.dirname(VARS_FILE)).items():
        relaxed.append({"setting": f"{layer} lowered: {entry['from']} -> {entry['to']}",
                        "effect": f"lowered by {entry['by']} on {entry['at']} (fabricctl security lower); raise it "
                                  "again in the Security page"})
    return relaxed
