import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.deploy.compose_builds import compose_builds
from fabriclib.dhcp.clear_stale_dhcp_names import clear_stale_dhcp_names
from fabriclib.dhcp.hand_set_addresses import hand_set_addresses
from fabriclib.dhcp.kea_key.kea_key import kea_key
from fabriclib.dhcp.reload_kea import reload_kea
from fabriclib.dns.freeze_and_install import freeze_and_install
from fabriclib.dns.install_zone_file import install_zone_file
from fabriclib.dns.reload_zone import reload_zone
from fabriclib.dns.rndc import rndc
from fabriclib.dns_filter.flush_published_names import flush_published_names
from fabriclib.ipam.move_subnets_to_plan import move_subnets_to_plan
from fabriclib.ipam.options.move_options_to_plan import move_options_to_plan
from fabriclib.keycloak.install_sso_keytab import install_sso_keytab
from fabriclib.samba.converge_domain import converge_domain
from fabriclib.samba.write_bind_dlz import write_bind_dlz
from fabriclib.setup.errors import SetupError
from fabriclib.setup.service_order import ORDER
from fabriclib.setup.start_unit import start_unit

TIMEOUT = {"keycloak": 90, "postgres": 60, "samba": 300}   # seconds per restart (others 30); the DC provisions once
# the measured rollout's order (1.14.2.11): OpenBao first, then setup's start order; (unit, container)
ROLLOUT = [("openbao", "openbao")] + [(unit, container) for unit, container, _ in ORDER]


def _roll_out(restart):
    """Purpose: restart the changed services one at a time in dependency order, each waited for until healthy, and
             stop at the first that is not (2.1.14.15, manual 1.14.2.11).
    Inputs:  restart — set of unit names to restart (a unit fabric does not order, such as a host service, goes
             last, checked active).
    Returns: None.
    Fails:   ValidationError naming the service that did not come back healthy and those not restarted after it.
    Feeds:   restart_changed."""
    known = {u for u, _ in ROLLOUT}
    plan = [(u, c) for u, c in ROLLOUT if u in restart] + [(u, None) for u in sorted(restart - known)]
    for i, (unit, container) in enumerate(plan):
        print(f"Restarting {unit} due to configuration changes...")
        try:
            if container:
                start_unit(unit, container, restart=True)
            else:
                subprocess.run(["systemctl", "restart", unit], check=True, timeout=TIMEOUT.get(unit, 30))
                if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode != 0:
                    raise SetupError(f"{unit} is not active after its restart")
        except (SetupError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            rest = [u for u, _ in plan[i + 1:]]
            raise ValidationError(f"{unit} did not come back healthy after the apply's restart; the rollout stopped"
                                  + (f" ({', '.join(rest)} not restarted)" if rest else "")
                                  + f": {str(e).splitlines()[0] if str(e) else type(e).__name__}. "
                                  "Run `sudo fabricctl doctor`.")


def _quiet(cmd, what, timeout, capture=False):
    """Purpose: run a systemctl or docker command where a timeout is reported, not fatal.
    Inputs:  cmd — argument list; what — text for the message; timeout — seconds; capture — keep the output
             (else it goes to the console, as systemctl's own errors should).
    Returns: the CompletedProcess, or None after printing "<what> timed out".
    Fails:   never for a timeout; FileNotFoundError without the command.
    Feeds:   restart_changed."""
    try:
        return subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"{what} timed out")
        return None


def _reconfig_bind():
    """Purpose: BIND's new configuration taken by the running BIND (`rndc reconfig`): its keys and update-policy grants
             (TSIG) and its zone list take effect here.
    Inputs:  none.
    Returns: None.
    Fails:   ValidationError when BIND refuses it or does not answer (a silent failure would leave a removed TSIG key
             working).
    Feeds:   restart_changed."""
    print("Reloading BIND9 configuration...")
    res = rndc(["reconfig"], timeout=90)          # generous: reconfig is slow on a loaded Pi
    if res is None or res.returncode != 0:
        raise ValidationError("BIND9 did not accept the new configuration "
                              f"({(res.stderr or res.stdout).strip() if res else 'timeout'}); "
                              "check `docker logs bind9`.")


def _enabled(unit):
    """Purpose: whether a systemd unit is enabled (installed for boot).
    Inputs:  unit — name.
    Returns: bool.
    Fails:   FileNotFoundError without systemctl.
    Feeds:   restart_changed."""
    return subprocess.run(["systemctl", "is-enabled", "--quiet", unit]).returncode == 0


def restart_changed(paths, final_vars, secrets, state, bind_ids):
    """Purpose: the end of an apply on a running install: build changed images, restart what changed, reload BIND's
             configuration and zones and nginx live, converge the domain (and move 0.7's DHCP subnets and global options
             into the address plan once, 1.10.4.15, 2.1.10.23), delete DHCP names left behind for addresses set by
             hand (2.1.10.22), and restart fabric-agent, the federation endpoint and the web UI last without blocking.
    Inputs:  paths — deploy_paths() (base, target, federation); final_vars — rendered settings (federation_endpoint,
             and what converge_domain reads); secrets — fabric's secrets (the domain's service accounts); state —
             what the install steps found (see finish_without_start); bind_ids — the bind user's ids.
    Returns: the set of units restarted (fabric-web included when it was queued; kea when its reload fell back to a
             restart).
    Fails:   ValidationError when a restarted service does not come back healthy (the rollout stops there, nothing
             after it runs: 2.1.14.15; Kea too, restarted after a reload it did not take: reload_kea) or BIND
             refuses `rndc reconfig` (a silent failure would leave a removed TSIG
             key working), or refuses deleting a DHCP name left behind (raised last, the rest of the apply done:
             2.1.10.22), or does not drop Kea's old key once Kea runs on the new one (drop_old_key, 2.1.10.42: the
             next apply drops it). Timeouts
             of other systemctl/docker calls and a domain that cannot be converged are
             reported, not raised.
    Feeds:   apply_deployment (start_services=True: `fabricctl --apply`, the web UI's Apply).
    Notes:   restarts go one at a time in dependency order, each health-gated (_roll_out). BIND down or about to
             restart reads its zone files on start, so they are installed first (a running
             BIND frozen before, so the files hold what DHCP registered: 2.1.10.7). Kea's changed files are
             reloaded over its control socket once BIND is reloaded (state["kea_reload"], 2.1.10.45); then the
             filtering resolver forgets the names whose records changed (state["names"], 2.1.10.46: a flush that
             fails is a warning). While Kea's DNS key is replaced (state["kea_drop"], 2.1.10.42) BIND takes the new
             key before Kea, and drops the old one last. The web UI is restarted last with --no-block: this apply may
             have come from it. No --pull on image builds."""
    restart = set(state["restart"])
    if state["daemon_reload"]:
        print("Reloading systemd daemon...")
        _quiet(["systemctl", "daemon-reload"], "systemctl daemon-reload", 15)
    res = _quiet(["docker", "ps", "--format", "{{.Names}}"], "docker ps", 15, capture=True)
    running = res.stdout.split("\n") if res else []

    bind9_live = "bind9" in running and "bind9" not in restart
    if not bind9_live:
        for zone, src, dst in state["zones"]:
            if "bind9" in running:               # about to restart: sync its journal first (DHCP's PTRs, 2.1.10.7),
                freeze_and_install(zone, src, dst, *bind_ids)       # BIND's write landed before the new file
            else:
                install_zone_file(src, dst, *bind_ids)
    restart_webui = "fabric-web" in restart or state["webui"]
    restart.discard("fabric-web")
    for folder in sorted(state["rebuild"]):
        compose = os.path.join(paths["base"], folder, "docker-compose.yml")
        verb = "build" if compose_builds(compose) else "pull"     # fabric's published images are pulled
        print(f"{'Rebuilding' if verb == 'build' else 'Pulling'} {folder} image...")
        subprocess.run(["docker", "compose", "-f", compose, verb], timeout=1200)
    early = bind9_live and state["bind9_config"] and state.get("kea_drop") and "kea" in restart
    if early:                                     # Kea restarts on a new key (2.1.10.42): BIND knows it first
        _reconfig_bind()
    _roll_out(restart)                            # one at a time, health-gated, stopping at a failure (2.1.14.15)

    print("Reloading active services...")
    if bind9_live:
        if state["bind9_config"] and not early:
            _reconfig_bind()
        for zone, src, dst in state["zones"]:
            reload_zone(zone, src, dst, *bind_ids)
    if state.get("kea_reload"):                   # after BIND took its keys and zones: Kea's changed files (2.1.10.45)
        print("Reloading Kea's configuration...")
        took = reload_kea(final_vars, state["kea_reload"])
        if took["restarted"]:
            restart.add("kea")
    if state.get("names"):            # BIND serves the new records: the resolver forgets the old (2.1.10.46)
        flushed = flush_published_names(final_vars, state["names"])
        if flushed["flushed"]:
            print(f"Filtering resolver: {flushed['flushed']} published name(s) flushed from its cache")
        if flushed["error"]:
            print(f"Warning: {flushed['error']}")
    if "nginx" in running and "nginx" not in restart and state["nginx"]:
        print("Reloading NGINX...")
        _quiet(["docker", "exec", "nginx", "nginx", "-s", "reload"], "Reloading NGINX", 15)
    if "samba" in running or "samba" in restart:
        try:                                      # idempotent: the domain as fabric wants it (manual 1.6.5.15)
            done = converge_domain(final_vars, paths["federation"], secrets)
            print("Windows domain: " + ("; ".join(done) if done else "as wanted"))
            for line in move_subnets_to_plan(final_vars, secrets):    # once: 0.7's subnets into the plan (1.10.4.15)
                print(line)
            for line in move_options_to_plan(final_vars, secrets):    # once: the global options too (2.1.10.23)
                print(line)
            if final_vars.get("install_keycloak") and install_sso_keytab(final_vars) and "keycloak" in running:
                print("Restarting Keycloak (Kerberos sign-in keytab)...")
                _quiet(["systemctl", "restart", "keycloak"], "Restart of keycloak", 180)
            if write_bind_dlz(final_vars):        # the first provisioning: BIND now serves the AD zone
                print("Restarting bind9 (the AD zone through DLZ)...")
                _quiet(["systemctl", "restart", "bind9"], "Restart of bind9", 60)
        except ValidationError as e:              # reported: the rest of the apply still has to happen
            print(f"Warning: {e}")
    cleanup_error = None
    if "bind9" in running or "bind9" in restart:      # DHCP names left behind for addresses set by hand (2.1.10.22)
        try:
            key = kea_key(secrets)
            for owner, rtype, rdata in clear_stale_dhcp_names(final_vars, hand_set_addresses(final_vars),
                                                              key["secret"], "root", "apply", key_name=key["name"]):
                print(f"DHCP name left behind deleted: {owner.rstrip('.')} {rtype} {rdata}")
        except ValidationError as e:              # raised once the rest of the apply is done
            cleanup_error = e
    if state["agent"] and _enabled("fabric-agent"):
        print("Restarting fabric-agent (queued)...")            # --no-block: this apply may run inside it
        subprocess.run(["systemctl", "restart", "--no-block", "fabric-agent"], timeout=15)
    if final_vars.get("federation_endpoint") and (state["federation_unit"] or subprocess.run(
            ["systemctl", "is-active", "--quiet", "fabric-federation"]).returncode != 0):
        print("Starting the federation endpoint...")
        subprocess.run(["systemctl", "enable", "fabric-federation"], capture_output=True, timeout=30)
        subprocess.run(["systemctl", "restart", "fabric-federation"], timeout=30)
    if restart_webui and _enabled("fabric-web"):
        print("Restarting webui (queued)...")
        subprocess.run(["systemctl", "restart", "--no-block", "fabric-web"], timeout=15)
        restart.add("fabric-web")
    if state.get("kea_drop"):                     # Kea runs on its new key: BIND drops the old one (2.1.10.42)
        print(f"Kea's DNS key: {state['kea_drop']()} dropped from BIND")
    if cleanup_error:
        raise ValidationError(f"{cleanup_error}. The rest of the apply is done; fabric-dhcp-names.timer tries again "
                              "hourly (`sudo fabricctl dhcp clean-names` at once).")
    print("Deployment complete.")
    return restart
