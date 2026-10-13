import os
import subprocess
import time

from fabriclib.common.console import info, ok
from fabriclib.common.errors import ValidationError
from fabriclib.deploy.apply_deployment import apply_deployment
from fabriclib.directory.ensure_default_device_roles import ensure_default_device_roles
from fabriclib.dns_filter.resolver_tls_pending import resolver_tls_pending
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.keycloak.install_sso_keytab import install_sso_keytab
from fabriclib.ipam.move_subnets_to_plan import move_subnets_to_plan
from fabriclib.samba.converge_domain import converge_domain
from fabriclib.samba.allow_rodc_cache import allow_rodc_cache
from fabriclib.samba.finish_join import finish_join
from fabriclib.samba.write_bind_dlz import write_bind_dlz
from fabriclib.secrets.save_secrets import save_secrets
from fabriclib.setup.ask_site_number import ask_site_number
from fabriclib.setup.errors import SetupError
from fabriclib.setup.retire_adguard import retire_adguard
from fabriclib.setup.retire_renamed_units import retire_renamed_units
from fabriclib.setup.service_order import ORDER
from fabriclib.setup.ensure_db_rotation import align_postgres_roles
from fabriclib.setup.start_unit import start_unit



def run(ctx):
    """Purpose: start the stack in dependency order (ORDER), converge the domain (and at the root site make fabric's
             default device roles), configure Keycloak, then fabric-agent and the web UI, and activate fabric.target.
    Inputs:  ctx — SetupContext: vars install_keycloak, install_webui, install_fluentbit, install_kea,
             install_freeradius, install_resolver, federation_endpoint; restart_services (units to
             restart); target_dir (lib/keycloak_bootstrap.py), vars_file, secrets_file, config_dir.
    Returns: None. fabric.target enabled and started; renamed units retired; the deploy rendered again when the DNS
             filter's certificate arrived after it (DoT and DoH, 1.12.2.16); every enabled unit running and its
             container healthy; the domain converged; the site's number asked once, while it has none (2.1.10.16;
             unattended, the suggestion); 0.7's DHCP subnets moved into the address plan (1.10.4.15);
             Keycloak given the DC's Kerberos keytab; Keycloak configured (up to 6 tries, 15 s apart); fabric-agent,
             fabric-web and fabric-scep-hook running when the web UI is on; fabric-federation running when
             federation_endpoint is on.
             Once Keycloak's password is OpenBao's, Postgres's roles are made to match fabric's secrets before
             Keycloak starts (a reinstall's fresh data folder, 2.1.7.4).
    Fails:   SetupError when a container is not healthy (start_unit), the domain cannot be converged, the default
             device roles cannot be made, or Keycloak configuration still fails after 6 tries; CalledProcessError
             from systemctl.
    Feeds:   setup step `start`, run by run_setup via STEPS."""
    v, lib = ctx.vars, os.path.join(ctx.target_dir, "lib")
    # fabric.target groups every unit: systemctl start|stop|restart fabric.target
    subprocess.run(["systemctl", "enable", "fabric.target"], check=True, capture_output=True)
    for unit in retire_renamed_units():
        ok(f"{unit}: retired (renamed)")
    for item in retire_adguard(v, ctx.secrets, ctx.secrets_file, ctx.config_dir):   # 0.7: the resolver takes 53
        ok(f"AdGuard Home retired: {item}")
    if resolver_tls_pending(v):          # the certificates step ran after the deploy: render again (1.12.2.16)
        ctx.restart_services.update(apply_deployment(start_services=False) or ())
        ok("DNS filter: DNS-over-TLS and DNS-over-HTTPS for clients, with the DNS name's certificate")
    for unit, container, flag in ORDER:
        if flag and not v.get(flag):
            continue
        info(f"{unit}…")
        ok(f"{unit}: {start_unit(unit, container, unit in ctx.restart_services)}")
        if unit == "postgres" and align_postgres_roles(ctx.secrets):
            ok("postgres: Keycloak's role and password as fabric's secrets hold them (2.1.7.4)")

    try:
        done = converge_domain(v, os.path.join(ctx.config_dir, "federation.yaml"), ctx.secrets)
    except ValidationError as e:
        raise SetupError(str(e))
    ok(f"directory {v['ad_domain']}: " + (f"{len(done)} change(s)" if done else "as wanted"))
    for line in ask_site_number(v, ctx.secrets, ctx.non_interactive):     # once: the site's number (2.1.10.16)
        info(line)
    for line in move_subnets_to_plan(v, ctx.secrets):        # once: 0.7's subnets into the address plan (1.10.4.15)
        info(line)
    if v.get("install_keycloak") and install_sso_keytab(v):     # Kerberos sign-in's keytab (manual 2.3.6.2.6.2)
        ok(f"keycloak: {start_unit('keycloak', 'keycloak', True)} (Kerberos sign-in keytab)")
    if (ctx.secrets or {}).get("ad_join"):        # a site whose DC just joined: its join account goes (1.9.8.4)
        try:
            cached = allow_rodc_cache(v)              # while the join account still exists (2.1.6.52)
            if cached:
                ok(cached)
            ok(finish_join(v, ctx.secrets))
            save_secrets({"ad_join": None}, ctx.secrets_file)
            ctx.secrets = None
        except ValidationError as e:
            raise SetupError(str(e))
    if write_bind_dlz(v):                         # the first provisioning: BIND now serves the AD zone
        ok(f"bind9: {start_unit('bind9', 'bind9', True)} (the AD zone through DLZ)")
    if is_root_site(os.path.join(ctx.config_dir, "federation.yaml")):    # the root site: fabric's defaults
        try:
            added = ensure_default_device_roles(v, ctx.secrets, ctx.path("fabric", "config", ".default-device-roles"))
        except ValidationError as e:
            raise SetupError(str(e))
        if added:
            ok("default device roles: " + ", ".join(added))

    if v.get("install_keycloak"):
        for attempt in range(6):
            res = subprocess.run(["python3", os.path.join(lib, "keycloak_bootstrap.py"),
                                  "--vars", ctx.vars_file, "--secrets", ctx.secrets_file],
                                 capture_output=True, text=True)
            if res.returncode == 0:
                break
            time.sleep(15)
        else:
            raise SetupError(f"Keycloak configuration failed:\n{res.stdout}{res.stderr}")
        ok("Keycloak configured (realm, the domain's people"
           + (", web UI client, sign-in flows)" if v.get("install_webui") else ")"))

    if v.get("install_webui"):
        subprocess.run(["systemctl", "enable", "--now", "fabric-agent"], check=True, capture_output=True)
        if "fabric-agent" in ctx.restart_services:
            subprocess.run(["systemctl", "restart", "fabric-agent"], check=True)
        ok(f"fabric-agent: {'restarted' if 'fabric-agent' in ctx.restart_services else 'running'}")
        ok(f"fabric-web: {start_unit('fabric-web', 'fabric-web', 'fabric-web' in ctx.restart_services)}")
        subprocess.run(["systemctl", "enable", "--now", "fabric-scep-hook"], check=True, capture_output=True)
        if "fabric-scep-hook" in ctx.restart_services:
            subprocess.run(["systemctl", "restart", "fabric-scep-hook"], check=True)
        ok("fabric-scep-hook (device enrolment's SCEP webhooks): running")

    if v.get("federation_endpoint"):
        subprocess.run(["systemctl", "enable", "--now", "fabric-federation"], check=True, capture_output=True)
        if "fabric-federation" in ctx.restart_services:
            subprocess.run(["systemctl", "restart", "fabric-federation"], check=True)
        ok(f"fabric-federation: {'restarted' if 'fabric-federation' in ctx.restart_services else 'running'}")

    # Everything is up: activate the target now (it is enabled for boot), so
    # `fabricctl stop|restart` / `systemctl ... fabric.target` reach every unit.
    subprocess.run(["systemctl", "start", "fabric.target"], check=True, capture_output=True)
    ok("fabric.target active (systemctl status fabric.target)")
