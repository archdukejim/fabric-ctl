#!/usr/bin/env python3
"""fabricctl lifecycle commands (routing only; each command lives in fabriclib/setup/).

  fabricctl setup [options]      install or re-converge (fabricctl setup --help)
  fabricctl doctor               end-to-end checks of the running install
  fabricctl status|start|stop|restart
                                 the whole stack (systemd fabric.target)
  fabricctl certs [--force|--scheduled]
                                 renew service certificates that need it (--force: all; --scheduled:
                                 the daily timer's run, recorded for status and doctor)
  fabricctl certs issued         certificates issued by hand, client certificates and site CAs
  fabricctl acme info|enroll|list|remove
                                 ACME from fabric's CA for machines on the LAN (DNS-01 keys)
  fabricctl certs revoke <serial|name> [--reason R]
                                 revoke one: published in the CRL at once
  fabricctl tsig list|add|update|set-secret|rotate|remove
                                 TSIG keys for RFC2136 updates (fabricctl tsig --help)
  fabricctl acl list|add|remove  BIND ACLs (who may query the zones)
  fabricctl dns-filter lists|apply|status|log|stats|ingest
                                 the DNS filter's BIND resolver: its lists, their state, the query log
  fabricctl dhcp status|leases|reserve|unreserve|add-subnet|set-subnet|remove-subnet|option|class|clean-names
                                 DHCP (optional Kea): subnets, leases, reservations, options, client classes
  fabricctl ipam show|find|export|block|vlan|subnet|range|address|option|class|netboot|watch|sync|scan|scan-requests
                                 the address manager: every site's VLANs, subnets, ranges, addresses, DHCP options,
                                 netboot; the plan poll, Sync now, scans of a subnet
                                 (fabricctl ipam --help)
  fabricctl radius status|log|add-client|rotate-secret|remove-client
                                 802.1X (optional FreeRADIUS): RADIUS clients, decisions
  fabricctl domain status|password-policy|add-machine|sort-machines|host-managed|grant
                                 the domain (Samba AD): its DC, roles, password policy, machines to join,
                                 sorting the machines that joined themselves, this host's management, the
                                 grants (who may do what, where)
  fabricctl admin reset-break-glass
                                 fabric-admin's lost password replaced, the account unlocked (writable DC)
  fabricctl host accounts list|approve|unapprove <name>
                                 this host's local root and administrator accounts; approved as break glass
  fabricctl local-admin status|checkout|policy|ssh|check
                                 this host's local-admin, set and kept by OpenBao: its password checked out,
                                 its rotation, local-admin over SSH (off by default)
  fabricctl people list|show|add|reset|disable|enable|remove|groups|group
                                 the site's people: sign-in, groups, removal (fabricctl people --help)
  fabricctl machines groups|group
                                 the site's host groups: groups of machines for sudo rules
  fabricctl sudo list|add|remove the site's sudo rules on its Linux machines: who, which commands, where
  fabricctl gpo load|templates|list|show|set|clear|starter
                                 Group Policy from ADMX templates for this site's machines and people
  fabricctl sso add|list|remove  apps (Proxmox VE, TrueNAS, …) signing people in through Keycloak
  fabricctl security [raise|lower|kerberos]
                                 sign-in layers: second factors, the web console's client certificate
  fabricctl settings export|import
                                 the setup wizard's settings as a file: export [FILE], import FILE [--yes]
  fabricctl federation status|enable|disable|invite|invitations|revoke|networks
                                 sites joining this install (setup --join on the new site)
  fabricctl vault status         OpenBao: sealed?, version, seal key, secret engines
  fabricctl logs status|set-password elastic
                                 log forwarding (optional Fluent Bit): destinations, sent, errors
  fabricctl images status|update|rollback|prune
                                 container images: validated versions, update, roll back, clean up
  fabricctl secrets list|show <name>
                                 fabric's own secrets (in OpenBao); `show` is audited
  fabricctl client-cert <user> [--days N]
                                 web UI client certificate (.p12) into ~/fabric-admin
  fabricctl uninstall            remove fabric from this host; offers to export all its data to a
                                 folder you choose first, and to remove the package too
                                 (unattended: --yes --export DIR|--no-export [--purge-package])
  fabricctl reinstall [--yes]    uninstall + setup, keeping config, secrets, the CA and certificates
  fabricctl restore <folder> [--yes]
                                 bring back a fabric exported by `uninstall --export` (or apt purge)

Older flag forms (still supported):
  fabricctl [--interactive]      the vars editor menu      fabricctl --print   list the vars
  fabricctl --apply              deploy vars.yaml now      fabricctl --version
  fabricctl --mint-certs [--apply] [--intermediate-ca [N]] [--kty T] [--size N]
                                 offline certificates from extra_certs (or asked for)
  fabricctl --service-cert [--apply]
                                 re-issue every service certificate
  fabricctl --render-jinja <file.j2> [--vars FILE] [--output FILE|DIR]
                                 render one template with fabric's vars
  fabricctl --client-cert <user> | --keycloak-sync | --update-containers
"""
import os
import subprocess
import sys

# Run as a script, Python puts fabriclib/ itself first on sys.path, where its
# folders (dns/, keycloak/) would shadow real packages. Use fabric/lib.
sys.path[0] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from fabriclib.common.ask import ask  # noqa: E402
from fabriclib.consent.show_consent_status import show_consent_status  # noqa: E402
from fabriclib.dhcp.run_dhcp_command import run_dhcp_command  # noqa: E402
from fabriclib.ipam.run_ipam_command import run_ipam_command  # noqa: E402
from fabriclib.dns.run_acl_command import run_acl_command  # noqa: E402
from fabriclib.dns_filter.run_dns_filter_command import run_dns_filter_command  # noqa: E402
from fabriclib.radius.run_radius_command import run_radius_command  # noqa: E402
from fabriclib.samba.run_domain_command import run_domain_command  # noqa: E402
from fabriclib.breakglass.run_admin_command import run_admin_command  # noqa: E402
from fabriclib.hostaccounts.run_host_command import run_host_command  # noqa: E402
from fabriclib.localadmin.run_local_admin_command import run_local_admin_command  # noqa: E402
from fabriclib.directory.run_people_command import run_people_command  # noqa: E402
from fabriclib.directory.run_machines_command import run_machines_command  # noqa: E402
from fabriclib.directory.run_sudo_command import run_sudo_command  # noqa: E402
from fabriclib.samba.run_gpo_command import run_gpo_command  # noqa: E402
from fabriclib.dns.run_tsig_command import run_tsig_command  # noqa: E402
from fabriclib.keycloak.run_sso_command import run_sso_command  # noqa: E402
from fabriclib.security.run_security_command import run_security_command  # noqa: E402
from fabriclib.settings.run_settings_command import run_settings_command  # noqa: E402
from fabriclib.federation.run_federation_command import run_federation_command  # noqa: E402
from fabriclib.images.run_images_command import run_images_command  # noqa: E402
from fabriclib.logs.run_logs_command import run_logs_command  # noqa: E402
from fabriclib.pki.hand_out_client_cert import hand_out_client_cert  # noqa: E402
from fabriclib.secrets.run_secrets_command import run_secrets_command  # noqa: E402
from fabriclib.pki.run_mint_certs_command import run_mint_certs_command  # noqa: E402
from fabriclib.pki.run_service_cert_command import run_service_cert_command  # noqa: E402
from fabriclib.system.render_template_file import render_template_file  # noqa: E402
from fabriclib.setup import run_setup  # noqa: E402
from fabriclib.setup.backup_install import backup_install  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.restore_install import restore_install  # noqa: E402
from fabriclib.setup.run_restore_command import run_restore_command  # noqa: E402
from fabriclib.setup.run_uninstall_command import run_uninstall_command  # noqa: E402
from fabriclib.setup.stage_source import stage_source  # noqa: E402
from fabriclib.system.control_stack import control_stack  # noqa: E402
from fabriclib.vault.run_vault_command import run_vault_command  # noqa: E402
from fabriclib.setup.uninstall import uninstall  # noqa: E402
from fabriclib.pki.run_acme_command import run_acme_command  # noqa: E402
from fabriclib.pki.run_certs_command import run_certs_command  # noqa: E402
from fabriclib.pki.show_cert_warnings import show_cert_warnings  # noqa: E402
from fabriclib.system.show_relaxed_settings import show_relaxed_settings  # noqa: E402
from fabriclib.system.show_memory_plan import show_memory_plan  # noqa: E402


def _base(args):
    """Purpose: the install root named on the command line.
    Inputs:  args — the subcommand's arguments (list of str); "--deploy-base DIR" as two words picks DIR
             ("--deploy-base=DIR" is not recognised).
    Returns: DIR, or "/opt" when --deploy-base is absent.
    Fails:   IndexError if --deploy-base is the last argument (no value follows).
    Feeds:   main (the SetupContext of every command, restore and uninstall)."""
    return args[args.index("--deploy-base") + 1] if "--deploy-base" in args else "/opt"


def _without_base(args):
    """Purpose: a subcommand's arguments without "--deploy-base DIR" (the commands that check their arguments).
    Inputs:  args — list of str.
    Returns: list of str.
    Fails:   never.
    Feeds:   main (acme, certs)."""
    at = args.index("--deploy-base") if "--deploy-base" in args else None
    return args if at is None else args[:at] + args[at + 2:]


def _confirm(prompt, args):
    """Purpose: ask the operator to confirm a destructive command unless --yes/-y was given.
    Inputs:  prompt — text shown before "Type 'yes' to continue:"; args — the subcommand's arguments.
    Returns: True when --yes/-y is in args or the answer is "yes" (any case); otherwise False.
    Fails:   EOFError from input() when stdin is closed and --yes was not given.
    Feeds:   main (`reinstall`)."""
    if "--yes" in args or "-y" in args:
        return True
    return ask("cli.reinstall.confirm", f"{prompt} Type 'yes' to continue: ").lower() == "yes"


def _version():
    """Purpose: `fabricctl --version`: this install's version and build.
    Inputs:  none (<fabric>/VERSION and BUILD next to this code).
    Returns: 0 after printing them.
    Fails:   never (a missing file prints "unknown" or nothing).
    Feeds:   main (before the root check: anyone may ask)."""
    fabric = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def read(name):
        path = os.path.join(fabric, name)
        return open(path).read().strip() if os.path.exists(path) else ""
    print(f"fabricctl version {read('VERSION') or 'unknown'}")
    if read("BUILD"):
        print(read("BUILD"))
    return 0


def _flags(argv):
    """Purpose: route the older flag forms (`fabricctl --mint-certs`, `--apply`, …) to their function.
    Inputs:  argv — the command-line words; the first known flag decides, as manage.sh did.
    Returns: exit status, or None when argv holds no known flag.
    Fails:   whatever the handler raises; SystemExit from the vars editor.
    Feeds:   main."""
    fabric = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    lib = os.path.join(fabric, "lib")
    vars_file = os.path.join(fabric, "config", "vars.yaml")

    def value(flag):
        i = argv.index(flag) + 1
        return argv[i] if flag in argv and i < len(argv) and not argv[i].startswith("--") else None

    for flag in argv:
        if flag == "--mint-certs":
            return run_mint_certs_command(vars_file, os.path.join(fabric, "archive"), argv)
        if flag == "--service-cert":
            return run_service_cert_command(SetupContext(deploy_base=os.path.dirname(fabric)).load_state(), argv)
        if flag == "--render-jinja":
            return render_template_file(value("--render-jinja"), value("--vars") or vars_file, value("--output"))
        if flag in ("--print", "--interactive"):
            return subprocess.call([sys.executable, os.path.join(lib, "interactive.py"), flag])
        if flag == "--update-containers":        # the old name
            return main(["images", "update", "--all"])
        if flag == "--client-cert":
            return main(["client-cert", *([value("--client-cert")] if value("--client-cert") else [])])
        if flag == "--keycloak-sync":
            return subprocess.call([sys.executable, os.path.join(lib, "keycloak_bootstrap.py"), "--vars", vars_file,
                                    "--secrets", os.path.join(fabric, "config", "fabric-secrets.yml")])
    if "--apply" in argv:
        return subprocess.call([sys.executable, os.path.join(lib, "interactive.py"), "--apply"])
    return None


def main(argv):
    """Purpose: route `fabricctl <command> ...` to the one function that implements it (routing only).
    Inputs:  argv — command-line words after the program name; argv[0] is the command (none: help).
             Every command except help needs root. --deploy-base DIR selects the install root.
    Returns: exit status (int): the handler's status, 0 for help, 2 for an unknown command or missing
             arguments (the module docstring is printed). `reinstall` never returns: after backup, uninstall
             and restore it replaces the process with `cli.py setup --yes` from the staged source.
    Fails:   SystemExit("Run as root ...") when not root. start/stop/restart/status: any exception is printed
             as "error: ..." and 1 is returned. Other commands let their handlers' exceptions propagate as a
             traceback (e.g. ValidationError, SetupError from `certs`, ValueError for a non-numeric --days).
    Feeds:   `__main__` of this file, run by /usr/bin/fabricctl (package), manage.sh (everything on an install;
             no arguments there opens the vars editor) and the OpenBao unit (`vault unlock`/`wipe-key`); the exit
             status is the process's. The older flag forms go through _flags."""
    if argv[:1] == ["--version"]:
        return _version()
    if os.geteuid() != 0:
        sys.exit("Run as root (sudo fabricctl ...)")
    if argv and argv[0].startswith("--") and argv[0] not in ("--help",):
        status = _flags(argv)
        if status is not None:
            return status
    cmd, args = (argv[0], argv[1:]) if argv else ("help", [])
    if cmd == "setup":
        return run_setup.main(args)
    if cmd == "doctor":
        return run_setup.main(["--doctor", *args])
    if cmd == "secrets":
        return run_secrets_command(args, SetupContext(deploy_base=_base(args)).secrets_file)
    if cmd == "logs":
        return run_logs_command(SetupContext(deploy_base=_base(args)).load_state(), args)
    if cmd == "radius":
        return run_radius_command(SetupContext(deploy_base=_base(args)).load_state().vars, args)
    if cmd == "domain":
        return run_domain_command(SetupContext(deploy_base=_base(args)).load_state().vars, args)
    if cmd == "admin":
        ctx = SetupContext(deploy_base=_base(args))
        return run_admin_command(ctx.load_state().vars, _without_base(args), ctx.config_dir)
    if cmd == "host":
        return run_host_command(SetupContext(deploy_base=_base(args)).config_dir, _without_base(args))
    if cmd == "local-admin":
        ctx = SetupContext(deploy_base=_base(args))
        return run_local_admin_command(ctx.load_state().vars, ctx.config_dir, _without_base(args))
    if cmd == "people":
        return run_people_command(SetupContext(deploy_base=_base(args)).load_state().vars, _without_base(args))
    if cmd == "machines":
        return run_machines_command(SetupContext(deploy_base=_base(args)).load_state().vars, _without_base(args))
    if cmd == "sudo":
        return run_sudo_command(SetupContext(deploy_base=_base(args)).load_state().vars, _without_base(args))
    if cmd == "gpo":
        return run_gpo_command(SetupContext(deploy_base=_base(args)).load_state().vars, args)
    if cmd == "federation":
        return run_federation_command(SetupContext(deploy_base=_base(args)).load_state(), args)
    if cmd == "dhcp":
        return run_dhcp_command(SetupContext(deploy_base=_base(args)).load_state().vars, args)
    if cmd == "ipam":
        return run_ipam_command(SetupContext(deploy_base=_base(args)).load_state().vars, _without_base(args))
    if cmd == "dns-filter":
        return run_dns_filter_command(SetupContext(deploy_base=_base(args)).load_state().vars, _without_base(args))
    if cmd == "images":
        return run_images_command(SetupContext(deploy_base=_base(args)).load_state(), args)
    if cmd == "vault":
        return run_vault_command(SetupContext(deploy_base=_base(args)).load_state().vars, args)
    if cmd == "acme":
        return run_acme_command(SetupContext(deploy_base=_base(args)), _without_base(args))
    if cmd == "certs":
        return run_certs_command(SetupContext(deploy_base=_base(args)), _without_base(args))
    if cmd == "client-cert" and args and not args[0].startswith("-"):
        days = int(args[args.index("--days") + 1]) if "--days" in args else 365
        p12, password = hand_out_client_cert(SetupContext(deploy_base=_base(args)).load_state().vars, args[0], days)
        print(f"client certificate for '{args[0]}': {p12}")
        print(f".p12 password (shown once): {password}")
        return 0
    if cmd in ("start", "stop", "restart", "status"):
        try:
            rows = control_stack(cmd)
        except Exception as e:           # ValidationError or a timeout: report, do not trace
            print(f"error: {e}", file=sys.stderr)
            return 1
        for unit, state, health in rows:
            print(f"{unit:<16} {state:<10} {health}")
        if cmd != "status":
            print(f"fabric: {cmd} done (systemctl {cmd} fabric.target)")
        else:
            ctx = SetupContext(deploy_base=_base(args))
            show_consent_status(ctx.config_dir)
            vars_ = ctx.load_state().vars
            show_relaxed_settings(vars_)
            show_memory_plan(vars_)
            show_cert_warnings(vars_)
        return 0
    if cmd == "tsig":
        return run_tsig_command(args)
    if cmd == "sso":
        return run_sso_command(args)
    if cmd == "security":
        return run_security_command(args)
    if cmd == "settings":
        return run_settings_command(_without_base(args))
    if cmd == "acl":
        return run_acl_command(args)
    if cmd == "restore":
        return run_restore_command(args, _base(args), os.path.abspath(__file__))
    if cmd == "uninstall":
        return run_uninstall_command(args, _base(args))
    if cmd == "reinstall":
        ctx = SetupContext(deploy_base=_base(args))
        if not _confirm("Reinstall fabric (config, secrets, CA and certificates are kept).", args):
            return 1
        saved = backup_install(ctx)
        source = stage_source(ctx)          # uninstall deletes an installed copy
        uninstall(ctx)
        restore_install(ctx, saved)
        cli = os.path.join(source, "lib", "fabriclib", "cli.py")
        os.execv(sys.executable, [sys.executable, cli, "setup", "--yes",
                                  *[a for a in args if a not in ("--yes", "-y")]])
    print(__doc__)
    return 0 if cmd in ("help", "--help", "-h") else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
