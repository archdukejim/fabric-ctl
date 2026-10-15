import ipaddress
import os
import subprocess

from fabriclib.common.console import info, ok, warn
from fabriclib.common.keep_original import ORIGINALS
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_firewall import plan_firewall
from fabriclib.consent.plan_own_rules import plan_own_rules
from fabriclib.consent.plan_ports import plan_ports
from fabriclib.security.apply_docker_firewall import apply_docker_firewall
from fabriclib.security.firewall_rules import firewall_rules
from fabriclib.security.host_own_rules import OWN_RULES, host_own_rules
from fabriclib.security.ssh_ports import ssh_ports
from fabriclib.security.ufw_active import ufw_active
from fabriclib.security.ufw_rule import RECORDS, ufw_rule
from fabriclib.setup.errors import SetupError

UNIT = "/etc/systemd/system/fabric-firewall.service"
UNIT_TEXT = """[Unit]
Description=fabric: limit Docker-published ports to the LAN (DOCKER-USER)
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PYTHONPATH={lib}
ExecStart=/usr/bin/python3 -m fabriclib.security.apply_docker_firewall {vars}

[Install]
WantedBy=multi-user.target docker.service
"""


def _ssh_client():
    """Purpose: the IP address the current SSH session comes from.
    Inputs:  none (env SSH_CONNECTION; sudo must keep it).
    Returns: the client address (str), or None when not over SSH.
    Fails:   never.
    Feeds:   run (lockout guard)."""
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return parts[0] if parts else None


def _forget_rules(config_dir, kind, allowed, what):
    """Purpose: remove the ufw rules fabric added earlier for networks or interfaces no longer allowed; record the
             current ones.
    Inputs:  config_dir — the install's config folder (security/ufw_rule RECORDS: what fabric opened last time);
             kind — "ssh", "ntp", "dhcp" or "ad"; allowed — the networks or interfaces now; what — the service's
             name for messages.
    Returns: None; the record rewritten with allowed. Rules fabric did not add are never touched.
    Fails:   OSError writing the record (a failing `ufw delete` is ignored: the rule may be gone already).
    Feeds:   run."""
    record = os.path.join(config_dir, RECORDS[kind])
    previous = open(record).read().split() if os.path.exists(record) else []
    if kind == "ssh":            # a record from before ssh_ports names the network only: port 22
        previous = [x if "@" in x else f"{x}@22" for x in previous]
    for x in previous:
        if x not in allowed:
            subprocess.run(["ufw", "delete", "allow", *ufw_rule(kind, x)], capture_output=True)
            info(f"host firewall: {what} from {x} removed (no longer allowed)")
    with open(record, "w") as f:
        f.write("\n".join(allowed) + ("\n" if allowed else ""))


def _keep_ufw_state(config_dir):
    """Purpose: record once whether ufw was on before fabric first enabled it, so undoing the firewall can leave it
             as it was (manual 1.2.9.5).
    Inputs:  config_dir — the install's config folder (<config>/host-originals/ufw.state).
    Returns: None; the record written only when absent ("active" or "inactive").
    Fails:   OSError writing it; FileNotFoundError without ufw.
    Feeds:   run; read by undo/undo_firewall."""
    path = os.path.join(config_dir, ORIGINALS, "ufw.state")
    if os.path.exists(path):
        return
    out = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "w") as f:
        f.write("active\n" if "Status: active" in out else "inactive\n")


def run(ctx):
    """Purpose: the host firewall in the three steps the owner set (2.1.2.13), each after its own consent: the ports
             fabric needs opened in ufw (`ports`); the host secured — ufw on, incoming denied by default, SSH from the
             LAN, Docker-published ports LAN-only through DOCKER-USER, re-applied at boot by fabric-firewall.service
             (`firewall`); the host's own ufw rules removed (`own_rules`, recorded for uninstall to put back).
    Inputs:  ctx — SetupContext: vars lan_cidr, security.firewall (default True), security.firewall_allow
             (extra CIDRs, e.g. a VPN), install_kea + dhcp.interfaces (UDP 67 allowed on them), ntp_serve (UDP 123
             from the networks chrony answers — chrony_settings), the domain controller's ports — the rules come from
             security/firewall_rules; vars_file, target_dir, config_dir. Env SSH_CONNECTION.
    Returns: None. Rules fabric added earlier for a network or interface no longer allowed are removed (the records,
             security/ufw_rule RECORDS, say which are fabric's); whether ufw was on before is recorded once for undo.
             Each part only after its consent (else a warning, that part left as it is). security.firewall false:
             DOCKER-USER opened, fabric-firewall disabled, a warning; ufw left as it is.
    Fails:   SetupError when securing would lock out the SSH client (outside every allowed CIDR), or when the ports are
             declined while ufw is on (2.1.2.12: run_setup stops before any step; this is the backstop);
             CalledProcessError from ufw, systemctl or iptables; KeyError without lan_cidr; ValueError for an invalid
             CIDR.
    Feeds:   setup step `firewall`, run by run_setup via STEPS."""
    security = ctx.vars.get("security") or {}
    if not security.get("firewall", True):
        apply_docker_firewall(ctx.vars_file)
        subprocess.run(["systemctl", "disable", "--now", "fabric-firewall"], capture_output=True)
        warn("firewall disabled (security.firewall: false): published ports are reachable from anywhere")
        return
    rules = firewall_rules(ctx.vars, ctx.config_dir)

    # 1. the ports fabric needs (2.1.2.13)
    if not check_consent(ctx.config_dir, "ports", plan_ports(ctx.vars, ctx.config_dir)):
        if ufw_active():        # ufw's own rules would block fabric's containers from the DC on this host (2.1.2.12)
            raise SetupError("ufw is on, and without fabric's rules it blocks fabric's own containers from this "
                             "host's domain controller (Keycloak, FreeRADIUS): setup would fail later. fabric only "
                             "opens its own ports beside your rules: sudo fabricctl setup --approve ports")
        return
    _keep_ufw_state(ctx.config_dir)
    for kind, entries, what in (("ntp", rules["ntp"], "NTP"), ("dhcp", rules["dhcp"], "DHCP"),
                                ("ad", rules["ad"], "the domain controller")):
        for entry in entries:
            subprocess.run(["ufw", "allow", *ufw_rule(kind, entry)], check=True, capture_output=True)
        _forget_rules(ctx.config_dir, kind, entries, what)
    ok("host firewall: the ports fabric needs are open (the domain controller, NTP" +
       (", DHCP)" if rules["dhcp"] else ")"))

    # 2. securing the host: only what fabric needs plus SSH (asked only after the ports are allowed)
    allowed = rules["ssh"]
    client = _ssh_client()
    if client and not any(ipaddress.ip_address(client) in ipaddress.ip_network(c, strict=False) for c in allowed):
        raise SetupError(f"your SSH session comes from {client}, outside {', '.join(allowed)}; enabling the "
                         f"firewall would lock you out. Add it to security.firewall_allow or connect from the LAN.")
    if not check_consent(ctx.config_dir, "firewall", plan_firewall(ctx.vars, ctx.config_dir)):
        return
    ports = ssh_ports()          # what sshd listens on, not a guessed 22
    info(f"host firewall (ufw): deny incoming, allow SSH (port {', '.join(map(str, ports))}) from "
         + ", ".join(allowed))
    for cmd in (["ufw", "default", "deny", "incoming"], ["ufw", "default", "allow", "outgoing"]):
        subprocess.run(cmd, check=True, capture_output=True)
    ssh = [f"{cidr}@{port}" for cidr in allowed for port in ports]
    for entry in ssh:
        subprocess.run(["ufw", "allow", *ufw_rule("ssh", entry)], check=True, capture_output=True)
    _forget_rules(ctx.config_dir, "ssh", ssh, "SSH")

    # 3. the host's own rules (asked only after securing is allowed, and only when there are any)
    own = host_own_rules(ctx.config_dir)
    if own and check_consent(ctx.config_dir, "own_rules", plan_own_rules(ctx.vars, ctx.config_dir)):
        record = os.path.join(ctx.config_dir, OWN_RULES)
        os.makedirs(os.path.dirname(record), mode=0o700, exist_ok=True)
        with open(record, "a") as f:         # kept for uninstall to put back
            f.write("".join(r + "\n" for r in own))
        warn(f"host firewall: removing {len(own)} rule(s) of this host's own (own_rules, 2.1.2.24); kept for uninstall "
             f"to put back, or now: sudo fabricctl setup --undo firewall")
        for r in own:
            subprocess.run(["ufw", "delete", *r.split()[1:]], capture_output=True)
            warn(f"host firewall: removed the host's own rule: {r}")
    subprocess.run(["ufw", "--force", "enable"], check=True, capture_output=True)

    lib = os.path.join(ctx.target_dir, "lib")
    with open(UNIT, "w") as f:
        f.write(UNIT_TEXT.format(lib=lib, vars=ctx.vars_file))
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "fabric-firewall"], check=True, capture_output=True)
    subprocess.run(["systemctl", "restart", "fabric-firewall"], check=True)
    ok(apply_docker_firewall(ctx.vars_file) + " (re-applied at boot by fabric-firewall.service)")
