import os

from agent.job_store import JOBS
from agent.route_not_found import RouteNotFound
from fabriclib.common.load_vars import load_vars
from fabriclib.common.read_audit import read_audit
from fabriclib.consent.consent_status import consent_status
from fabriclib.dhcp.dhcp_overview import dhcp_overview
from fabriclib.dns.list_tsig_keys import list_tsig_keys
from fabriclib.dns.list_zones import list_zones
from fabriclib.dns.reverse_zones import reverse_zones
from fabriclib.dns.zone_detail import zone_detail
from fabriclib.dns_filter.filter_overview import filter_overview
from fabriclib.ipam.networks_csv import networks_csv
from fabriclib.ipam.networks_overview import networks_overview
from fabriclib.federation.federation_overview import federation_overview
from fabriclib.ipam.scannable_subnets import scannable_subnets
from fabriclib.ipam.options.options_overview import options_overview
from fabriclib.directory.device_overview import device_overview
from fabriclib.directory.list_host_groups import list_host_groups
from fabriclib.directory.list_people import list_people
from fabriclib.directory.list_sudo_rules import list_sudo_rules
from fabriclib.images.image_status import image_status
from fabriclib.pki.acme_info import acme_info
from fabriclib.pki.acme_machines import acme_machines
from fabriclib.pki.ca_summary import ca_summary
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.scep.list_enrolments import list_enrolments
from fabriclib.vault.ssh.ssh_overview import ssh_overview
from fabriclib.radius.radius_guides import radius_guides
from fabriclib.samba.domain_overview import domain_overview
from fabriclib.samba.gpo_overview import gpo_overview
from fabriclib.samba.logon_overview import logon_overview
from fabriclib.radius.radius_overview import radius_overview
from fabriclib.radius.radius_sessions import radius_sessions
from fabriclib.system.service_status import service_status
from fabriclib.system.version_info import version_info
from fabriclib.vault.detect_devices import detect_devices
from fabriclib.vault.list_slots import list_slots
from fabriclib.vault.vault_status import vault_status
from fabriclib.pki.cert_warnings import cert_warnings
from fabriclib.system.relaxed_settings import relaxed_settings
from fabriclib.security.signin_layers import read_lowered, signin_rows
from fabriclib.common.paths import VARS_FILE
from fabriclib.setup.context import SetupContext

# GET /v1/<route> -> the read operation answering it (vars are read per request)
READS = {
    ("version",): lambda: version_info(),
    ("services",): lambda: service_status(),
    ("host-changes",): lambda: consent_status(os.path.join(load_vars()["deploy_base_dir"], "fabric", "config")),
    ("relaxed-settings",): lambda: relaxed_settings(load_vars()),
    ("cert-warnings",): lambda: cert_warnings(load_vars()),
    ("security",): lambda: signin_rows(load_vars(), read_lowered(os.path.dirname(VARS_FILE))),
    ("zones",): lambda: list_zones(),
    ("audit",): lambda: read_audit(),
    ("pki", "ca"): lambda: ca_summary(load_vars()),
    ("pki", "issued"): lambda: list_issued(),
    ("pki", "enrolments"): lambda: list_enrolments(),
    ("tsig",): lambda: list_tsig_keys(),
    ("reverse-zones",): lambda: reverse_zones(load_vars()),
    ("devices",): lambda: device_overview(load_vars()),
    ("people",): lambda: list_people(load_vars()),
    ("domain",): lambda: domain_overview(load_vars()),
    ("domain", "logon"): lambda: logon_overview(load_vars()),
    ("host-groups",): lambda: list_host_groups(load_vars()),
    ("sudo",): lambda: list_sudo_rules(load_vars()),
    ("gpo",): lambda: gpo_overview(load_vars()),
    ("federation",): lambda: federation_overview(load_vars()),
    ("dhcp",): lambda: dhcp_overview(load_vars()),
    ("networks",): lambda: networks_overview(load_vars()),
    ("ipam", "scan"): lambda: {"subnets": scannable_subnets(load_vars())},
    ("dns-filter",): lambda: filter_overview(load_vars()),
    ("radius",): lambda: radius_overview(load_vars()),
    ("radius", "guides"): lambda: radius_guides(load_vars()),
    ("radius", "sessions"): lambda: radius_sessions(load_vars()),
    ("vault",): lambda: vault_status(load_vars()),
    ("vault", "devices"): lambda: detect_devices(v=load_vars()),
    ("images",): lambda: image_status(SetupContext(deploy_base=load_vars()["deploy_base_dir"]).load_state()),
    ("pki", "acme"): lambda: {"info": acme_info(load_vars()), "machines": acme_machines(load_vars()),
                              "domain": load_vars()["domain"]},
}


def get_route(route, user=None):
    """Purpose: answer GET /v1/<route>: one fabriclib read operation per route.
    Inputs:  route — list of path segments after /v1/ (already authorized by the handler); user — the token's user
             (None for root): a job is read only by the person who started it.
    Returns: the operation's JSON-serialisable result. zones/<key>: zone_detail; vault/slots: the unlock methods with
             this host's name; images: the image status rows; pki/acme: {info, machines, domain}; jobs/<id>: the job;
             networks[/<site>]: networks_overview (the Networks tab, a site this console shows); networks/<site>/export:
             networks_csv ({"csv", "name"}); ipam/options/<site>[/<target>]: options_overview (the DHCP options and,
             given a target, its effective options with their sources, 1.10.4.24.3);
             pki/enrolments: list_enrolments; ssh: ssh_overview for the token's user.
    Fails:   RouteNotFound for any other route (-> 404); whatever the operation raises (ValidationError -> 400).
    Feeds:   agent/handler.py (dispatch)."""
    if tuple(route) in READS:
        return READS[tuple(route)]()
    if len(route) == 2 and route[0] == "zones":
        return zone_detail(route[1])
    if len(route) == 2 and route[0] == "networks":
        return networks_overview(load_vars(), route[1])
    if len(route) == 3 and route[0] == "networks" and route[2] == "export":
        return networks_csv(load_vars(), route[1])
    if len(route) in (3, 4) and route[:2] == ["ipam", "options"]:
        return options_overview(load_vars(), "" if route[2] == "-" else route[2], route[3] if len(route) == 4 else "")
    if len(route) == 2 and route[0] == "jobs":
        return JOBS.read(route[1], user)
    if route == ["ssh"]:                     # SSH certificates: may this person sign? (1.6.11.9)
        return ssh_overview(load_vars(), user)
    if route == ["vault", "slots"]:
        v = load_vars()
        return {"slots": list_slots(v), "host": v.get("hostname", "")}
    raise RouteNotFound()
