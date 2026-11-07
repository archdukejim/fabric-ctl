import os
import time

from agent.job_store import JOBS
from agent.kept_store import KEPT, started
from agent.one_thing import one_thing
from agent.read_tree import read_tree
from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.read_audit import read_audit
from fabriclib.consent.consent_status import consent_status
from fabriclib.dhcp.dhcp_overview import dhcp_overview
from fabriclib.dns.list_tsig_keys import list_tsig_keys
from fabriclib.dns.list_zones import list_zones
from fabriclib.dns.reverse_zones import reverse_zones
from fabriclib.dns.zone_detail import zone_detail
from fabriclib.dns_filter.filter_overview import filter_overview
from fabriclib.federation.federation_overview import federation_overview
from fabriclib.federation.site_selector import site_selector
from fabriclib.directory.device_overview import device_overview
from fabriclib.directory.list_host_groups import list_host_groups
from fabriclib.directory.list_machines import list_machines
from fabriclib.directory.list_people import list_people
from fabriclib.directory.list_sudo_rules import list_sudo_rules
from fabriclib.domain.list_groups import list_groups
from fabriclib.domain.list_ous import list_ous
from fabriclib.domain.list_spns import list_spns
from fabriclib.domain.machine_overview import machine_overview
from fabriclib.domain.site_overview import site_overview
from fabriclib.domain.directory_overview import directory_overview
from fabriclib.domain.my_account import my_account
from fabriclib.domain.person_overview import person_overview
from fabriclib.domain.my_groups import my_groups
from fabriclib.domain.show_group import show_group
from fabriclib.grants.explain_grant import explain_grant
from fabriclib.grants.list_grants import list_grants
from fabriclib.hostaccounts.constants import RECORD
from fabriclib.grants.show_grant import show_grant
from fabriclib.images.image_status import image_status
from fabriclib.ipam.networks_csv import networks_csv
from fabriclib.ipam.networks_overview import networks_overview
from fabriclib.ipam.options.options_overview import options_overview
from fabriclib.ipam.scan_overview import scan_overview
from fabriclib.pki.acme_info import acme_info
from fabriclib.pki.acme_machines import acme_machines
from fabriclib.pki.ca_summary import ca_summary
from fabriclib.pki.list_issued import list_issued
from fabriclib.radius.radius_guides import radius_guides
from fabriclib.samba.domain_overview import domain_overview
from fabriclib.samba.gpo_overview import gpo_overview
from fabriclib.samba.kerberos_overview import kerberos_overview
from fabriclib.radius.radius_overview import radius_overview
from fabriclib.system.service_status import service_status
from fabriclib.system.version_info import version_info
from fabriclib.vault.detect_devices import detect_devices
from fabriclib.vault.list_slots import list_slots
from fabriclib.vault.vault_status import vault_status
from fabriclib.pki.cert_warnings import cert_warnings
from fabriclib.system.relaxed_settings import relaxed_settings
from fabriclib.system.host_reminders import host_reminders
from fabriclib.security.signin_layers import read_lowered, signin_rows
from fabriclib.common.paths import FEDERATION_FILE, VARS_FILE
from fabriclib.setup.context import SetupContext
from fabriclib.settings.export_settings import export_settings
from fabriclib.settings.settings_overview import settings_overview
from fabriclib.sizing.state import read_sizing



def _overview():
    """Purpose: the Overview's slow reads together, so they can be kept as one (manual 1.8.9.2, 2.3.8.9.1).
    Inputs:  none.
    Returns: {"services": service_status, "reminders": host_reminders, or None when they could not be read}.
    Fails:   what service_status raises.
    Feeds:   READS."""
    try:
        reminders = host_reminders(load_vars()["deploy_base_dir"])
    except (ValidationError, OSError):
        reminders = None
    return {"services": service_status(), "reminders": reminders}


def _reminders_stale(out):
    """Purpose: whether the kept Overview's reminders must be read afresh (manual 1.8.9.2): while the break-glass
             file's reminder shows, so it goes with its file (2.1.6.69); and once the local accounts' record changed
             after they were kept, since `fabricctl host accounts approve` writes it without the agent (2.1.6.78).
    Inputs:  out — the kept Overview, with "kept": {"age_s"}.
    Returns: bool.
    Fails:   never (a record that cannot be read leaves them as kept).
    Feeds:   get_route."""
    if any(r.get("kind") == "break-glass" for r in out.get("reminders") or ()):
        return True
    record = os.path.join(load_vars()["deploy_base_dir"], "fabric", "config", RECORD)
    try:
        return os.stat(record).st_mtime >= time.time() - out["kept"]["age_s"] - 1
    except OSError:
        return False


# GET /v1/<route> -> the read operation answering it (vars are read per request)
READS = {
    ("version",): lambda: {**version_info(), "host": load_vars().get("hostname", ""),          # the top bar (1.8.6.2)
                           "domain": load_vars().get("domain", "")},
    ("services",): lambda: service_status(),
    ("overview",): _overview,
    ("updates",): lambda: {"rows": image_status(SetupContext(deploy_base=load_vars()["deploy_base_dir"]).load_state())},
    ("host-changes",): lambda: consent_status(os.path.join(load_vars()["deploy_base_dir"], "fabric", "config")),
    ("relaxed-settings",): lambda: relaxed_settings(load_vars()),
    ("cert-warnings",): lambda: cert_warnings(load_vars()),
    ("reminders",): lambda: host_reminders(load_vars()["deploy_base_dir"]),
    ("security",): lambda: signin_rows(load_vars(), read_lowered(os.path.dirname(VARS_FILE))),
    ("zones",): lambda: list_zones(),
    ("audit",): lambda: read_audit(),
    ("pki", "ca"): lambda: ca_summary(load_vars()),
    ("pki", "issued"): lambda: list_issued(),
    ("tsig",): lambda: list_tsig_keys(),
    ("reverse-zones",): lambda: reverse_zones(load_vars()),
    ("devices",): lambda: device_overview(load_vars()),
    ("people",): lambda: list_people(load_vars()),
    ("machines",): lambda: list_machines(load_vars()),
    ("domain",): lambda: domain_overview(load_vars()),
    ("directory",): lambda: directory_overview(load_vars()),
    ("sites",): lambda: site_overview(load_vars()),
    ("sites", "tree"): lambda: site_selector(load_vars(), FEDERATION_FILE),     # the site selector (1.8.6.12)
    ("domain", "grants"): lambda: list_grants(load_vars()),
    ("domain", "kerberos"): lambda: kerberos_overview(load_vars()),
    ("domain", "kerberos", "spns"): lambda: list_spns(load_vars()),
    ("groups",): lambda: list_groups(load_vars()),
    ("ous",): lambda: list_ous(load_vars()),
    ("host-groups",): lambda: list_host_groups(load_vars()),
    ("sudo",): lambda: list_sudo_rules(load_vars()),
    ("gpo",): lambda: gpo_overview(load_vars()),
    ("federation",): lambda: federation_overview(load_vars()),
    ("dhcp",): lambda: dhcp_overview(load_vars()),
    ("networks",): lambda: networks_overview(load_vars()),
    ("dns-filter",): lambda: filter_overview(load_vars()),
    ("radius",): lambda: radius_overview(load_vars()),
    ("radius", "guides"): lambda: radius_guides(load_vars()),
    ("vault",): lambda: vault_status(load_vars()),
    ("vault", "devices"): lambda: detect_devices(v=load_vars()),
    ("images",): lambda: image_status(SetupContext(deploy_base=load_vars()["deploy_base_dir"]).load_state()),
    ("settings",): lambda: settings_overview(load_vars()),
    ("settings", "export"): lambda: export_settings(load_vars(), version_info()["version"]),
    ("pki", "acme"): lambda: {"info": acme_info(load_vars()), "machines": acme_machines(load_vars()),
                              "domain": load_vars()["domain"]},
}

# the console's fixed pages' slow reads, kept for a signed-in person (manual 1.8.9.2, causes 2.3.8.9.1)
KEPT_FIXED = (("overview",), ("updates",), ("dns-filter",), ("directory",), ("sites",), ("domain", "grants"),
              ("domain", "kerberos"), ("gpo",), ("federation",), ("pki", "ca"))


def keep_fixed_pages():
    """Purpose: the fixed pages' reads, kept from the agent's start, so the first person to open one need not wait.
    Inputs:  none.
    Returns: None.
    Fails:   never.
    Feeds:   agent/kept_store.start_kept."""
    for key in KEPT_FIXED:
        KEPT.register(key, READS[key])


def _kept(key, fn, perms, lasting=False):
    """Purpose: one read for a signed-in person through what is kept; the host itself (a root peer) and anything but
             a running fabric-agent always read live.
    Inputs:  key — the read's key; fn — the read; perms — the token's permissions (None for root); lasting — one of
             the fixed pages.
    Returns: the read's answer.
    Fails:   what fn raises.
    Feeds:   get_route."""
    if perms is None or not started():
        return fn()
    return KEPT.serve(key, fn, lasting)


def _pending(route, user, perms):
    """Purpose: Apply per page's reads (manual 1.8.6.5): this person's pending changes per page, or one page's
             Review with its queue (shown to whoever may see the page).
    Inputs:  route — ["pending"] or ["pending", <page>]; user — the token's user; perms — its permissions.
    Returns: pending: {page: {"pending", "running"}}; pending/<page>: PendingStore.page's dict.
    Fails:   RouteNotFound for an unknown page; ValidationError for a root peer (nothing is held for the host).
    Feeds:   get_route."""
    from agent.pending_thing import PAGES
    from agent.post_pending import PENDING
    if not user or perms is None:
        raise ValidationError("a pending change belongs to a signed-in person")

    def may_see(page):
        return PAGES.get(page) == "session" or PAGES.get(page) in perms

    if len(route) == 1:
        return PENDING.counts(user, may_see)
    if route[1] not in PAGES:
        raise RouteNotFound()
    return PENDING.page(user, route[1], may_see)


def get_route(route, user=None, perms=None):
    """Purpose: answer GET /v1/<route>: one fabriclib read operation per route.
    Inputs:  route — list of path segments after /v1/ (already authorized by the handler); user — the token's user
             (None for root): a job is read only by the person who started it, pending changes are each person's;
             perms — the token's permissions (who may see a page's queue; None for root).
    Returns: the operation's JSON-serialisable result. version: version_info with the host's name and domain (the
             console's top bar); zones/<key>: zone_detail; vault/slots: the unlock methods with
             this host's name; images: the image status rows; reminders: host_reminders (the console's top bar);
             pki/acme: {info, machines, domain}; jobs/<id>: the job; domain/grants: list_grants; domain/grants/<name>:
             show_grant; domain/grants/explain/<person>[/<machine>]: explain_grant; domain/kerberos: kerberos_overview;
             domain/kerberos/spns: list_spns; groups: list_groups; groups/<name>: show_group; ous: list_ous;
             account: my_account (the signed-in person's own details, groups, certificates and devices);
             people/<uid>: person_overview (a person's page); machines: list_machines (Computers);
             machines/<name>: machine_overview (a computer's page); sites: site_overview (Sites); sites/tree:
             site_selector (the top bar's site selector); directory: directory_overview (the Directory's Overview);
             sizing: read_sizing (the timer's last result, this person's alerts, 1.8.8.8);
             overview: {"services", "reminders"}; updates: {"rows"}: image_status; KEPT_FIXED, zones/<key>,
             account/groups and domain/grants/explain/...: for a signed-in person, what fabric-agent keeps, with
             "kept" (1.8.9);
             account/groups: my_groups (the groups the signed-in person manages); pending: the person's pending
             changes per page and the pages with an apply running (1.8.6.5); pending/<page>: the page's Review;
             settings: settings_overview (the setup wizard, 1.8.5); settings/export: {"text", "name"}, the
             settings file; networks[/<site>]: networks_overview (the Networks tab: any site of the domain,
             1.10.4.35); networks/<site>/export: networks_csv ({"csv", "name"}); ipam/options/<site>[/<target>]:
             options_overview (`-` for this site; a target's effective options with their sources, 1.10.4.24.3);
             ipam/scan: scan_overview (the subnets a scan may cover, and whether this person may scan here);
             directory/tree/ou=…/q=…/w=…/i=…: read_tree (the directory browser, 1.8.8.4).
    Fails:   RouteNotFound for any other route (-> 404); NotFound for a person, computer, group, grant or site
             (networks, ipam/options) that is not there (-> 404, 2.1.8.21; 1.10.4.40.1); whatever the operation
             raises (ValidationError -> 400).
    Feeds:   agent/handler.py (dispatch)."""
    if route == ["overview"]:
        out = _kept(("overview",), READS[("overview",)], perms, lasting=True)
        if out.get("kept") and _reminders_stale(out):
            out = {**out, "reminders": host_reminders(load_vars()["deploy_base_dir"])}
        return out
    if tuple(route) in KEPT_FIXED:
        return _kept(tuple(route), READS[tuple(route)], perms, lasting=True)
    if tuple(route) in READS:
        return READS[tuple(route)]()
    if len(route) == 2 and route[0] == "zones":
        return _kept(tuple(route), lambda: zone_detail(route[1]), perms)
    if len(route) == 2 and route[0] == "jobs":
        return JOBS.read(route[1], user)
    if route == ["account"]:
        return my_account(load_vars(), user)
    if route == ["account", "groups"]:
        return _kept(("account", "groups", user), lambda: my_groups(load_vars(), user), perms)
    if route[:1] == ["pending"] and len(route) <= 2:
        return _pending(route, user, perms)
    if route == ["sizing"]:                         # the file the timer writes, less what this person dismissed
        return read_sizing(os.path.join(load_vars()["deploy_base_dir"], "fabric", "config"), user)
    if len(route) == 2 and route[0] == "groups":
        return one_thing(show_group, load_vars(), route[1])
    if len(route) == 2 and route[0] == "people":
        return one_thing(person_overview, load_vars(), route[1], named=f"person {route[1]}")
    if len(route) == 2 and route[0] == "machines":
        return one_thing(machine_overview, load_vars(), route[1])
    if len(route) == 3 and route[:2] == ["domain", "grants"]:
        return one_thing(show_grant, load_vars(), route[2])
    if len(route) in (4, 5) and route[:3] == ["domain", "grants", "explain"]:
        return _kept(tuple(route), lambda: explain_grant(load_vars(), route[3], route[4] if len(route) == 5 else None),
                     perms)
    if len(route) == 2 and route[0] == "networks":
        return one_thing(networks_overview, load_vars(), route[1])
    if len(route) == 3 and route[0] == "networks" and route[2] == "export":
        return one_thing(networks_csv, load_vars(), route[1])
    if len(route) in (3, 4) and route[:2] == ["ipam", "options"]:
        return one_thing(options_overview, load_vars(), "" if route[2] == "-" else route[2],
                         route[3] if len(route) == 4 else "")
    if route == ["ipam", "scan"]:
        return scan_overview(load_vars(), user)
    if len(route) == 6 and route[:2] == ["directory", "tree"]:
        return read_tree(route[2:])
    if route == ["vault", "slots"]:
        v = load_vars()
        return {"slots": list_slots(v), "host": v.get("hostname", "")}
    raise RouteNotFound()
