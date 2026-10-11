import os
import shutil

from fabriclib.dhcp.client_networks import client_networks
from fabriclib.common.ensure_dir import ensure_dir
from fabriclib.common.service_user import service_user
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns_filter.check_filter_settings import check_filter_settings
from fabriclib.dns_filter.common.adguard_paths import adguard_paths
from fabriclib.dns_filter.common.filter_zones import filter_zones
from fabriclib.dns_filter.common.resolver_paths import resolver_paths
from fabriclib.dns_filter.common.resolver_rndc import resolver_rndc
from fabriclib.dns_filter.common.safe_search import ZONES as SAFE_ZONES, safe_search_records
from fabriclib.dns_filter.resolver_views import resolver_views
from fabriclib.pki.common.ca_files import ca_files

CONFIG = ("named.conf", "fabric.rpz", "owner.rpz", "rndc.key")


def deploy_resolver(v, secrets, links, jinja_env):
    """Purpose: the BIND resolver's deploy step (manual 1.12.2.10, 1.12.3.2, 1.12.3.6): its folders, its configuration
             (the main view and each client group's view, each forwarding to AdGuard Home on its own: everyone over
             plain DNS, a group over DNS-over-TLS naming it; DoT and DoH for clients once the DNS name's certificate is
             in <base>/resolver/tls, 1.12.2.16), its rules zones (fabric's zones never filtered, the owner's allows
             and blocks, each group's, safe search), its control key, fabric's root CA (to check AdGuard's
             certificate); a running resolver reloads what changed. The lists are AdGuard's (1.12.3.5): the converted
             zones a 0.8.0 candidate kept in <base>/resolver/lists go.
    Inputs:  v — rendered vars: deploy_base_dir, service_users.resolver, ip_bind9, ip_adguard, domain, lan_cidr,
             fabric_subnet, security.firewall_allow, DHCP's subnets (client_networks: full and guest, 2.1.10.4),
             dns_filter_allow, dns_filter_block, dns_filter_safe_search, dns_filter_youtube, dns_filter_groups and
             what filter_zones reads; secrets — resolver_rndc_secret; links — dns_links' result (the linked sites'
             zones); jinja_env — fabric's template environment.
    Returns: {"config": bool (a configuration file changed), "reconfigured": bool (the running resolver took it)}.
    Fails:   ValidationError from check_filter_settings; KeyError for a missing secret or var; OSError writing the
             files; jinja2 errors.
    Feeds:   deploy/deploy_optional_parts (when install_resolver), dns_filter/apply_dns_filter (a console change);
             tests/resolver/run.py, tests/resolver/groups.py."""
    v = dict(v)
    check_filter_settings(v)
    paths = resolver_paths(v)
    uid, gid = service_user(v, "resolver")
    ensure_dir(paths["root"], 0o750, 0, gid)
    ensure_dir(paths["config"], 0o750, 0, gid)
    ensure_dir(paths["log"], 0o750, uid, gid)
    ensure_dir(paths["cache"], 0o750, uid, gid)
    ensure_dir(paths["tls"], 0o750, uid, gid)          # as install_cert leaves it (mint_service_certs)
    if os.path.isdir(paths["lists"]):                  # a 0.8.0 candidate's converted lists (1.12.3.11)
        shutil.rmtree(paths["lists"])
    # DoT and DoH for clients once the DNS name's certificate is there (a first deploy runs before the certificates)
    client_tls = all(os.path.exists(os.path.join(paths["tls"], f)) for f in ("fullchain.pem", "privkey.pem"))
    # the groups reach AdGuard over DoT once its certificate for *.filter.<domain> is there (1.12.3.6)
    ag_tls = adguard_paths(v)["tls"]
    root_ca = ca_files(v)[0]
    adguard_tls = os.path.exists(root_ca) and all(os.path.exists(os.path.join(ag_tls, f))
                                                  for f in ("fullchain.pem", "privkey.pem"))
    views = resolver_views(v)
    security = v.get("security") or {}
    ctx = {**v, "resolver_rndc_secret": secrets["resolver_rndc_secret"], "zones": filter_zones(v, links),
           "safe_zone": views["safe_zone"], "groups": views["groups"], "client_tls": client_tls,
           "adguard_tls": adguard_tls,
           "clients": list(dict.fromkeys([v["lan_cidr"], v["fabric_subnet"],
                                          *(security.get("firewall_allow") or []),
                                          *client_networks(v)["full"], *client_networks(v)["guest"]]))}
    files = {name: jinja_env.get_template(f"resolver/config/{name}.j2").render(**ctx) for name in CONFIG}
    if adguard_tls:
        with open(root_ca) as f:
            files["fabric-root-ca.crt"] = f.read()
    rpz = jinja_env.get_template("resolver/config/rules.rpz.j2")
    for level, zone in SAFE_ZONES.items():
        files[zone] = jinja_env.get_template("resolver/config/safesearch.rpz.j2").render(
            zone=zone, level=level, records=safe_search_records(level))
    for g in v["dns_filter_groups"]:
        files[f"group-{g['name']}.rpz"] = rpz.render(zone=f"group-{g['name']}.rpz", what=f"group {g['name']}",
                                                     allow=g["allow"], block=g["block"])
    changed = False
    for name, text in files.items():
        changed |= write_file_if_changed(os.path.join(paths["config"], name), text, 0o640, 0, gid)
    for f in os.listdir(paths["config"]):           # a removed group's rules zone
        if f.startswith("group-") and f.endswith(".rpz") and f not in files:
            os.remove(os.path.join(paths["config"], f))
            changed = True
    reconfigured = False
    if changed:
        # reload, not reconfig: it rereads the configuration and every zone whose file changed (the rules zones)
        r = resolver_rndc(["reload"], timeout=120)
        reconfigured = bool(r and r.returncode == 0)
    return {"config": changed, "reconfigured": reconfigured}
