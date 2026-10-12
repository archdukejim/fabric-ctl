import hashlib
import os
import ssl

from fabriclib.federation.site_networks import site_networks
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.radius.windows_lan_profile import windows_lan_profile
from fabriclib.samba.check_logon_policies import check_logon_policies
from fabriclib.samba.id_range import id_range
from fabriclib.samba.sso_spns import sso_spns
from fabriclib.samba.run_converge import run_converge


def converge_domain(v, federation_file, secrets, container="samba"):
    """Purpose: bring the domain to what fabric wants (manual 1.6.5.15, S1.3): hand the wanted state to the converge
             code inside the running DC (src/containers/samba/converge.py) and return what it changed. Every part is
             idempotent, so it runs after every start and apply.
    Inputs:  v — rendered vars: site_name, ad_password_policy, deploy_base_dir (the root CA under
             stepca/data/certs), lan_cidr and the DHCP subnets (site_networks), ldap_groups, webui_admin_group,
             service_users (FreeRADIUS's gid), install_freeradius, radius_people and hostname_radius (the Windows
             baseline's 802.1X profile), the id block (id_range), what
             sso_spns reads (Keycloak's Kerberos sign-in account), logon_policies (who may sign in per OU, 1.6.11.4;
             null: the site's log-on rights as before 0.9);
             federation_file — the federation registry (whether this is the root site); secrets — fabric's secrets
             (the service accounts' passwords: ad_agent_password, ad_keycloak_password, ad_radius_password);
             container — the DC's container.
    Returns: list of str, what changed (empty when the domain already was as wanted).
    Fails:   ValidationError when the DC is not running or the converge code reports an error (its message), or
             for logon_policies check_logon_policies refuses;
             KeyError for a missing service-account secret;
             OSError reading the root CA; subprocess.TimeoutExpired after 10 minutes.
    Feeds:   setup/start_services (after the DC starts), deploy/restart_changed (every apply), tests/samba."""
    root_ca = os.path.join(v["deploy_base_dir"], "stepca", "data", "certs", "root_ca.crt")
    state = {"site": v["site_name"], "root": is_root_site(federation_file),
             "password_policy": v["ad_password_policy"],
             "networks": site_networks(v),
             "root_ca_pem": open(root_ca).read(), "id_range": id_range(v),
             "groups": [{"name": g["name"], "gidNumber": g["gidNumber"], "description": g.get("description", "")}
                        for g in v.get("ldap_groups") or []],
             "admin_group": v.get("webui_admin_group") or "admins",
             "accounts": {f"fabric-{kind}-{v['site_name']}": secrets[f"ad_{kind}_password"]
                          for kind in ("agent", "keycloak", "radius")},
             "radius_gid": v["service_users"]["freeradius"]["gid"], "lan_profile": _lan_profile(v, root_ca),
             "sso_spns": sso_spns(v), "logon_policies": check_logon_policies(v.get("logon_policies"))}
    state["sso_host"] = v["hostname_keycloak"] if state["sso_spns"] else ""
    state["rodc"] = not state["root"] and v.get("ad_dc_type") == "rodc"
    if not state["root"]:                 # the AD site link to the parent (manual 1.9.8.5)
        state["parent"] = (load_registry(federation_file).get("upstream") or {}).get("site_name") or ""
    return run_converge(state, container)


def _lan_profile(v, root_ca):
    """Purpose: the wired 802.1X profile the site's Windows baseline installs (manual 1.6.5.20): PEAP to this site's
             FreeRADIUS, checked against fabric's root CA.
    Inputs:  v — rendered vars (install_freeradius, radius_people, hostname_radius); root_ca — path of the root CA.
    Returns: str, the profile XML; "" while FreeRADIUS is off or no group is mapped (no password method on).
    Fails:   OSError reading the root CA; ValueError for a file that is not a PEM certificate.
    Feeds:   converge_domain."""
    if not v.get("install_freeradius") or not v.get("radius_people"):
        return ""
    sha1 = hashlib.sha1(ssl.PEM_cert_to_DER_cert(open(root_ca).read())).hexdigest()
    return windows_lan_profile("peap", v["hostname_radius"], " ".join(sha1[i:i + 2] for i in range(0, 40, 2)))

