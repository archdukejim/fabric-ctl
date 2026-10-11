"""Converge fabric's Samba AD domain to what fabric wants (manual 1.6.5.15, S1.3), inside the DC, as root, on its own
database: no credentials, no network. Run after every start and apply by fabriclib/samba/converge_domain:
    docker exec -i samba python3 /fabric/converge.py < state.json
The wanted state comes on stdin as JSON: {"site", "root" (bool), "password_policy" {…}, "networks" [site_networks
items], "root_ca_pem", "id_range", "groups" [{name, gidNumber, description}], "admin_group", "accounts" {name:
password}, "radius_gid", "lan_profile", optional "parent", "rodc", "join_account", "moving", "sso_spns" and
"logon_policies"} (stdin,
never a command line: it holds the service accounts' passwords). Prints one JSON object: {"changed": [what changed,
…]}. Exits 1 with the error on stderr."""
import json
import sys

from admin_gpo import ensure_gpo_admins
from ensure_ad_site import ensure_ad_site
from ensure_gpo import ensure_gpo
from ensure_groups import ensure_groups
from ensure_join_account import ensure_join_account
from ensure_layout import ensure_layout
from ensure_logon_policies import ensure_logon_policies
from ensure_networks import ensure_networks
from ensure_schema import ensure_schema
from ensure_service_accounts import ensure_service_accounts
from ensure_site_acl import ensure_site_acl
from ensure_site_info import ensure_site_info
from ensure_site_link import ensure_site_link
from ensure_sso_account import ensure_sso_account
from ensure_sudo_rule import ensure_sudo_rule
from open_samdb import open_samdb
from remove_ipv6_records import remove_ipv6_records
from root_ca_policy import EXTENSIONS as TRUST_EXTENSIONS, root_ca_policy
from set_password_policy import set_password_policy
from share_winbind import share_winbind
from windows_baseline_policy import windows_baseline_policy
import paths

CONF = "/data/etc/smb.conf"


def converge(state):
    """Purpose: every part of the domain fabric owns, in order: the schema, the layout, the site's id block, the
             groups, the site's service accounts, the AD zones on IPv4 only (2.1.6.29), its access entries, its networks
             (the address plan), its default
             sudo rule, the AD site and its subnets, the password policy, the domain's trust GPO (fabric's root CA),
             the site's log-on GPOs (one per OU, 1.6.11.4), its Windows baseline GPO and winbind's privileged pipe
             for FreeRADIUS. Each part changes only what differs, so a second run changes nothing.
    Inputs:  state — dict: site (str), root (bool: the root site, which also holds the organisation's items and the
             domain-wide trust GPO), password_policy (dict, every key), networks (site_networks' list), root_ca_pem
             (str), id_range ("first-last"), groups (fabric's ldap_groups), admin_group (the web UI's admin group, in
             the log-on policy), accounts ({sAMAccountName: password}: the site's service accounts), radius_gid (int:
             FreeRADIUS's group, given winbind's privileged pipe), parent (str, optional: a site's parent site,
             for the AD site link), rodc (bool, optional: a read-only DC, where
             only winbind's pipe is converged), join_account ({name, password}, optional: at the root, the
             temporary account a new site's DC joins with), moving (bool, optional: at a new parent, a site with its
             own DC moving here: its OU and links only, never its GPOs, which its own DC owns), lan_profile (str:
             the Windows wired 802.1X profile the baseline installs, "" without one), sso_spns (list, optional: the
             HTTP SPNs of the site's Kerberos sign-in account; none, no account), sso_host (str, optional: Keycloak's
             name, which the Windows baseline lets browsers use Kerberos for; "" or none, no allowlist), logon_policies
             (optional: {ou path: {console, remote}}, who may sign in per OU; none, the site's log-on GPO as before
             0.9).
    Returns: list of str, what changed.
    Fails:   KeyError for a missing state key; whatever a part raises (ldb.LdbError, OSError, CalledProcessError).
    Feeds:   this script's main."""
    site, root = state["site"], bool(state["root"])
    if state.get("rodc"):                 # a read-only DC holds the domain's copy: only what is local to it
        _, lp = open_samdb(CONF)
        return share_winbind(lp, int(state["radius_gid"]))
    changed = [f"schema: {name} added" for name in ensure_schema(CONF)]
    samdb, lp = open_samdb(CONF)
    changed += ensure_layout(samdb, site, root, state.get("parent") or "")
    changed += ensure_site_info(samdb, site, state["id_range"])
    changed += ensure_groups(samdb, site, root, state["groups"])
    changed += ensure_service_accounts(samdb, lp, site, state["accounts"])
    changed += ensure_sso_account(samdb, lp, CONF, site, state.get("sso_spns") or [])
    changed += remove_ipv6_records(samdb)            # IPv4 only (2.1.6.29)
    changed += ensure_site_acl(samdb, site, root)
    changed += ensure_networks(samdb, site, state["networks"])
    changed += ensure_sudo_rule(samdb, site, state["admin_group"], root)
    changed += ensure_ad_site(samdb, site, [n["cidr"] for n in state["networks"]])
    if state.get("parent"):               # a site: its AD site linked to its parent's (manual 1.9.8.5)
        changed += ensure_site_link(samdb, site, state["parent"])
    base, site_dn = str(samdb.domain_dn()), paths.site_dn(samdb, site)
    if root:                              # the domain's own settings are the root's (manual 1.9.8.3)
        changed += [f"password policy: {a}" for a in set_password_policy(samdb, state["password_policy"])]
        changed += ensure_gpo(samdb, lp, "fabric: trust in fabric's root CA", base, TRUST_EXTENSIONS,
                              {"Machine/Registry.pol": root_ca_policy(state["root_ca_pem"])})
    if state.get("moving"):               # a site with its own DC moving here: its GPOs are its own to rewrite
        changed += share_winbind(lp, int(state["radius_gid"]))
        return changed
    changed += ensure_logon_policies(samdb, lp, site, state.get("logon_policies"), state["admin_group"])
    changed += ensure_gpo_admins(samdb, lp, site)
    extensions, files = windows_baseline_policy(state.get("lan_profile") or "", state.get("sso_host") or "")
    changed += ensure_gpo(samdb, lp, f"fabric: {site} Windows baseline", site_dn, extensions,
                          files)
    if state.get("join_account"):         # at the root, preparing a new site's DC join (manual 1.9.8.4)
        changed += ensure_join_account(samdb, state["join_account"]["name"], state["join_account"]["password"])
    changed += share_winbind(lp, int(state["radius_gid"]))
    return changed


if __name__ == "__main__":
    try:
        result = converge(json.load(sys.stdin))
    except Exception as e:                  # the caller reports it; the DC keeps running
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"changed": result}))
