"""Converge fabric's Samba AD domain to what fabric wants (manual 1.6.5.15, S1.3; 1.6.13.2), inside the DC, as root,
on its own database: no credentials, no network. Run after every start and apply by fabriclib/samba/converge_domain,
and by a parent preparing a joining site's DC (fabriclib/samba/prepare_site):
    docker exec -i samba python3 /fabric/converge.py < state.json
The wanted state comes on stdin as JSON: {"site", "dc", "dc_type", "root" (bool), "password_policy" {…}, "networks"
[site_networks items], "root_ca_pem", "groups" [{name, gidNumber, description}], "accounts" {name: password},
"radius_gid", "lan_profile", optional "tier_policies" {enterprise_admin, directory_admins}, "parent", "rodc",
"join_account", "moving", "sso_spns" and "sso_host"} (stdin,
never a command line: it holds the service accounts' passwords). Prints one JSON object: {"changed": [what changed,
…]}. Exits 1 with the error on stderr."""
import json
import sys

from admin_gpo import ensure_gpo_admins
from compile_grants import compile_grants
from ensure_ad_site import ensure_ad_site
from ensure_dc_record import ensure_dc_record
from ensure_domain_options import ensure_domain_options
from ensure_directory_acl import ensure_directory_acl
from ensure_gpo import ensure_gpo
from ensure_groups import ensure_groups
from ensure_join_account import ensure_join_account
from ensure_layout import ensure_layout
from ensure_networks import ensure_networks
from ensure_schema import ensure_schema
from ensure_service_accounts import ensure_service_accounts
from ensure_site_record import ensure_site_record
from ensure_site_link import ensure_site_link
from ensure_sso_account import ensure_sso_account
from id_layout import dc_range
from open_samdb import open_samdb
from plan_cidrs import plan_cidrs
from refresh_sudo_hosts import refresh_sudo_hosts
from remove_ipv6_records import remove_ipv6_records
from repair_role_owners import repair_role_owners
from root_ca_policy import EXTENSIONS as TRUST_EXTENSIONS, root_ca_policy
from ensure_tier_policies import ensure_tier_policies
from set_password_policy import set_password_policy
from share_winbind import share_winbind
from ship_grants import ship_grants
from windows_baseline_policy import windows_baseline_policy
import paths

CONF = "/data/etc/smb.conf"


def converge(state):
    """Purpose: every part of the domain fabric owns, in order: the roles this DC holds named by its current DN (again
             after the AD site, which may move it), the schema, the directory's folders (one set for the domain,
             1.6.13.2), the DC's record with its id range (2.1.6.79), the site's record (1.10.4.32), the groups
             (1.6.13.3), the DC's service accounts (2.1.6.82), the site's Kerberos sign-in account, the AD zones on
             IPv4 only (2.1.6.29), the directory's access entries (2.1.6.76), the site's networks (never the address
             manager's subnets, 1.10.4.33), the host names of fabric's sudo rules on host groups (1.6.11.7), the AD
             site and its subnets (the plan's too) and link, the password policy, the domain's DHCP options entry
             (1.10.4.32) and the domain's trust GPO (fabric's root CA) at the root, the Directory Administrators'
             rights on the site's admin GPOs, the site's Windows baseline GPO (linked at OU=machines, 2.1.6.84), at the root the grants (the shipped
             ones once, then compiled: 1.6.13.4, 1.6.13.5) and winbind's privileged pipe for
             FreeRADIUS. Each part changes only what differs, so a second run changes nothing.
    Inputs:  state — dict: site (str); dc (str: the DC converged or prepared, dc-NNNN: its record, its range and its
             service accounts); dc_type ("writable" or "rodc": the DC prepared; a read-only one gets its cache group,
             2.1.6.85); root (bool: the root site, which also holds the domain's own settings and the domain-wide
             groups and trust GPO); password_policy (dict, every key); tier_policies (optional, the tiers' own,
             written at the root); networks (site_networks' list); root_ca_pem (str); groups (fabric's ldap_groups);
             accounts ({sAMAccountName: password}: the DC's service accounts);
             radius_gid (int: FreeRADIUS's group, given winbind's privileged pipe); parent (str, optional: a site's
             parent site, for the AD site link); rodc (bool, optional: converging on a read-only DC, where only
             winbind's pipe is converged); join_account ({name, password}, optional: at a parent, the temporary
             account a new site's DC joins with); moving (bool, optional: at a new parent, a site with its own DC
             moving here: its AD site link only, nothing else of it); lan_profile (str: the Windows wired 802.1X
             profile the baseline installs, "" without one); sso_spns (list, optional: the HTTP SPNs of the site's
             Kerberos sign-in account; none, no account); sso_host (str, optional: Keycloak's name, which the Windows
             baseline lets browsers use Kerberos for; "" or none, no allowlist); grants_fallback_open (bool,
             optional: the fallback GPO left out, 2.1.6.88).
    Returns: list of str, what changed.
    Fails:   KeyError for a missing state key; ValueError for a DC name that is not dc-NNNN (checked before anything is
             written); whatever a part raises (ldb.LdbError, OSError, CalledProcessError).
    Feeds:   this script's main."""
    site, root = state["site"], bool(state["root"])
    if state.get("rodc"):                 # a read-only DC holds the domain's copy: only what is local to it
        _, lp = open_samdb(CONF)
        return share_winbind(lp, int(state["radius_gid"]))
    if state.get("moving"):               # a site with its own DC moving here: its AD site's link to its new parent
        samdb, lp = open_samdb(CONF)
        return ensure_site_link(samdb, site, state["parent"])
    dc = state["dc"]
    dc_range(dc)                          # a name with no number has no range: refused before anything is written
    # before the schema: Samba checks its master by the owner's DN text. Samba keeps one schema per process, loaded by
    # the first database opened, with that one's "schema update allowed": so this one allows them, as ensure_schema's
    samdb, lp = open_samdb(CONF, schema_updates=True)
    changed = repair_role_owners(samdb)
    changed += [f"schema: {name} added" for name in ensure_schema(CONF)]
    samdb, lp = open_samdb(CONF)
    changed += ensure_layout(samdb)
    changed += ensure_dc_record(samdb, dc, site)
    changed += ensure_site_record(samdb, site)       # its number and its DHCP options (1.10.4.32)
    changed += ensure_groups(samdb, dc, site, root, state["groups"], rodc=state.get("dc_type") == "rodc")
    changed += ensure_service_accounts(samdb, lp, dc, state["accounts"])
    changed += ensure_sso_account(samdb, lp, CONF, site, state.get("sso_spns") or [])
    changed += remove_ipv6_records(samdb)            # IPv4 only (2.1.6.29)
    changed += ensure_directory_acl(samdb, dc)
    changed += ensure_networks(samdb, site, state["networks"])
    changed += refresh_sudo_hosts(samdb)             # fabric's sudo rules follow their host groups (1.6.11.7)
    cidrs = [n["cidr"] for n in state["networks"]]   # with the address plan's subnets (1.10.4.33)
    changed += ensure_ad_site(samdb, site, cidrs + [c for c in plan_cidrs(samdb, site) if c not in cidrs])
    changed += repair_role_owners(samdb)  # a renamed AD site moved the DC: its roles follow it
    if state.get("parent"):               # a site: its AD site linked to its parent's (manual 1.9.8.5)
        changed += ensure_site_link(samdb, site, state["parent"])
    base, machines = str(samdb.domain_dn()), paths.folder_dn(samdb, "machines")
    if root:                              # the domain's own settings are the root's (manual 1.9.8.3)
        changed += [f"password policy: {a}" for a in set_password_policy(samdb, state["password_policy"])]
        changed += ensure_domain_options(samdb)    # every site's DHCP options first (1.10.4.32)
        if state.get("tier_policies"):    # the tiers' own policies, beside the domain's (2.1.6.71)
            changed += ensure_tier_policies(samdb, state["tier_policies"])
        changed += ensure_gpo(samdb, lp, "fabric: trust in fabric's root CA", base, TRUST_EXTENSIONS,
                              {"Machine/Registry.pol": root_ca_policy(state["root_ca_pem"])})
    changed += ensure_gpo_admins(samdb, lp, site)
    extensions, files = windows_baseline_policy(state.get("lan_profile") or "", state.get("sso_host") or "")
    changed += ensure_gpo(samdb, lp, f"fabric: {site} Windows baseline", machines, extensions, files)
    if root:                              # the grants: the shipped ones once, then compiled (1.6.13.4, 1.6.13.5)
        changed += ship_grants(samdb)
        changed += compile_grants(samdb, lp, dc, bool(state.get("grants_fallback_open")))
    if state.get("join_account"):         # at a parent, preparing a new site's DC join (manual 1.9.8.4)
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
