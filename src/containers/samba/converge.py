"""Converge fabric's Samba AD domain to what fabric wants (manual 1.6.5.15, S1.3), inside the DC, as root, on its own
database: no credentials, no network. Run after every start and apply by fabriclib/samba/converge_domain:
    docker exec -i samba python3 /fabric/converge.py < state.json
The wanted state comes on stdin as JSON: {"site", "root" (bool), "password_policy" {…}, "networks" [site_networks
items], "root_ca_pem", "id_range", "groups" [{name, gidNumber, description}], "admin_group", "accounts" {name:
password}, "radius_gid", "lan_profile", optional "parent", "rodc", "join_account", "moving", "sso_spns",
"logon_policies" and "privileged_groups"} (stdin,
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
from narrow_site_admins import narrow_site_admins
from ensure_org_options import ensure_org_options
from ensure_schema import ensure_schema
from ensure_service_accounts import ensure_service_accounts
from ensure_site_acl import ensure_site_acl
from ensure_site_info import ensure_site_info
from ensure_site_link import ensure_site_link
from ensure_sso_account import ensure_sso_account
from ensure_sudo_rule import ensure_sudo_rule
from id_layout import check_block
from refresh_sudo_hosts import refresh_sudo_hosts
from open_samdb import open_samdb
from plan_cidrs import plan_cidrs
from protect_privileged_people import protect_privileged_people
from levels import misplaced
from remove_ipv6_records import remove_ipv6_records
from repair_role_owners import repair_role_owners
from root_ca_policy import EXTENSIONS as TRUST_EXTENSIONS, root_ca_policy
from set_password_policy import set_password_policy
from share_winbind import share_winbind
from windows_baseline_policy import windows_baseline_policy
import paths

CONF = "/data/etc/smb.conf"


def _misplaced_lines(samdb, site, privileged):
    """Purpose: a line per person of a site who holds a role beyond it (2.1.9.24, manual 1.6.3.18.8): reported at
             every convergence, never moved.
    Inputs:  samdb — SamDB; site — str; privileged — list of str, the fabric groups.
    Returns: list of str.
    Fails:   ldb.LdbError from a search.
    Feeds:   converge, _sites_below."""
    return [f"misplaced: {m['uid']} lives at {m['lives']} but holds a role at {', '.join(sorted(m['holds']))} "
            f"(2.1.9.24): move it from a site above (fabricctl people move {m['uid']} --site "
            f"{sorted(m['holds'])[0]}) or take the role away" for m in misplaced(samdb, site, privileged)]


def _sites_below(samdb, site, admin_group, privileged):
    """Purpose: 0.9's layered roles (2.1.9.21) at every site below this one too — its admins narrowed, its helpdesk
             rights and the denies that guard people who hold a role — so a site whose own DC is read-only, or not
             upgraded yet, gets them from above. A site that cannot take them is reported, never fatal here: its own
             convergence (or the next one above) applies them.
    Inputs:  samdb — SamDB (as the system); site — str, this site; admin_group — the organisation's admin group;
             privileged — list of str, the fabric groups (protect_privileged_people).
    Returns: list of str, what changed, and a line per site below that could not take them.
    Fails:   ldb.LdbError from finding the sites below.
    Feeds:   converge."""
    done = []
    for each in paths.below(samdb, site):
        try:
            done += narrow_site_admins(samdb, each, False, admin_group)
            done += ensure_site_acl(samdb, each, False)
            done += protect_privileged_people(samdb, each, privileged)
            done += _misplaced_lines(samdb, each, privileged)
        except Exception as e:          # one site below must not stop this site's convergence
            done.append(f"site {each}: layered roles not applied from here ({type(e).__name__}: {e}); "
                        "its own convergence applies them (2.1.9.21)")
    return done


def converge(state):
    """Purpose: every part of the domain fabric owns, in order: the roles this DC holds named by its current DN (again
             after the AD site, which may move it), the schema, the layout, the site's id block, the
             groups, the site's admins narrowed to its helpdesk (2.1.9.21: its own and every site's below it), the
             site's service accounts, the AD zones on IPv4 only (2.1.6.29), its access entries and the denies that keep
             its helpdesk from people who hold a role, its networks
             (the address plan), its default
             sudo rule and the host names of fabric's sudo rules on host groups (1.6.11.7), the AD site and its
             subnets (the plan's among them, 1.10.4.13), the password policy, the domain's trust GPO (fabric's root
             CA), the organisation's DHCP options entry with its editors' group (2.1.10.23), the site's log-on GPOs
             (one per OU, 1.6.11.4), its Windows baseline GPO and winbind's privileged pipe for FreeRADIUS. Each part
             changes only what differs, so a second run changes nothing.
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
             0.9), privileged_groups (optional: the organisation's fabric groups, whose members the site helpdesk may
             not touch; none, the admin group alone), join_only (bool, optional: a site's DC type change, 2.1.9.23:
             only join_account is made, nothing else converged).
    Returns: list of str, what changed.
    Fails:   KeyError for a missing state key; whatever a part raises (ldb.LdbError, OSError, CalledProcessError).
    Feeds:   this script's main."""
    if state.get("join_only"):            # a site re-joining under its own name (2.1.9.23): its join account alone
        samdb, _ = open_samdb(CONF)
        return ensure_join_account(samdb, state["join_account"]["name"], state["join_account"]["password"])
    site, root = state["site"], bool(state["root"])
    if state.get("rodc"):                 # a read-only DC holds the domain's copy: only what is local to it
        _, lp = open_samdb(CONF)
        return share_winbind(lp, int(state["radius_gid"]))
    check_block(state["id_range"])        # a block the ranges do not fit is refused before anything is written
    # before the schema: Samba checks its master by the owner's DN text. Samba keeps one schema per process, loaded by
    # the first database opened, with that one's "schema update allowed": so this one allows them, as ensure_schema's
    samdb, lp = open_samdb(CONF, schema_updates=True)
    changed = repair_role_owners(samdb)
    changed += [f"schema: {name} added" for name in ensure_schema(CONF)]
    samdb, lp = open_samdb(CONF)
    changed += ensure_layout(samdb, site, root, state.get("parent") or "")
    changed += ensure_site_info(samdb, site, state["id_range"])
    changed += ensure_groups(samdb, site, root, state["groups"])
    changed += narrow_site_admins(samdb, site, root, state["admin_group"])
    changed += ensure_service_accounts(samdb, lp, site, state["accounts"])
    changed += ensure_sso_account(samdb, lp, CONF, site, state.get("sso_spns") or [])
    changed += remove_ipv6_records(samdb)            # IPv4 only (2.1.6.29)
    privileged = state.get("privileged_groups") or [state["admin_group"]]
    changed += ensure_site_acl(samdb, site, root)
    changed += protect_privileged_people(samdb, site, privileged)
    changed += _misplaced_lines(samdb, site, privileged)
    changed += _sites_below(samdb, site, state["admin_group"], privileged)
    changed += ensure_networks(samdb, site, state["networks"])
    changed += ensure_sudo_rule(samdb, site, state["admin_group"], root)
    changed += refresh_sudo_hosts(samdb, site)          # fabric's sudo rules follow their host groups (1.6.11.7)
    cidrs = [n["cidr"] for n in state["networks"]]
    changed += ensure_ad_site(samdb, site, cidrs + [c for c in plan_cidrs(samdb, site) if c not in cidrs])
    changed += repair_role_owners(samdb)  # a renamed AD site moved the DC: its roles follow it
    if state.get("parent"):               # a site: its AD site linked to its parent's (manual 1.9.8.5)
        changed += ensure_site_link(samdb, site, state["parent"])
    base, site_dn = str(samdb.domain_dn()), paths.site_dn(samdb, site)
    if root:                              # the domain's own settings are the root's (manual 1.9.8.3)
        changed += [f"password policy: {a}" for a in set_password_policy(samdb, state["password_policy"])]
        changed += ensure_gpo(samdb, lp, "fabric: trust in fabric's root CA", base, TRUST_EXTENSIONS,
                              {"Machine/Registry.pol": root_ca_policy(state["root_ca_pem"])})
        changed += ensure_org_options(samdb)      # the organisation's DHCP options and who edits them (2.1.10.23)
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
