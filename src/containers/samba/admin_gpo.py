"""The site's admin GPOs (manual 1.6.5.20, S5.4; 1.9.8.14): the policies an admin sets with `fabricctl gpo` and the
web UI's editor, kept apart from fabric's own GPOs, which convergence rewrites. Both are linked at the domain's root
(2.1.6.106; at OU=machines before 0.9.2, 2.1.6.84), denied to the DCs and the fabric hosts: `fabric: <site> admin
settings` as any GPO, `fabric: <site> controls` enforced, so a GPO an admin links in any OU cannot override it."""
import os

import ldb
from samba.dcerpc import preg
from samba.ndr import ndr_pack, ndr_unpack

from acl_entries import ensure_aces, sid_of
from ensure_gpo import ensure_gpo
from find_gpo import find_gpo
from member_gpo_filter import member_gpo_filter
import paths
from set_gpo_acl import set_gpo_acl
from unlink_gpo import unlink_gpo
from group_names import DIRECTORY_ADMINS

REGISTRY_MACHINE = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957D-509E-11D1-A7CC-0000F87571E3}]"
REGISTRY_USER = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{0F6B957E-509E-11D1-A7CC-0000F87571E3}]"


def _name(site, control=False):
    """Purpose: the display name of one of the site's admin GPOs.
    Inputs:  site — str; control — bool, the enforced one.
    Returns: str "fabric: <site> admin settings" or "fabric: <site> controls".
    Fails:   never.
    Feeds:   admin_settings, save_admin_settings."""
    return f"fabric: {site} controls" if control else f"fabric: {site} admin settings"


def admin_settings(samdb, lp, site, control=False):
    """Purpose: what one of the site's admin GPOs sets today.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; site — str; control — bool, the enforced one.
    Returns: {"machine": [[key, value name, type, data]], "user": [...]}; both empty before anything was set.
    Fails:   ldb.LdbError; OSError reading SYSVOL.
    Feeds:   gpo_tool (ops "show", "set", "clear")."""
    out = {"machine": [], "user": []}
    found = samdb.search(base=f"CN=Policies,CN=System,{samdb.domain_dn()}", scope=ldb.SCOPE_ONELEVEL,
                         expression=f"(displayName={ldb.binary_encode(_name(site, control))})", attrs=["cn"])
    if not found:
        return out
    folder = os.path.join(lp.get("path", "sysvol"), lp.get("realm").lower(), "Policies", str(found[0]["cn"]))
    for scope, sub in (("machine", "Machine"), ("user", "User")):
        path = os.path.join(folder, sub, "Registry.pol")
        if os.path.exists(path):
            pol = ndr_unpack(preg.file, open(path, "rb").read())
            out[scope] = [[e.keyname, e.valuename, e.type, e.data] for e in pol.entries]
    return out


def _pack(entries):
    """Purpose: a Registry.pol file of these entries (Samba's PReg encoding).
    Inputs:  entries — list of [key, name, type, data].
    Returns: bytes.
    Fails:   TypeError for data of the wrong type for its value type.
    Feeds:   save_admin_settings."""
    f = preg.file()
    f.header.signature, f.header.version = "PReg", 1
    items = []
    for key, name, kind, data in entries:
        e = preg.entry()
        e.keyname, e.valuename, e.type, e.data = key, name, kind, data
        items.append(e)
    f.num_entries = len(items)          # before the entries: NDR sizes the array by it
    f.entries = items
    return ndr_pack(f)


def save_admin_settings(samdb, lp, site, settings, control=False):
    """Purpose: write one of the site's admin GPOs (created and linked at the domain's root when missing, denied to the
             DCs and the fabric hosts, 2.1.6.106; the controls enforced), its version bumped.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; site — str; settings — admin_settings' shape; control —
             bool, the enforced one.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError; OSError; CalledProcessError (ensure_gpo).
    Feeds:   gpo_tool (ops "set", "clear")."""
    done = ensure_gpo(samdb, lp, _name(site, control), str(samdb.domain_dn()),
                      REGISTRY_MACHINE if settings["machine"] else "",
                      {"Machine/Registry.pol": _pack(settings["machine"]),
                       "User/Registry.pol": _pack(settings["user"])},
                      user_extensions=REGISTRY_USER if settings["user"] else "", enforced=control)
    done += member_gpo_filter(samdb, lp, _name(site, control))
    return done + ensure_gpo_admins(samdb, lp, site)


def admin_gpos_at_root(samdb, lp, site):
    """Purpose: the site's admin GPOs that exist, linked at the domain's root as save_admin_settings links them, and
             their old link at OU=machines (an install from before 0.9.2) taken out (2.1.6.106). What they hold is
             not touched.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; site — str.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError; OSError; NTSTATUSError from set_gpo_acl.
    Feeds:   converge."""
    done = []
    for control in (False, True):
        name = _name(site, control)
        found = find_gpo(samdb, name)
        if found is None:
            continue
        now = samdb.search(base=found[0], scope=ldb.SCOPE_BASE,
                           attrs=["gPCMachineExtensionNames", "gPCUserExtensionNames"])[0]
        done += ensure_gpo(samdb, lp, name, str(samdb.domain_dn()), str(now.get("gPCMachineExtensionNames", [""])[0]),
                           {}, user_extensions=str(now.get("gPCUserExtensionNames", [""])[0]), enforced=control)
        done += member_gpo_filter(samdb, lp, name)
        done += unlink_gpo(samdb, paths.folder_dn(samdb, "machines"), name)
    return done


def ensure_gpo_admins(samdb, lp, site):
    """Purpose: the Directory Administrators (`directory-admins`, 2.1.6.76) edit the site's two admin GPOs with
             Windows' own tools too: full control of each GPO object (never its permissions), and so of its SYSVOL
             folder (its file ACLs follow the object's).
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; site — str.
    Returns: list of str, the access entries added (none for a GPO not made yet).
    Fails:   ldb.LdbError; NTSTATUSError from set_gpo_acl.
    Feeds:   save_admin_settings, converge."""
    sid = sid_of(samdb, DIRECTORY_ADMINS)
    done = []
    for control in (False, True):
        found = samdb.search(base=f"CN=Policies,CN=System,{samdb.domain_dn()}", scope=ldb.SCOPE_ONELEVEL,
                             expression=f"(displayName={ldb.binary_encode(_name(site, control))})", attrs=["cn"])
        if not found:
            continue
        added = ensure_aces(samdb, [(str(found[0].dn), f"(A;CI;RPWPCRCCDCLCLORCSDDTSW;;;{sid})")])
        if added:
            set_gpo_acl(samdb, lp, str(found[0]["cn"][0]))
        done += added
    return done
