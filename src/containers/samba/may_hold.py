from ou_paths import exists, ou_dn, place_ok
import paths

KINDS = ("person", "machine", "group")
# where each kind may be put, by a move (1.8.8.5) or Create in... (2.1.6.101): any OU (2.1.6.106), but the closed ones
# and OU=service-accounts, whose accounts are by definition not people and which Keycloak cannot see. The one place
# this rule lives: the console's choices come from kinds_held, so they follow.


def _refused(samdb, kind, target, path):
    """Purpose: why a kind may not be put in an OU, by fabric's rule alone (the OU's existence is the caller's).
    Inputs:  samdb — SamDB; kind — one of KINDS; target — the OU's DN; path — its path, for the message.
    Returns: str, the reason, or "" when it may.
    Fails:   never.
    Feeds:   may_hold, kinds_held."""
    if not place_ok(samdb, target):
        return f"{path} is one of fabric's closed folders (or AD's Domain Controllers): nothing is put in it " \
               "(manual 1.8.8.5)"
    if target.lower() == str(samdb.domain_dn()).lower():
        return f"the domain's root is not an OU: choose an OU for this {kind} (manual 1.8.8.5)"
    services = paths.folder_dn(samdb, "service-accounts").lower()
    if target.lower() == services or target.lower().endswith("," + services):
        return f"{path} holds service accounts only: a {kind} is not put in it (manual 1.8.8.5)"
    return ""


def may_hold(samdb, kind, path):
    """Purpose: the OU a person, machine or group may be put in, by a move or Create in... (manual 1.8.8.5; 2.1.6.101,
             2.1.6.106): any OU that exists, not one of fabric's closed folders nor AD's Domain Controllers
             (ou_paths.place_ok), not OU=service-accounts nor below it, and not the domain's root itself.
    Inputs:  samdb — SamDB; kind — "person", "machine" or "group"; path — the OU's path ("people/staff",
             "branch/sales").
    Returns: str, the OU's DN.
    Fails:   ValueError, saying why: an unknown kind, a bad path, a closed folder, OU=service-accounts, no such OU.
    Feeds:   move_object, create_person, create_group, create_machine."""
    if kind not in KINDS:
        raise ValueError(f"kind: one of {', '.join(KINDS)}, not {kind!r}")
    target = ou_dn(samdb, path)
    why = _refused(samdb, kind, target, path)
    if why:
        raise ValueError(why)
    if not exists(samdb, target):
        raise ValueError(f"no OU {path}")
    return target


def kinds_held(samdb, dn, path):
    """Purpose: which kinds an existing OU may be given, by the same rule as may_hold: what the console offers in
             Move to... and Create in... (1.8.8.4, 1.8.8.5).
    Inputs:  samdb — SamDB; dn — the OU's DN; path — its path.
    Returns: list of str, among KINDS.
    Fails:   never.
    Feeds:   list_ous."""
    return [k for k in KINDS if not _refused(samdb, k, dn, path)]
