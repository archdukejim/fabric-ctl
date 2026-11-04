from all_machines import all_machines
from directory_scope import find_groups, find_people


def directory_size(samdb, lp, site):
    """Purpose: how much the directory holds, for the sizing advice (manual 1.8.8.8): counted on the timer, never on a
             page's request.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused).
    Returns: {"people", "computers", "groups"}: ints.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "directory_size")."""
    return {"people": len(find_people(samdb)), "computers": len(all_machines(samdb)), "groups": len(find_groups(samdb))}
