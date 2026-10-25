from check_grant import check_grant
from grant_names import SHIPPED
from grant_store import read_grant, read_state, write_grant, write_state


def ship_grants(samdb):
    """Purpose: the grants a fresh install ships (manual 1.6.13.5): the server, desktop and network administrators'
             and every person's at the desktops, made once, at the root's first convergence with the store; a shipped
             grant an admin later removed or changed stays as they left it.
    Inputs:  samdb — SamDB (as the system; the store and the groups exist: ensure_layout, ensure_groups).
    Returns: list of str, what was made.
    Fails:   ldb.LdbError from AD; ValueError from check_grant (a shipped grant's group missing).
    Feeds:   converge (at the root)."""
    state = read_state(samdb)
    if state["shipped"]:
        return []
    done = []
    for grant in SHIPPED:
        if read_grant(samdb, grant["name"]) is None:
            write_grant(samdb, check_grant(samdb, grant))
            done.append(f"grant {grant['name']} made (shipped)")
    state["shipped"] = True
    write_state(samdb, state)
    return done
