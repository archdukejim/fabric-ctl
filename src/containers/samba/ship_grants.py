from check_grant import check_grant
from grant_names import SHIPPED, SHIPPED_NETWORKS
from grant_store import read_grant, read_state, write_grant, write_state


def ship_grants(samdb):
    """Purpose: the grants a fresh install ships (manual 1.6.13.5): the server, desktop and network administrators'
             and every person's at the desktops, made once, at the root's first convergence with the store; and the
             network administrators' address plan, `network-plan` (1.6.13.12), made once too, at the root's first
             convergence with 0.9.0 (a fresh install, or an 0.8.0 domain upgraded), with its own mark in the state. A
             shipped grant an admin later removed or changed stays as they left it.
    Inputs:  samdb — SamDB (as the system; the store and the groups exist: ensure_layout, ensure_groups).
    Returns: list of str, what was made.
    Fails:   ldb.LdbError from AD; ValueError from check_grant (a shipped grant's group missing).
    Feeds:   converge (at the root)."""
    state, done = read_state(samdb), []
    for mark, grants in (("shipped", SHIPPED), ("shipped_networks", SHIPPED_NETWORKS)):
        if state.get(mark):
            continue
        for grant in grants:
            if read_grant(samdb, grant["name"]) is None:
                write_grant(samdb, check_grant(samdb, grant))
                done.append(f"grant {grant['name']} made (shipped)")
        state[mark] = True
    write_state(samdb, state)             # nothing written when the marks were already there
    return done
