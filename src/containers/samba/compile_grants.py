from access_policy import access_policy
from ensure_computed_group import computed_groups, ensure_computed_group
from ensure_gpo import ensure_gpo
from ensure_grant_sudo import ensure_grant_sudo
from find_gpo import find_gpo
from grant_members import excluded, find_group, reach
from grant_names import (FALLBACK_GPO, GROUP_MARK, SECURITY_EXTENSIONS, SECURITY_TEMPLATE, gpo_rights, set_gpo,
                         set_group, where_group, who_group)
from grant_store import read_grants, read_state, write_state
from order_gpo_links import order_gpo_links
import paths
from remove_gpo import remove_gpo
from set_gpo_filter import set_gpo_filter


def _sets(grants, reached):
    """Purpose: the machines grouped by the set of grants that reach them with a right their GPO carries (1.6.13.4):
             each machine one set, keyed by its allowing and its restricting grants; a machine no allowing grant
             reaches is in none (the fallback denies it, 2.1.6.87).
    Inputs:  grants — read_grants' list; reached — {grant name: reach()'s result}.
    Returns: {(allow names tuple, restrict names tuple): sorted list of computer DNs}.
    Fails:   never.
    Feeds:   compile_grants."""
    by_machine = {}
    for g in grants:
        if not gpo_rights(g):
            continue
        for dn in reached[g["name"]]["where_computers"]:
            entry = by_machine.setdefault(dn, (set(), set()))
            entry[0 if g["kind"] == "allow" else 1].add(g["name"])
    out = {}
    for dn, (allow, restrict) in by_machine.items():
        if allow:
            out.setdefault((tuple(sorted(allow)), tuple(sorted(restrict))), []).append(dn)
    return {k: sorted(v) for k, v in out.items()}


def _set_rights(samdb, n, allow, restrict, grants, reached, sids, keep):
    """Purpose: who holds each right on one set's machines: for a right no restricting grant there narrows, the allowing
             grants' computed who groups; for one that one narrows, the set's own computed group
             (`access-<n>-<right>`): the allowing grants' people who are also in every such restricting grant's who
             (2.1.6.77). The restricted groups are made here.
    Inputs:  samdb — SamDB; n — int; allow, restrict — grant names; grants — {name: grant}; reached — {name:
             reach()}; sids — {computed group name: SID}, filled; keep — set of computed group names to keep, filled.
    Returns: ({right: [SID]}, list of str, what changed).
    Fails:   ldb.LdbError from AD.
    Feeds:   compile_grants."""
    out, done = {}, []
    for right in ("keyboard", "remote", "local-admin"):
        holders = [a for a in allow if right in gpo_rights(grants[a])]
        narrowing = [r for r in restrict if right in gpo_rights(grants[r])]
        if not narrowing:
            out[right] = [sids[who_group(a)] for a in holders]
            continue
        people = set()
        for a in holders:
            people |= set(reached[a]["who"])
        for r in narrowing:
            people &= set(reached[r]["who"])
        name = set_group(n, right)
        done += ensure_computed_group(samdb, name, sorted(people),
                                      description=f"{GROUP_MARK}: who keeps {right} on access-{n}")
        keep.add(name)
        sids[name] = find_group(samdb, name)[1]
        out[right] = [sids[name]]
    return out, done


def compile_grants(samdb, lp, dc):
    """Purpose: the grants made into what AD, sssd and Windows enforce (manual 1.6.13.4), every part changed only where
             it differs: each grant's computed groups (`grant-<name>-who`, a POSIX group for sudo, and
             `grant-<name>-where`); the machines grouped into sets by the grants that reach them, each set's computers
             in `access-<n>` (computers only: anything else taken out) and its one GPO `fabric: access <n>` at
             OU=machines, filtered to that group, giving each right to its holders (restricted where a restricting grant
             says) and putting the local administrators' groups in each machine's Administrators; a set no longer
             wanted removed with its GPO and groups; the fallback `fabric: access none` (2.1.6.87), every machine's,
             kept first in OU=machines' links; one sudo rule per grant with sudo (ensure_grant_sudo). A set keeps its
             number while its grants stay the same; a new one takes the next number never used. Run at the root's
             writable DC only: the GPOs are the root's, and the other DCs copy their folders (pull_sysvol).
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; dc — the DC compiling (dc-NNNN: the who groups' gids come
             from its built-in range).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError, OSError (SYSVOL), NTSTATUSError (its ACLs); ValueError from alloc_id when the range is full.
    Feeds:   grants_tool (add, set, remove, compile), converge (at the root)."""
    done = []
    grants = read_grants(samdb)
    by_name = {g["name"]: g for g in grants}
    out = excluded(samdb)
    cache, reached, sids, keep = {}, {}, {}, set()
    for g in grants:
        reached[g["name"]] = r = reach(samdb, g, out, cache)
        who, where = who_group(g["name"]), where_group(g["name"])
        done += ensure_computed_group(samdb, who, list(r["who"]), dc=dc,
                                      description=f"{GROUP_MARK}: grant {g['name']}'s people")
        done += ensure_computed_group(samdb, where, list(r["where_people"]) + list(r["where_computers"]),
                                      description=f"{GROUP_MARK}: what grant {g['name']} reaches")
        keep |= {who, where}
        sids[who] = find_group(samdb, who)[1]
    state = read_state(samdb)
    numbers = {(tuple(s["allow"]), tuple(s["restrict"])): int(n) for n, s in state["sets"].items()}
    machines = paths.folder_dn(samdb, "machines")
    wanted = {}
    for key, computers in sorted(_sets(grants, reached).items()):
        n = numbers.get(key)
        if n is None:
            n, state["next"] = state["next"], state["next"] + 1
        wanted[str(n)] = {"allow": list(key[0]), "restrict": list(key[1])}
        group = set_group(n)
        done += ensure_computed_group(samdb, group, computers,
                                      description=f"{GROUP_MARK}: the machines of set {n} (computers only)")
        keep.add(group)
        rights, changed = _set_rights(samdb, n, key[0], key[1], by_name, reached, sids, keep)
        done += changed
        policy = access_policy(rights["keyboard"], rights["remote"], rights["local-admin"])
        done += ensure_gpo(samdb, lp, set_gpo(n), machines, SECURITY_EXTENSIONS, {SECURITY_TEMPLATE: policy})
        done += set_gpo_filter(samdb, lp, set_gpo(n), find_group(samdb, group)[1])
    state["sets"] = wanted
    for n in range(1, state["next"]):      # every set no longer wanted (one an interrupted compile left too)
        if str(n) not in wanted and find_gpo(samdb, set_gpo(n)) is not None:
            done += remove_gpo(samdb, lp, set_gpo(n))
    for name, dn in sorted(computed_groups(samdb).items()):
        if name not in keep:
            samdb.delete(dn)
            done.append(f"group {name} removed (no grant or set uses it)")
    done += ensure_gpo(samdb, lp, FALLBACK_GPO, machines, SECURITY_EXTENSIONS,
                       {SECURITY_TEMPLATE: access_policy([], [], [])})
    done += set_gpo_filter(samdb, lp, FALLBACK_GPO, None)
    done += order_gpo_links(samdb, machines, FALLBACK_GPO)
    done += ensure_grant_sudo(samdb, grants)
    if write_state(samdb, state):
        done.append("the sets of machines recorded")
    return done
