from grant_store import read_grants
from group_store import all_managers, group_guid
from host_groups import sudo_rules


def group_uses(samdb, name, dn):
    """Purpose: where a group is used in the directory (manual 1.6.12.5: a group in use is not deleted): the grants
             that name it (who or where), the sudo rules that name it (`sudoUser: %<name>`), the groups whose managers
             or "only from" name it.
    Inputs:  samdb — SamDB; name — the group's name; dn — its DN.
    Returns: {"grants": [names], "sudo": [rule names], "managers_of": [the GUIDs of the groups whose managers' record
             names it]}; each list empty when unused.
    Fails:   ldb.LdbError from a search.
    Feeds:   remove_group, group_scope."""
    low = name.lower()
    grants = [g["name"] for g in read_grants(samdb)
              if low in {x.lower() for x in g.get("who", []) + g.get("where", [])}]
    sudo = [str(r["cn"][0]) for r in sudo_rules(samdb)
            if f"%{low}" in {str(u).lower() for u in r.get("sudoUser", [])}]
    own = group_guid(samdb, dn)
    managers_of = [m["guid"] for m in all_managers(samdb) if m["guid"] != own
                   and (low in {x.lower() for x in m["managers"]} or m["only_from"].lower() == low)]
    return {"grants": grants, "sudo": sudo, "managers_of": managers_of}
