from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.grants.grant_request import grant_request

NOT_HERE = "root site's writable DC"        # grants_tool's refusal at any other DC


def sync_grants(v, actor="fabric", source="timer", container="samba", quiet=False):
    """Purpose: the grants compiled again from the directory as it is (manual 1.6.13.4): at once after a change fabric
             makes to a group's members (a person's groups, a machine's), and every 5 minutes by the fabric-grants
             timer for a change made elsewhere (RSAT, samba-tool, a join). Only the root's writable DC compiles; at any
             other the root's next run picks the change up.
    Inputs:  v — rendered vars; actor, source — for the audit; container — the DC's container; quiet — bool: never
             raise (a change that already happened is not undone because the compile failed; the timer retries).
    Returns: {"changed": [what changed]}, or {"skipped": why} (not the root's writable DC; or quiet and refused).
    Fails:   ValidationError from grant_request (the DC not running), unless quiet.
    Feeds:   grants/run_grant_command (`grant sync`, the fabric-grants timer); agent route POST /v1/domain/grants/sync;
             directory/set_person_group, add_machine, set_host_group_member, sort_machines (at once).
    Notes:   audited GRANT_COMPILE with what changed, only when something did."""
    try:
        done = grant_request(v, {"op": "compile"}, container)
    except ValidationError as e:
        if quiet or NOT_HERE in str(e):
            return {"skipped": str(e)}
        raise
    if done["changed"]:
        write_audit(actor, "GRANT_COMPILE", "; ".join(done["changed"])[:2000], source)
    return done
