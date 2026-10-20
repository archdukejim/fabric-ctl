from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.grants.add_grant import add_grant
from fabriclib.grants.read_grant_fields import read_grant_fields
from fabriclib.grants.remove_grant import remove_grant
from fabriclib.grants.set_grant import set_grant
from fabriclib.grants.sync_grants import sync_grants


def post_grants(route, actor, data, caller=None):
    """Purpose: the grants' changes (manual 1.6.13.7): POST /v1/domain/grants (body: name, template, its fields),
             /v1/domain/grants/<name> (body: the fields to change), /v1/domain/grants/<name>/delete and
             /v1/domain/grants/sync; each `groups:admin` (the Directory Administrators).
    Inputs:  route — ["domain", "grants", ...]; actor — str; data — the JSON body; caller — the token's user
             (fabric-agent's check: the Directory Administrators alone), or None for a root peer.
    Returns: add, set: {"grant", "changed"}; delete: {"name", "changed"}; sync: {"changed"} or {"skipped"}.
    Fails:   ValidationError("unknown operation") for another route, or from fabriclib (-> 400): the fields' types, the
             DC's refusals with why.
    Feeds:   agent/post_domain.py."""
    v, rest = load_vars(), route[2:]
    if rest == []:
        return add_grant(v, actor, read_text(data, "name"), read_grant_fields(data),
                         read_text(data, "template") or None, source="web", caller=caller)
    if rest == ["sync"]:
        return sync_grants(v, actor, source="web")
    if len(rest) == 1:
        return set_grant(v, actor, rest[0], read_grant_fields(data), source="web", caller=caller)
    if len(rest) == 2 and rest[1] == "delete":
        return remove_grant(v, actor, rest[0], source="web", caller=caller)
    raise ValidationError("unknown operation")
