from agent.read_text import read_text
from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.domain.create_ou import create_ou
from fabriclib.domain.delete_ou import delete_ou
from fabriclib.domain.rename_ou import rename_ou


def post_ous(route, actor, data):
    """Purpose: the admin's own OUs (manual 1.6.12.7, 1.6.12.12; `ous:admin`): POST /v1/ous (create: parent, name),
             /v1/ous/rename (ou, name) and /v1/ous/delete (ou); an OU named by its path ("people/staff"). fabric's own
             OUs are refused by the DC.
    Inputs:  route — ["ous"], ["ous", "rename"] or ["ous", "delete"]; actor — str; data — the JSON body.
    Returns: create, rename: {"path", "dn"}; delete: {"path"}.
    Fails:   ValidationError (-> 400): "unknown operation", or fabriclib's refusal with why.
    Feeds:   agent/post_route.py (POST ous/...)."""
    v = load_vars()
    if route == ["ous"]:
        return create_ou(v, actor, read_text(data, "parent"), read_text(data, "name"))
    if route == ["ous", "rename"]:
        return rename_ou(v, actor, read_text(data, "ou"), read_text(data, "name"))
    if route == ["ous", "delete"]:
        return delete_ou(v, actor, read_text(data, "ou"))
    raise ValidationError("unknown operation")
