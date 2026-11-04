import os

from fabriclib.common.load_vars import load_vars
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.sizing.state import dismiss_alert


def post_sizing(actor, data):
    """Purpose: POST /v1/sizing/dismiss (status:read; manual 1.8.8.8, decision 2.1.8.39): the signed-in person dismisses
             one sizing alert, for themselves, audited.
    Inputs:  actor — str, the signed-in person; data — {"resource"}.
    Returns: {"resource", "level", "objects"} as recorded.
    Fails:   ValidationError (no resource, no such alert, no person); OSError writing.
    Feeds:   post_route."""
    resource = data.get("resource")
    if not isinstance(resource, str) or not resource:
        raise ValidationError("resource: which alert to dismiss")
    if not actor:
        raise ValidationError("a dismissal belongs to a signed-in person")
    out = dismiss_alert(os.path.join(load_vars()["deploy_base_dir"], "fabric", "config"), actor, resource)
    write_audit(actor, "SIZING_DISMISS", f"resource={resource} level={out['level']}", source="web")
    return out
