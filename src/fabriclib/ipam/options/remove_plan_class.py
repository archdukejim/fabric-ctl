from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.set_owner import set_owner


def remove_plan_class(v, actor, scope, name, site="", secrets=None, container="samba", source="cli"):
    """Purpose: remove a client class, with its options, from the organisation's or a site's set (manual 1.10.4.24.5).
    Inputs:  v — fabric vars; actor — who asks (audit); scope — "org" or "site"; name — the class's name; site — whose
             set ("" this site's); secrets, container, source — as edit_options.
    Returns: edit_options' result; result = the class removed.
    Fails:   ValidationError: no class of that name there; what set_owner or edit_options refuses.
    Feeds:   run_option_command (class remove), agent routes POST /v1/ipam/classes and /v1/ipam/classes/org."""
    want = str(name or "").strip()

    def change(plan):
        owner = set_owner(plan, scope)
        classes = owner["set"]["client_classes"]
        found = next((c for c in classes if c["name"] == want), None)
        if found is None:
            raise ValidationError(f"no client class {want!r} in {owner['label']}")
        kept = [c for c in classes if c is not found]
        return (owner["write"]({"client_classes": kept}), found, f"scope={owner['label']} class {want} removed", [])
    return edit_options(v, actor, site, "IPAM_CLASS_REMOVE", change, secrets, container, source)
