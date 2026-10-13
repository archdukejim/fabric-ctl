from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.read_plan import read_plan
from fabriclib.secrets.load_secrets import load_secrets

GROUP = "fabric-dhcp-org-editors"


def set_option_editor(v, actor, site, allow, secrets=None, container="samba", source="cli", root=None):
    """Purpose: let a site edit the organisation's DHCP options, or stop it (decision 2.1.10.23, manual 1.10.4.24.2):
             its fabric-agent account put in or taken out of `fabric-dhcp-org-editors`, which only the top site may
             change (the group is in the top's OU=organisation). Its people still need `dhcp:org-options`.
    Inputs:  v — fabric vars (site_name); actor — who asks (audit); site — the site's name; allow — bool; secrets —
             fabric's secrets (default load_secrets()); container — the DC's container; source — "cli" or "web";
             root — whether this is the top site (None: the federation registry says).
    Returns: {"site", "allowed" (bool), "changed" (bool), "editors" (the sites allowed now)}.
    Fails:   ValidationError: not the top site; the top's own site (it always may); a site the plan does not know; the
             directory refusing (the DC not answering, the group not there yet: apply at the top first).
    Feeds:   run_option_command (option-editors add|remove), agent route POST /v1/ipam/option-editors."""
    root = is_root_site() if root is None else root
    if not root:
        raise ValidationError("only the top site decides which sites may edit the organisation's DHCP options")
    site = str(site or "").strip()
    if site == v["site_name"]:
        raise ValidationError(f"{site} is the top site: it always may edit the organisation's DHCP options")
    secrets = secrets if secrets is not None else load_secrets()
    read = read_plan(v, secrets, container=container)
    if site not in [s["name"] for s in read.get("sites") or []]:
        raise ValidationError(f"no site {site!r} in the organisation")
    op = "add_group_member" if allow else "remove_group_member"
    try:
        answer = run_op(v, secrets, op, {"group": GROUP, "uid": f"fabric-agent-{site}"}, container=container)
    except ValidationError as e:
        if "no such entry" in str(e):
            raise ValidationError(f"the group {GROUP} or {site}'s agent account is not in the domain yet: apply at the "
                                  "top site, and let the site finish joining")
        raise
    changed = bool(answer.get("added") if allow else answer.get("removed"))
    write_audit(actor, "IPAM_OPTION_EDITOR_ADD" if allow else "IPAM_OPTION_EDITOR_REMOVE",
                f"from={v['site_name']} site={site} changed={changed}", source)
    editors = site_plan(read_plan(v, secrets, of=v["site_name"], container=container), v["site_name"])["org_editors"]
    return {"site": site, "allowed": allow, "changed": changed, "editors": editors}
