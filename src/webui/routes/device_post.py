import re

from webui.routes.held import held, q


def _device_fields(form):
    """Purpose: Turn the device form into the fields fabric-agent's device routes take.
    Inputs:  form — dict from read_form: type, owner, description, macs (space or comma separated), enabled (any
             non-empty value), role_<name> checkboxes.
    Returns: {'type': str, 'owner': str, 'description': str, 'macs': [str], 'enabled': bool, 'roles': [role names]}.
    Fails:   never.
    Feeds:   device_post."""
    return {"type": form.get("type", ""), "owner": form.get("owner", ""), "description": form.get("description", ""),
            "macs": [m for m in re.split(r"[\s,]+", form.get("macs", "")) if m],
            "enabled": bool(form.get("enabled")),
            "roles": [k[5:] for k, val in form.items() if k.startswith("role_") and val]}


def _role_fields(form):
    """Purpose: Turn the device role form into the fields fabric-agent's role routes take.
    Inputs:  form — dict from read_form: description, vlan, priority, perm_<permission> checkboxes.
    Returns: {'description': str, 'vlan': str, 'priority': str, 'permissions': [permissions checked]}.
    Fails:   never.
    Feeds:   device_post."""
    return {"description": form.get("description", ""), "vlan": form.get("vlan", ""),
            "priority": form.get("priority", ""),
            "permissions": [k[5:] for k, val in form.items() if k.startswith("perm_") and val]}


def device_post(h, parts, form):
    """Purpose: 802.1X's Devices and Device roles (manual 2.1.8.10, 1.8.6.5): each form one fabric-agent change, held on
             its page (Devices or Device roles) until that page's Apply.
    Inputs:  h — the request handler (back, deny); parts — path segments after /directory/: ['devices'|'roles',
             '_new'] (form name + fields), [kind, <name>] (save its fields), [kind, <name>, 'delete'], ['devices',
             <name>, 'certs', 'unlink'] (form sha256: the certificate to unlink); form — dict.
    Returns: 303 to the page saying the change waits for Apply, or why it was not held: the list after an add or a
             removal, the item's page otherwise.
    Fails:   404 for another path (only the exact unlink route: 1.8.6.7); AgentError, PermissionDenied and AuthError
             propagate.
    Feeds:   directory_post (/directory/devices/…, /directory/roles/…)."""
    kind, name = parts[0], (parts[1] if len(parts) > 1 else "")
    if kind not in ("devices", "roles") or not name:
        return h.deny(404, "Not found.")
    listing = f"/8021x/{kind}"
    here = f"{listing}/{q(name)}"
    fields = _device_fields(form) if kind == "devices" else _role_fields(form)
    if name == "_new" and len(parts) == 2:
        return held(h, listing, kind, {"name": form.get("name", "").strip(), "fields": fields})
    if name in ("_new", "_form"):
        return h.deny(404, "Not found.")
    if len(parts) == 2:
        return held(h, here, f"{kind}/{q(name)}", {"fields": fields})
    if parts[2:] == ["delete"]:
        return held(h, listing, f"{kind}/{q(name)}/delete", {})
    if kind == "devices" and parts[2:] == ["certs", "unlink"]:
        return held(h, here, f"devices/{q(name)}/certs", {"sha256": form.get("sha256", ""), "link": False})
    return h.deny(404, "Not found.")
