from webui.views.constants import DIRECTORY_SECTIONS, POLICY_FIELDS
from webui.views.render_page import render_page


def directory(ctx, view, data=None, people=None, device=None, role=None, msg="", err="", unavailable="", domain=None,
              gpo=None, logon=None, access=None):
    """Purpose: The Directory tab: devices, one device, roles, one role, people and groups, the domain, its machines,
             or Group Policy.
    Inputs:  ctx — page context; view — 'devices' | 'device' | 'roles' | 'role' | 'people'; data — device_overview()
             dict (devices, roles, types, permissions), default empty; people — list_people() dict (users, groups,
             keycloak_url) for the people view; device / role — the item for the detail views; msg, err — flash
             texts; unavailable — why the directory could not be read (shown instead of the data); domain —
             domain_overview() for the domain and machines views (the domain view's policy form: POLICY_FIELDS);
             gpo — gpo_overview() for the gpo view; logon — logon_overview() for the machines view (who may sign in
             per OU; None: not shown); access — the machines view's host groups and sudo rules {"groups", "sudo",
             "error"} (None: not shown).
    Returns: HTML str; the section tab is 'devices' for device and 'roles' for role.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/directory_page; devserver.
    """
    section = {"device": "devices", "role": "roles"}.get(view, view)
    return render_page("directory", ctx=ctx, tab="directory", view=view, section=section, sections=DIRECTORY_SECTIONS,
                   data=data or {"devices": [], "roles": [], "types": [], "permissions": {}}, people=people,
                   device=device, role=role, msg=msg, err=err, unavailable=unavailable, domain=domain, gpo=gpo,
                   logon=logon, access=access, policy_fields=POLICY_FIELDS)
