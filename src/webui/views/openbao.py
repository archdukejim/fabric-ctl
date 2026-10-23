from webui.views.constants import OPENBAO_SECTIONS, SLOT_TYPES
from webui.views.render_page import render_page


def openbao(ctx, status, view="status", slots=(), devices=None, slot_id="", host="", live=False, msg="", err="",
            add_live=None):
    """Purpose: The OpenBao tab: status, unlock methods (with add, rotate and remove views), secrets, disk encryption
             guide.
    Inputs:  ctx — page context; status — vault_status() dict; view — one of OPENBAO_VIEWS; slots — list of unlock
             methods (vault_slots()['slots']); devices — vault_devices() dict (pkcs11, tokens, disks) for the add
             views, default no devices; slot_id — the method the remove view is about; host — this host's name, typed
             to confirm; live — whether slot changes are available (False shows them disabled); msg, err — flash
             texts; add_live — {'security-key', 'usb', 'hsm': bool}, which add forms are enabled, default none.
    Returns: HTML str; the section tab is the view itself for status, secrets and disk, else 'unlock'.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out); UndefinedError if a slot's type is not in SLOT_TYPES.
    Feeds:   src/webui/routes/openbao_page; devserver.
    """
    section = view if view in ("status", "secrets", "disk") else "unlock"
    page = "/secrets" + ("" if section in ("status", "secrets") else "/" + section)
    return render_page("openbao", ctx=ctx, page=page, s=status, view=view, section=section,
                       sections=OPENBAO_SECTIONS,
                   slots=list(slots), devices=devices or {"tokens": [], "disks": []}, slot_types=SLOT_TYPES,
                   slot_id=slot_id, host=host, live=live, msg=msg, err=err,
                   add_live=add_live or {"security-key": False, "usb": False, "hsm": False})
