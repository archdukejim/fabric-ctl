from webui import agentclient as actions
from webui import views


def openbao_page(h, ctx, query):
    """Purpose: Render the OpenBao tab: status, unlock methods and their add/rotate/remove forms, secrets, disk
             encryption.
    Inputs:  h — the request handler (send); ctx — page context; query — dict: view (one of views.OPENBAO_VIEWS, else
             'status'), slot (for an unlock method's page, "method", and its remove view).
    Returns: 200 OpenBao page; slot changes are live and every add type is enabled; 404 for the method and remove
             views of a method that is not there (2.1.8.16).
    Fails:   agent errors from vault_slots, vault_status and vault_devices (the last only for add-security-key and
             add-usb) propagate to handle_request (400, redirect to /login, 403, 503).
    Feeds:   get_page (/secrets, /secrets/<view>).
    """
    view = query.get("view") if query.get("view") in views.OPENBAO_VIEWS else "status"
    slots = actions.vault_slots()
    if view in ("method", "remove") and not any(s.get("id") == query.get("slot") for s in slots["slots"]):
        return h.deny(404, "No unlock method has that id.")
    devices = actions.vault_devices() if view in ("add-security-key", "add-usb") else None
    return h.send(200, views.openbao(ctx, actions.vault_status(), view, slots["slots"], devices,
                                     slot_id=query.get("slot", ""), host=slots["host"], live=True,
                                     add_live={"security-key": True, "usb": True, "hsm": True}))
