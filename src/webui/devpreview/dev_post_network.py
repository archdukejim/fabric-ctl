import urllib.parse

from webui import views
from webui.devpreview.sample_data import SAMPLE_RADIUS, SAMPLE_RADIUS_SESSIONS


def dev_post_network(h, path, form):
    """Purpose: RADIUS groups, clients and sessions' CoA, acted out on the sample data in memory (Kea:
             dev_post_dhcp); nothing is sent to any switch.
    Inputs:  h — the dev handler (send, ctx); path — /freeradius/people…, /freeradius/clients…,
             /freeradius/sessions/<action>; form — dict.
    Returns: True when the path was handled (a 303 with msg, or the shared-secret page); None otherwise.
    Fails:   ValueError for a non-numeric vlan or priority (not caught: http.server closes the connection).
    Feeds:   dev_post_action."""
    if path.startswith("/freeradius/people"):
        parts = [urllib.parse.unquote(p) for p in path.split("/")[3:]]
        people = SAMPLE_RADIUS["people"]
        if parts:
            people[:] = [m for m in people if m["group"] != parts[0]]
            msg = f"Members of {parts[0]} may no longer join by password (dev preview)."
        else:
            people.append({"group": form.get("group", ""), "vlan": int(form["vlan"]) if form.get("vlan") else None,
                           "priority": int(form.get("priority") or 100)})
            msg = f"Members of {form.get('group', '')} may join by password (dev preview)."
        h.send(303, b"", location="/freeradius?" + urllib.parse.urlencode({"msg": msg}))
        return True
    if path.startswith("/freeradius/sessions"):
        found = next((s for s in SAMPLE_RADIUS_SESSIONS["sessions"]
                      if s["client"] == form.get("client") and s["session"] == form.get("session")), None)
        action = path.rsplit("/", 1)[-1]
        if found is None or action not in found["actions"]:
            query = {"view": "sessions", "err": (found or {}).get("no_coa") or "no such session (dev preview)"}
        else:
            query = {"view": "sessions", "msg": f"{action}: {found['who']} on {found['client']}: acknowledged "
                                                "(dev preview: nothing sent)"}
        h.send(303, b"", location="/freeradius?" + urllib.parse.urlencode(query))
        return True
    if path.startswith("/freeradius/clients"):
        parts = [urllib.parse.unquote(p) for p in path.split("/")[3:]]
        clients = SAMPLE_RADIUS["clients"]
        if len(parts) == 2 and parts[1] == "set":
            for c in clients:
                if c["name"] == parts[0]:
                    c.update(vendor=form.get("vendor") or c["vendor"],
                             transport=form.get("transport") or c["transport"],
                             coa=(form.get("vendor") or c["vendor"]) == "cisco")
            h.send(303, b"", location="/freeradius?" + urllib.parse.urlencode(
                {"msg": f"RADIUS client {parts[0]} changed (dev preview)."}))
            return True
        if len(parts) == 2 and parts[1] == "delete":
            clients[:] = [c for c in clients if c["name"] != parts[0]]
            h.send(303, b"", location="/freeradius?" + urllib.parse.urlencode(
                {"msg": f"RADIUS client {parts[0]} removed (dev preview)."}))
            return True
        name = parts[0] if parts else form.get("name", "").lower()
        if not parts:
            clients.append({"name": name, "address": form.get("address", ""),
                            "message_authenticator": form.get("message_authenticator") == "1",
                            "vendor": form.get("vendor", "generic"), "transport": form.get("transport", "udp"),
                            "coa": form.get("vendor") == "cisco"})
        client = next((c for c in clients if c["name"] == name), {})
        h.send(200, views.radius_secret(h.ctx, name, "dev-preview-not-a-real-secret",
                                        "added" if not parts else "rotated", "192.168.1.2", client=client))
        return True
    return None
