import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.routes.account_page import account_page
from webui.routes.bind9_page import bind9_page
from webui.routes.devices_page import devices_page
from webui.routes.directory_page import directory_page
from webui.routes.finish_setting_up import finish_setting_up
from webui.routes.computers_page import computers_page
from webui.routes.access_page import access_page
from webui.routes.groups_page import groups_page
from webui.routes.sites_page import sites_page
from webui.routes.kerberos_page import kerberos_page
from webui.routes.ous_page import ous_page
from webui.routes.dns_filter_page import dns_filter_page
from webui.routes.moved_to import moved_to
from webui.routes.networks_page import networks_page
from webui.routes.networks_scan_page import networks_scan_page
from webui.routes.openbao_page import openbao_page
from webui.routes.options_page import options_page
from webui.routes.people_page import people_page
from webui.routes.radius_page import radius_page
from webui.routes.relaxations import relaxations
from webui.routes.roles_page import roles_page
from webui.routes.policies_page import policies_page
from webui.routes.settings_page import settings_page
from webui.routes.stepca_page import stepca_page
from webui.session.page_context import page_context

SIGNED_IN = "Signed in again. Repeat the change: it needs a sign-in from the last 5 minutes."


def _overview(h, sess, ctx, path):
    """Purpose: The Overview entry's pages: Health (/), Doctor, Updates.
    Inputs:  h — the request handler; sess — the session; ctx — page context; path — "/", "/overview/doctor" or
             "/overview/updates".
    Returns: the page sent (Health: the host changes fabric may make, the host's reminders read afresh and, until the
             setup wizard is finished, Finish setting up — its first view in a sign-in opens the wizard instead, 303
             to /settings).
    Fails:   agent errors propagate to handle_request.
    Feeds:   get_page."""
    if path == "/overview/doctor":
        return h.send(200, views.overview(ctx, page=path))
    if path == "/overview/updates":
        try:
            images = actions.image_rows()
        except (actions.AgentError, actions.ValidationError):
            images = None
        return h.send(200, views.overview(ctx, images=images, page=path))
    wizard, open_now = finish_setting_up(h, sess, ctx)
    if open_now:                                   # the first Overview of a sign-in opens the wizard (1.8.5.3)
        return h.redirect("/settings")
    try:                                           # Overview reads the reminders afresh (2.1.6.69)
        ctx["reminders"] = actions.host_reminders()
        with h.app.lock:                           # the session's other pages follow
            if sess.get("sid") in h.app.sessions:
                h.app.sessions[sess["sid"]]["reminders"] = ctx["reminders"]
    except (actions.AgentError, actions.ValidationError, actions.PermissionDenied):
        pass
    return h.send(200, views.overview(ctx, actions.service_status(), actions.host_changes(),
                                      actions.relaxed_settings(), actions.cert_warnings(), None, "", wizard))


def _rest(path, prefix):
    """Purpose: The one URL-decoded segment after a prefix (/8021x/devices/<name>), or None.
    Inputs:  path — str; prefix — str ending in "/".
    Returns: str or None (no segment, or more than one).
    Fails:   never.
    Feeds:   get_page."""
    rest = path[len(prefix):] if path.startswith(prefix) else ""
    return urllib.parse.unquote(rest) if rest and "/" not in rest else None


def get_page(h, sess, path, query):
    """Purpose: Route a signed-in GET to its page (the navigation of manual 1.8.6.4); an old address answers with a
             redirect to its new one (moved_to).
    Inputs:  h — the request handler (send, redirect, deny); sess — dict from find_session; path — str; query — dict
             (view, zone, device, name, slot, step, the query log's search as each page uses them).
    Returns: 303 to the new address of a page that moved; 200 page: Overview (/, /overview/doctor,
             /overview/updates, /audit), DNS (/dns/zones, /dns-filter), DHCP (/networks[/export|/scan|/options],
             1.10.4.40.1; /kea), PKI (/pki, /pki/acme),
             Directory (/directory, /directory/people|groups|computers[/_new|/<name>], /directory/computers/_groups,
             /directory/ous[?ou=<path>], /directory/access[/_new|/<name>], /directory/sites[/<name>],
             /directory/kerberos,
             /directory/policies[/gpo|/sudo]), 802.1X
             (/8021x, /8021x/decisions, /8021x/guides, /8021x/devices[/_new|/<name>], /8021x/roles[/_new|/<name>]),
             Secrets
             (/secrets[/<view>]), Federation (/federation),
             Settings (/settings, /settings/export, /settings/sign-in), My account (/account, /account/groups,
             1.8.6.6), a job (/jobs/<id>), a page's pending changes and queue (/changes/<page id>, 1.8.6.5); 303
             from / to the first page they may see for a person who may not see the Overview (My account for one
             with no fabric role); 403 for a navigation page whose permission they lack (checked here too, not only
             by fabric-agent: a page that reads nothing, such as Doctor, would otherwise show; a person's or a
             group's page and Add person or Create group are their list's).
    Fails:   404 for any other path; agent errors propagate to handle_request (400, redirect to /login, 403, 503).
    Feeds:   handler.Handler.handle_request.
    """
    new = moved_to(path, query)
    if new:
        return h.redirect(new)
    ctx = page_context(sess)
    if query.get("signed_in") and not ctx.get("flash"):     # back from a step-up sign-in: a fixed text, not the query's
        ctx["flash"] = {"ok": SIGNED_IN}
    if path == "/" and "status:read" not in ctx["perms"]:    # the Overview is not theirs: their first page
        return h.redirect(views.nav_menu(set(ctx["perms"]), None)[0]["href"])
    shown = views.PENDING_PAGES.get(_rest(path, "/changes/") or "", path)   # a Review: the page it reviews
    for listing in ("/directory/people", "/directory/groups", "/directory/computers", "/directory/access",
                    "/directory/sites", "/directory/policies", "/8021x/devices", "/8021x/roles"):
        if path.startswith(listing + "/"):
            shown = listing
    if path.startswith("/8021x/clients/") or path.startswith("/8021x/people/"):
        shown = "/8021x"
    if path in ("/networks/scan", "/networks/export"):     # pages of Networks (1.10.4.40.1)
        shown = "/networks"
    if path.startswith("/pki/issued/") or path.startswith("/pki/acme/"):
        shown = "/pki/acme" if path.startswith("/pki/acme/") else "/pki"
    need = next((n for _, _, pages in views.NAV for href, _, n in pages if href == shown and n), None)
    if need and not set(need) & set(ctx["perms"]):            # a navigation page's own permission (1.8.6.4)
        return h.deny(403, f"You need the permission {' or '.join(need)} to see this page.")
    if path == "/" or path == "/overview/doctor" or path == "/overview/updates":
        return _overview(h, sess, ctx, path)
    if path == "/account" or path == "/account/groups":
        return account_page(h, ctx, path)
    if path == "/audit":
        return h.send(200, views.audit(ctx, actions.read_audit()))
    if path.startswith("/jobs/") and path.count("/") == 2:
        return h.send(200, views.job_page(ctx, actions.read_job(path[len("/jobs/"):])))
    if path == "/dns/zones":
        return bind9_page(h, ctx, query)
    if path == "/dns-filter":
        return dns_filter_page(h, ctx, query)
    if path == "/networks" or path == "/networks/export":
        return networks_page(h, ctx, path, query)
    if path == "/networks/scan":
        return networks_scan_page(h, ctx, query)
    if path == "/networks/options":
        return options_page(h, ctx, query)
    if path == "/kea":
        return h.send(200, views.kea(ctx, actions.dhcp_overview()))
    if path == "/pki":
        view = query.get("view", "ca")
        return stepca_page(h, ctx, "ca" if view == "acme" else view, device=query.get("device", ""))
    if path == "/pki/acme":
        return stepca_page(h, ctx, "acme")
    if _rest(path, "/pki/issued/"):
        return stepca_page(h, ctx, "cert", serial=_rest(path, "/pki/issued/"))
    if _rest(path, "/pki/acme/"):
        return stepca_page(h, ctx, "machine", serial=_rest(path, "/pki/acme/"))
    if path == "/directory":
        return directory_page(h, ctx)
    if path == "/directory/people" or path.startswith("/directory/people/"):
        return people_page(h, ctx, path, query)
    if path == "/directory/groups" or path.startswith("/directory/groups/"):
        return groups_page(h, ctx, path, query)
    if path == "/directory/access" or path.startswith("/directory/access/"):
        return access_page(h, ctx, path, query)
    if path == "/directory/sites" or path.startswith("/directory/sites/"):
        return sites_page(h, ctx, path)
    if path == "/directory/kerberos":
        return kerberos_page(h, ctx)
    if path == "/directory/ous":
        return ous_page(h, ctx, query)
    if path == "/directory/computers" or path.startswith("/directory/computers/"):
        return computers_page(h, ctx, path, query)
    if path == "/directory/policies" or path == "/directory/policies/gpo" or path == "/directory/policies/sudo":
        return policies_page(h, ctx, path, query)
    if path == "/8021x/devices" or _rest(path, "/8021x/devices/"):
        return devices_page(h, ctx, path)
    if path == "/8021x/roles" or _rest(path, "/8021x/roles/"):
        return roles_page(h, ctx, path)
    if path == "/8021x" or path == "/8021x/decisions" or path == "/8021x/guides":
        view = {"/8021x": "overview", "/8021x/decisions": "decisions"}.get(path)
        view = view or (query.get("view") if query.get("view") in ("switches", "windows") else "switches")
        guides = actions.radius_guides() if view in ("switches", "windows") else None
        return h.send(200, views.freeradius(ctx, actions.radius_overview(), view=view, guides=guides))
    if path.startswith("/8021x/clients/") or path.startswith("/8021x/people/"):
        return radius_page(h, ctx, path)
    if path == "/secrets":
        return openbao_page(h, ctx, {**query, "view": "status"})
    if _rest(path, "/secrets/") in views.OPENBAO_VIEWS:
        return openbao_page(h, ctx, {**query, "view": _rest(path, "/secrets/")})
    if _rest(path, "/changes/") in views.PENDING_PAGES:      # a page's Review and queue (1.8.6.5)
        return h.send(200, views.changes(ctx, actions.pending_page(_rest(path, "/changes/"))))
    if path == "/federation":
        return h.send(200, views.federation(ctx, actions.federation_overview()))
    if path == "/settings" or path == "/settings/export":
        return settings_page(h, sess, ctx, path, query)
    if path == "/settings/sign-in":
        return h.send(200, views.security(ctx, actions.security_layers(), relaxed=relaxations(ctx)))
    return h.deny(404, "Not found.")
