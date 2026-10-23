#!/usr/bin/env python3
"""The `settings` suite, the setup wizard in the agent and the web console with no container (manual 1.8.5.9): each
agent route allowed with settings:admin and refused without it (the permission table, the admin bundle only); the
agent's plan from the wizard's fields and from a file, its Apply as a job, a stale plan made again, another person's
plan refused, the wizard dismissed; the web console's steps (Back and Next keep what was typed, the console-only
settings read only), the plan page, Apply refused with a sign-in older than 5 minutes, a refused import, the export
download, Finish setting up on the Overview and the first sign-in opening the wizard. The agent's work below the
routes is stood in for; the webui suite's container runs the pages against a real fabric-agent.

    python3 tests/settings/console.py
"""
import copy
import os
import re
import sys
import urllib.parse
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES, PERMISSIONS  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


def refused(fn, words):
    try:
        fn()
    except ValidationError as e:
        return words in str(e) or str(e)
    return "not refused"


# ---- the permission table: settings:admin, the admin bundle only
ROUTES = [("GET", ["settings"]), ("GET", ["settings", "export"]), ("POST", ["settings", "plan"]),
          ("POST", ["settings", "apply"]), ("POST", ["settings", "dismiss"])]
# covers: agent:get.settings agent:get.settings.export agent:post.settings.plan agent:post.settings.apply +
# covers: agent:post.settings.dismiss +
check("every settings route needs settings:admin", all(required_permission(m, r) == "settings:admin"
                                                       for m, r in ROUTES))
# covers: agent:get.settings agent:get.settings.export agent:post.settings.plan agent:post.settings.apply -
# covers: agent:post.settings.dismiss -
check("settings:admin: in the console admin's bundle only (default deny for the rest)",
      "settings:admin" in PERMISSIONS and "settings:admin" in BUNDLES["admin"]
      and not any("settings:admin" in perms for name, perms in BUNDLES.items() if name != "admin"))
check("a route under settings not in the table: refused (None -> 403)",
      required_permission("POST", ["settings", "lower"]) is None and required_permission("GET", ["settings", "x"])
      is None and required_permission("POST", ["settings"]) is None)

try:
    import agent.post_settings as m_agent  # noqa: E402
    from agent.job_store import JOBS  # noqa: E402
    from agent.plan_store import PlanStore  # noqa: E402
    from agent.route_not_found import RouteNotFound  # noqa: E402
    agent_ok = True
except ImportError as exc:          # the agent's imports need the host's modules (yaml, ...)
    agent_ok, why = False, exc

if agent_ok:
    V = {"dns_filter": "bind"}
    m_agent.load_vars = lambda: copy.deepcopy(V)
    m_agent.PLANS = PlanStore()
    SEEN = []

    def fake_plan(v, given, ignored=(), source="web"):
        if given.get("host_ram_capacity") == 99:
            raise ValidationError("host_ram_capacity: a whole number of GB, 4 to 8, not 99")
        SEEN.append((given, list(ignored), source))
        return {"source": source, "given": given, "ignored": list(ignored), "base": {"dns_filter": v["dns_filter"]},
                "settings": {}, "changes": [{"key": k, "old": "a", "new": "b"} for k in given], "keys": list(given),
                "parts": [], "memory": None}
    m_agent.plan_settings = fake_plan
    m_agent.read_settings = lambda v: {"log_forwarding": {}}
    m_agent.plan_is_current = lambda plan, v: plan["base"]["dns_filter"] == v["dns_filter"]
    DONE = threading.Event()
    APPLIED = []

    def fake_apply(plan, actor):
        APPLIED.append((plan["keys"], actor))
        DONE.set()
        return {"ok": True, "keys": plan["keys"], "message": "Applied: dns_filter.", "output": "ok"}
    m_agent.apply_settings = fake_apply

    p = m_agent.post_settings(["settings", "plan"], "alice", {"form": {"dns_filter": "none"}}, "alice")
    check("POST /v1/settings/plan with the wizard's fields: the plan with an id, from the web",
          p["id"] and SEEN[-1] == ({"dns_filter": "none"}, [], "web") and p["keys"] == ["dns_filter"], p)
    text = "fabric_settings: 1\nsettings:\n  dns_filter: none\n  webui_oidc_secret: x\n"
    pf = m_agent.post_settings(["settings", "plan"], "alice", {"file": text}, "alice")
    check("POST /v1/settings/plan with a file: its wizard keys, the secret ignored and why, from a file",
          SEEN[-1] == ({"dns_filter": "none"}, [{"key": "webui_oidc_secret", "reason": "a secret"}], "file"), SEEN[-1])
    check("refused: neither fields nor a file", refused(
        lambda: m_agent.post_settings(["settings", "plan"], "alice", {}, "alice"), "fields or a settings file") is True)
    check("refused: a file that is not a settings file", refused(lambda: m_agent.post_settings(
        ["settings", "plan"], "alice", {"file": "hello: 1\n"}, "alice"), "fabric_settings: 1") is True)
    check("refused: an invalid value, named", refused(lambda: m_agent.post_settings(
        ["settings", "plan"], "alice", {"form": {"host_ram_capacity": "99"}}, "alice"), "host_ram_capacity") is True)
    check("refused: another person's plan (no difference shown from an unknown one)", refused(
        lambda: m_agent.post_settings(["settings", "apply"], "bob", {"plan": p["id"]}, "bob"), "no such plan") is True)
    job = m_agent.post_settings(["settings", "apply"], "alice", {"plan": p["id"]}, "alice")
    DONE.wait(5)
    time.sleep(0.1)
    read = JOBS.read(job["id"], "alice")
    check("POST /v1/settings/apply: one apply job as the signed-in user, read by them",
          read["kind"] == "settings" and read["state"] == "done" and APPLIED[-1] == (["dns_filter"], "alice"), read)
    check("a plan is applied once", refused(lambda: m_agent.post_settings(
        ["settings", "apply"], "alice", {"plan": p["id"]}, "alice"), "no such plan") is True)
    V["dns_filter"] = "none"                      # someone else applied first
    n = len(APPLIED)
    res = m_agent.post_settings(["settings", "apply"], "alice", {"plan": pf["id"]}, "alice")
    check("a stale plan: refused at Apply, nothing applied, the plan made again with the same values and source",
          res.get("stale") is True and res["plan"]["id"] != pf["id"] and res["plan"]["source"] == "file"
          and len(APPLIED) == n, res)
    m_agent.mark_wizard_finished = lambda how, actor, source: {"how": how, "by": actor, "at": "now"}
    check("POST /v1/settings/dismiss: recorded as dismissed by the user",
          m_agent.post_settings(["settings", "dismiss"], "alice", {}, "alice")["how"] == "dismissed")
    try:
        m_agent.post_settings(["settings", "lower"], "alice", {}, "alice")
        nf = False
    except RouteNotFound:
        nf = True
    check("another route under settings: not found (404)", nf)
else:
    check("the agent's settings routes import", False, why)

# ---- the web console
sys.path.insert(0, REPO)
try:
    from webui import agentclient as actions  # noqa: E402
    from webui import views  # noqa: E402
    import webui.routes.finish_setting_up as m_finish  # noqa: E402
    import webui.routes.settings_page as m_page  # noqa: E402
    import webui.routes.settings_post as m_post  # noqa: E402
    from webui.devpreview.sample_settings import SAMPLE_PLAN, SAMPLE_SETTINGS  # noqa: E402
    web_ok = True
except ImportError as exc:          # jinja2 missing on this machine
    web_ok, why = False, exc


class H:
    def __init__(self):
        self.to, self.status, self.body, self.ctype, self.headers = None, None, "", "", []
        self.app = type("App", (), {"lock": threading.Lock(), "sessions": {"sid1": {"user": "alice"}}})()

    def redirect(self, url, headers=None):
        self.to = url

    def back(self, location, msg="", err=""):
        """A form's outcome (the console keeps it for the next page, 1.8.6.3), written as msg=/err= for these checks."""
        q = urllib.parse.urlencode({"err": err} if err else {"msg": msg} if msg else {})
        self.redirect(location + (("&" if "?" in location else "?") + q if q else ""))

    def send(self, status, body, ctype="text/html", headers=None):
        self.status, self.body, self.ctype, self.headers = status, body, ctype, headers or []

    def deny(self, status, message):
        self.status, self.body = status, message


if web_ok:
    CTX = {"user": "alice", "csrf": "tok", "perms": ["status:read", "settings:admin"], "version": {"version": "0.8.0"}}
    actions.version_info = lambda: {"version": "0.8.0", "build": ""}
    actions.settings_overview = lambda: copy.deepcopy(SAMPLE_SETTINGS)
    SESS = {"user": "alice", "csrf": "tok", "perms": CTX["perms"], "auth_at": time.time(), "sid": "sid1"}

    # covers: web:get.settings +
    page = views.settings(CTX, SAMPLE_SETTINGS)
    check("the wizard's first step: the parts with today's values, DHCP's first subnet (0.9.0), the console-only "
          "settings read only with their commands, the steps, Next", "Optional parts" in page
          and 'name="install_fluentbit"' in page and 'name="install_kea"' in page and 'name="dhcp_subnet"' in page
          and 'list="ifaces"' in page and '<option value="wlan0">' in page
          and "home.arpa" in page and "sudo fabricctl setup (a new install)" in page
          and 'name="host_ip"' not in page and 'value="memory"' in page and 'action="/settings/step"' in page,
          page[:3000])
    page2 = views.settings(CTX, {**SAMPLE_SETTINGS, "dhcp_first_subnet": False})
    check("DHCP with subnets already: no first-subnet questions, its fields carried hidden",
          'name="install_kea"' in page2
          and 'type="hidden" name="dhcp_subnet"' in page2 and 'list="ifaces"' not in page2, page2[:3000])
    check("the first step: Export, Import and Dismiss (not finished yet)", 'href="/settings/export"' in page
          and 'action="/settings/import"' in page and 'action="/settings/dismiss"' in page)
    check("the other steps' fields carried hidden (Back and Next keep what was typed)",
          'type="hidden" name="host_ram_capacity" value="8"' in page
          and '<textarea name="dns_filter_upstreams" hidden>' in page)
    # covers: web:post.settings.step +
    h = H()
    m_post.settings_post(h, SESS, ["step"], {**SAMPLE_SETTINGS["form"], "host_ram_capacity": "6", "go": "memory"})
    check("Next: the memory step with what was typed, today's value beside it, Back",
          h.status == 200 and 'name="host_ram_capacity" type="number" min="4" max="8" value="6"' in h.body
          and "today: 8" in h.body and 'value="parts"' in h.body, h.body[:3000])
    h = H()
    m_post.settings_post(h, SESS, ["step"], {**SAMPLE_SETTINGS["form"], "host_ram_capacity": "6", "go": "review"})
    check("Review: what changed against today, Make the plan posting to /settings/plan",
          'action="/settings/plan"' in h.body
          and re.search(r"<code>host_ram_capacity</code></td><td[^>]*>8</td><td[^>]*>6", h.body),
          h.body[:3000])
    # covers: web:post.settings.step -
    h = H()
    m_post.settings_post(h, SESS, ["step"], {"go": "nowhere"})
    check("a step that does not exist: the first step", h.status == 200 and "Optional parts" in h.body)
    old = {**SESS, "auth_at": time.time() - 3600}
    h = H()
    m_page.settings_page(h, old, CTX, "/settings", {})
    check("a sign-in older than 5 minutes: said up front, with the way to sign in again",
          "sign in again" in h.body and "/login?next=/settings" in h.body)
    # covers: web:post.settings.plan +
    actions.settings_plan = lambda form=None, file=None: {**SAMPLE_PLAN, "source": "file" if file else "web"}
    h = H()
    m_post.settings_post(h, SESS, ["plan"], {**SAMPLE_SETTINGS["form"], "install_fluentbit": "true"})
    check("the plan page: each change old -> new, the parts, the memory plan, the ignored keys and why, Apply",
          "<code>install_fluentbit</code>" in h.body and "started" in h.body and "The memory plan" in h.body
          and "webui_oidc_secret" in h.body and "a secret" in h.body and 'action="/settings/apply"' in h.body
          and 'name="plan" value="dev-plan"' in h.body, h.body[:3000])

    # covers: web:post.settings.plan -
    def bad_plan(form=None, file=None):
        raise actions.ValidationError("host_ram_capacity: a whole number of GB, 4 to 8, not 99")
    actions.settings_plan = bad_plan
    h = H()
    m_post.settings_post(h, SESS, ["plan"], {**SAMPLE_SETTINGS["form"], "host_ram_capacity": "99"})
    check("a refused plan: back on Review with what was typed, the key and why",
          h.status == 200 and "Refused, nothing changed: host_ram_capacity" in h.body and "Review" in h.body
          and re.search(r"<td[^>]*>99</td>", h.body), h.body[:2000])
    # covers: web:post.settings.import -
    h = H()
    m_post.settings_post(h, SESS, ["import"], {"file": b"fabric_settings: 7\n"})
    check("an import refused: back to the wizard saying why, nothing changed",
          h.to.startswith("/settings?err=The+file+was+refused") and "host_ram_capacity" in h.to, h.to)
    h = H()
    m_post.settings_post(h, SESS, ["import"], {"text": "  "})
    check("an import with no file: asked for one", "Choose+a+settings+file" in h.to, h.to)
    # covers: web:post.settings.import +
    actions.settings_plan = lambda form=None, file=None: {**SAMPLE_PLAN, "source": "file", "file": file}
    h = H()
    m_post.settings_post(h, SESS, ["import"], {"file": "fabric_settings: 1\n".encode()})
    check("an import: the plan page, from a settings file", h.status == 200 and "from a settings file" in h.body)
    # covers: web:post.settings.apply -
    calls = []
    actions.settings_apply = lambda pid: calls.append(pid) or {"id": "job1"}
    h = H()
    m_post.settings_post(h, old, ["apply"], {"plan": "dev-plan"})
    check("Apply with a sign-in older than 5 minutes: sent to sign in again, nothing applied",
          h.to.startswith("/login?next=/settings") and calls == [], h.to)
    # covers: web:post.settings.apply +
    h = H()
    m_post.settings_post(h, SESS, ["apply"], {"plan": "dev-plan"})
    check("Apply: the job's page", h.to == "/jobs/job1" and calls == ["dev-plan"], h.to)
    actions.settings_apply = lambda pid: {"stale": True, "plan": {**SAMPLE_PLAN, "id": "plan2"}}
    h = H()
    m_post.settings_post(h, SESS, ["apply"], {"plan": "dev-plan"})
    check("Apply of a stale plan: refused, the plan made again shown", h.status == 200
          and "Someone else applied first" in h.body and 'value="plan2"' in h.body, h.body[:1500])

    def gone(pid):
        raise actions.ValidationError("no such plan (it expired after 15 minutes, or was applied)")
    actions.settings_apply = gone
    h = H()
    m_post.settings_post(h, SESS, ["apply"], {"plan": "old"})
    check("Apply of an expired plan: back to the wizard saying why", h.to.startswith("/settings?err=no+such+plan"))
    # covers: web:post.settings.dismiss +
    dismissed = []
    actions.settings_dismiss = lambda: dismissed.append(1) or {"how": "dismissed"}
    h = H()
    m_post.settings_post(h, SESS, ["dismiss"], {})
    check("Dismiss: recorded, back to the Overview", dismissed == [1] and h.to == "/")
    # covers: web:post.settings.dismiss -
    h = H()
    m_post.settings_post(h, SESS, ["lower"], {})
    check("another form under /settings/: not found", h.status == 404)
    # covers: web:get.settings.export +
    actions.settings_export = lambda: {"text": "fabric_settings: 1\n", "name": "home/../x settings.yaml"}
    h = H()
    m_page.settings_page(h, SESS, CTX, "/settings/export", {})
    check("Export: a YAML download, its name made safe", h.status == 200 and h.ctype.startswith("text/yaml")
          and h.headers == [("Content-Disposition", 'attachment; filename="home_.._x_settings.yaml"')], h.headers)
    # covers: web:get.settings.export web:get.settings -

    def denied():
        raise actions.PermissionDenied("you need the permission settings:admin")
    actions.settings_export = denied
    actions.settings_overview = denied
    for path in ("/settings/export", "/settings"):
        try:
            m_page.settings_page(H(), SESS, CTX, path, {})
            ok = False
        except actions.PermissionDenied:
            ok = True
        check(f"{path} without settings:admin: the agent's 403 reaches the handler (403 Not allowed)", ok)
    nav = views.overview({**CTX, "perms": ["status:read"]}, [])
    check("without settings:admin: no Settings tab", 'href="/settings"' not in nav)

    # ---- the Overview: Finish setting up, and the first sign-in opening the wizard
    actions.settings_overview = lambda: copy.deepcopy(SAMPLE_SETTINGS)
    h = H()
    wizard, open_now = m_finish.finish_setting_up(h, SESS, CTX)
    check("the first Overview of a sign-in: the wizard opens, once (the session remembers)",
          open_now is True and h.app.sessions["sid1"].get("wizard_opened") is True)
    wizard, open_now = m_finish.finish_setting_up(h, {**SESS, "wizard_opened": True}, CTX)
    check("after that: the Overview, with Finish setting up", open_now is False and wizard["finished"] is False)
    page = views.overview(CTX, [], wizard=wizard)
    check("the Overview's Finish setting up: Open Settings and Dismiss", "Finish setting up" in page
          and 'href="/settings"' in page and 'action="/settings/dismiss"' in page)
    page = views.overview(CTX, [], wizard={"finished": True})
    check("finished: no Finish setting up", "Finish setting up" not in page)
    check("without settings:admin: no wizard and nothing asked of the agent",
          m_finish.finish_setting_up(H(), SESS, {**CTX, "perms": ["status:read"]}) == (None, False))
    actions.settings_overview = lambda: {**SAMPLE_SETTINGS, "finished": {"finished": True}}
    check("finished: the wizard no longer opens", m_finish.finish_setting_up(H(), SESS, CTX)[1] is False)
    job = views.job_page(CTX, {"id": "j", "kind": "settings", "state": "done", "error": "",
                               "result": {"message": "Applied: dns_filter.", "output": "deploy ok"}})
    check("the apply job's page: what was applied, its output, back to Settings", "Settings · apply" in job
          and "Applied: dns_filter." in job and "deploy ok" in job and 'href="/settings"' in job)
else:
    print(f"SKIP the console's setup wizard: {why}")

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
