from webui import views
from webui.devpreview.sample_settings import SAMPLE_PLAN, SAMPLE_SETTINGS, SAMPLE_SETTINGS_FILE
from webui.views.constants import WIZARD_FIELDS


def dev_settings(h, method, path, data):
    """Purpose: the setup wizard in the dev preview (manual 1.8.5.3) over sample data: its steps (Back and Next keep
             what was typed), a sample plan, an apply that finishes at once in memory, the export's sample file.
             Nothing is saved or applied.
    Inputs:  h — the dev handler (send, state, ctx); method — "GET" or "POST"; path — the URL path; data — the query
             (GET: step, msg, err) or the form (POST: the wizard's fields, go).
    Returns: True when the path was the wizard's (the page or redirect sent), else False.
    Fails:   Jinja2 errors propagate.
    Feeds:   dev_get_page, dev_post_action."""
    ctx = h.ctx
    if method == "GET" and path == "/settings":
        h.send(200, views.settings(ctx, SAMPLE_SETTINGS, data.get("step", "parts"), None, data.get("msg", ""),
                                   data.get("err", "")))
        return True
    if method == "GET" and path == "/settings/export":
        h.send(200, SAMPLE_SETTINGS_FILE, "text/yaml; charset=utf-8")
        return True
    if method != "POST" or not path.startswith("/settings/"):
        return False
    typed = {f: data[f] for f in WIZARD_FIELDS if isinstance(data.get(f), str)}
    if path == "/settings/step":
        h.send(200, views.settings(ctx, SAMPLE_SETTINGS, data.get("go", ""), typed))
    elif path in ("/settings/plan", "/settings/import"):
        h.send(200, views.settings_plan(ctx, {**SAMPLE_PLAN, "source": "file" if path.endswith("import") else "web"}))
    elif path == "/settings/apply":
        jobs = h.state.data.setdefault("jobs", {})
        job_id = f"dev-{len(jobs) + 1}"
        jobs[job_id] = {"id": job_id, "kind": "settings", "state": "done", "error": "",
                        "result": {"message": "Applied (in memory): install_fluentbit, host_ram_capacity.",
                                   "output": "DEV PREVIEW — nothing was rendered or reloaded."}}
        h.send(303, b"", location=f"/jobs/{job_id}")
    elif path == "/settings/dismiss":
        h.send(303, b"", location="/")
    else:
        h.send(404, views.error_page(404, "Not found."))
    return True
