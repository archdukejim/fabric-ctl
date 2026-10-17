import urllib.parse

from webui import views
from webui.devpreview.dev_post_directory import dev_post_directory
from webui.devpreview.dev_post_dns import dev_post_dns
from webui.devpreview.dev_post_dhcp import dev_post_dhcp
from webui.devpreview.dev_post_dns_filter import dev_post_dns_filter
from webui.devpreview.dev_post_network import dev_post_network
from webui.devpreview.dev_settings import dev_settings
from webui.devpreview.sample_data import SAMPLE_CA, SAMPLE_DOCTOR, SAMPLE_INFO, SAMPLE_PEM
from webui.devpreview.sample_result import sample_result


def dev_post_action(h, path, form):
    """Purpose: Act out every form post in memory only (DNS records, TSIG keys, apply, jobs, PKI, vault, devices, roles,
             people, DHCP reservations, RADIUS clients and groups, the setup wizard) and show the same result page or
             redirect as production. Nothing is saved, signed or applied; secrets and passwords shown are fake or
             throwaway.
    Inputs:  h — the dev handler (send, state, ctx); path — the URL path; form — dict (text fields only).
    Returns: None; sends 200 result pages, 303 redirects carrying msg/err, or 404 for an unknown route.
    Fails:   errors other than the directory's ValidationError are not caught: http.server logs them and closes the
             connection.
    Feeds:   dev_handler.DevHandler.do_POST (under the state lock)."""
    state, ctx = h.state, h.ctx
    if path == "/logout":
        return h.send(303, b"", location="/")
    if path == "/apply":
        state.log("APPLY", "dev preview: nothing applied")
        return h.send(200, views.apply_result(ctx, True, "DEV PREVIEW — nothing was rendered or reloaded.\n"
                                                         "On a real install this runs `fabricctl --apply`."))
    if path.startswith("/overview/"):           # jobs finish at once in the preview
        parts = path.split("/")[2:]
        jobs = state.data.setdefault("jobs", {})
        job_id = f"dev-{len(jobs) + 1}"
        if parts == ["doctor"]:
            jobs[job_id] = {"id": job_id, "kind": "doctor", "state": "done", "result": SAMPLE_DOCTOR, "error": ""}
        elif len(parts) == 3 and parts[0] == "images" and parts[2] in ("update", "rollback"):
            if "images:update" not in ctx["perms"]:
                return h.send(403, views.error_page(403, "Not allowed: you need the permission images:update."))
            verb = "updated" if parts[2] == "update" else "rolled back"
            jobs[job_id] = {"id": job_id, "kind": "images", "state": "done", "error": "",
                            "result": {"action": parts[2], "service": parts[1], "moved": [parts[1]],
                                       "message": f"{verb} {parts[1]} (in memory)"}}
        else:
            return h.send(404, views.error_page(404, "Not found."))
        return h.send(303, b"", location=f"/jobs/{job_id}")
    if path == "/stepca/acme/enroll":
        host = form.get("host", "").strip().lower()
        return h.send(200, views.tsig_result(ctx, f"acme-{host}", "ZGV2LXByZXZpZXctbm90LWEtcmVhbC1rZXk=",
                                             "# DEV PREVIEW — not a real key\n", "created"))
    if path.startswith("/openbao/"):
        return h.send(303, b"", location="/openbao?" + urllib.parse.urlencode(
            {"view": "unlock", **state.vault_action(path.split("/")[2:], form)}))
    if dev_settings(h, "POST", path, form):     # the setup wizard (1.8.5.3)
        return None
    for area in (dev_post_dhcp, dev_post_dns_filter, dev_post_network, dev_post_directory):
        if area(h, path, form):
            return None
    if path == "/stepca/sign/review":
        review = {"pem": SAMPLE_PEM, "subject": SAMPLE_INFO["subject"], "cn": "device.home.arpa",
                  "sans": SAMPLE_INFO["sans"], "key": "RSA 2048", "ca_requested": False, "problems": [],
                  "text": "DEV PREVIEW — a real install shows the decoded request here."}
        return h.send(200, views.stepca(ctx, "sign", SAMPLE_CA, review=review))
    if path == "/stepca/inspect":
        item = {"info": SAMPLE_INFO, "trusted": True,
                "text": "DEV PREVIEW — a real install shows `openssl x509 -text` here."}
        return h.send(200, views.stepca(ctx, "inspect", SAMPLE_CA, inspected={"kind": "cert", "items": [item]}))
    if path in ("/stepca/sign", "/stepca/issue", "/stepca/convert"):
        kind = path.rsplit("/", 1)[1]
        state.log(f"PKI_{kind.upper()}", "dev preview: sample only, nothing signed")
        return h.send(200, views.pki_result(ctx, kind, sample_result(kind)))
    if dev_post_dns(h, path, form):
        return None
    return h.send(404, views.error_page(404, "Not found."))
