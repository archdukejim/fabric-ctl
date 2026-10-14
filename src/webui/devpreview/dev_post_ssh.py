import urllib.parse

from webui import views
from webui.devpreview.sample_data import SAMPLE_SSH


def dev_post_ssh(h, path, form):
    """Purpose: the SSH page, acted out in memory (manual 1.6.11.9): on and off flip the sample state; sign shows a
             placeholder certificate for an Ed25519 public key and refuses anything else, as production does.
    Inputs:  h — the dev handler (send, ctx); path — /ssh/sign, /ssh/on, /ssh/off; form — dict (public_key).
    Returns: True when the path was handled; None otherwise.
    Fails:   never.
    Feeds:   dev_post_action."""
    if not path.startswith("/ssh/"):
        return None
    op = path[len("/ssh/"):]
    if op in ("on", "off"):
        SAMPLE_SSH["on"] = op == "on"
        msg = f"SSH certificates are {op} (dev preview)."
        h.send(303, b"", location="/ssh?" + urllib.parse.urlencode({"msg": msg}))
    elif op == "sign":
        key = form.get("public_key", "").strip()
        if not SAMPLE_SSH["on"] or not key.startswith("ssh-ed25519 ") or len(key.splitlines()) != 1:
            why = ("SSH certificates are off on this site" if not SAMPLE_SSH["on"] else
                   "paste one public key: one line such as \"ssh-ed25519 AAAA... you@laptop\"")
            h.send(400, views.ssh(h.ctx, SAMPLE_SSH, err=why))
        else:
            h.send(200, views.ssh(h.ctx, SAMPLE_SSH, signed={
                "certificate": "ssh-ed25519-cert-v01@openssh.com AAAADEVPREVIEW not-a-real-certificate",
                "principal": ",".join(f"{h.ctx['user']}@{s}" for s in SAMPLE_SSH["sites"]),
                "principals": [f"{h.ctx['user']}@{s}" for s in SAMPLE_SSH["sites"]], "valid_hours": 8,
                "type": "ssh-ed25519", "serial": "0", "fingerprint": "SHA256:DEVPREVIEW",
                "key_id": "fabric:dev:preview"}))
    else:
        h.send(404, views.error_page(404, "Not found."))
    return True
