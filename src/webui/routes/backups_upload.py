import os

from webui import agentclient as actions

BACK = "/settings/backups"


def backups_upload(h, sess, parts):
    """Purpose: Upload a bundle (manual 1.3.7.9): the form's file part passed on to fabric-agent as it arrives, never
             held; the CSRF field was read and checked first (handler). A Domain Admin only; fabric-agent checks
             again and checks the bundle whole before it is listed.
    Inputs:  h — the request handler (back, deny); sess — dict from find_session (domain_admin); parts — the request's
             MultipartStream, after its csrf part.
    Returns: 303 back to Backups saying what was added, or why not (nothing added).
    Fails:   403 for someone the sign-in did not find a Domain Admin; AgentError, PermissionDenied and AuthError
             propagate to handle_request.
    Feeds:   webui/handler (POST /settings/backups/upload)."""
    h.close_connection = True                 # what is left of the body, after a refusal, is not read
    if not sess.get("domain_admin"):
        return h.deny(403, "Only the domain's Domain Admins may use backups.")
    try:
        part = parts.next_part()
        if not part or part[0] != "bundle" or not part[1]:
            raise actions.ValidationError("choose a bundle file to upload")
        name = os.path.basename(part[1].replace("\\", "/"))
        out = actions.backup_upload(name, parts.read_part())
    except actions.ValidationError as exc:
        return h.back(BACK, err=f"Not uploaded: {exc}")
    return h.back(BACK, msg=f"Uploaded {out['file']} ({out['size'] >> 20} MiB): its check passed, it is in the list.")
