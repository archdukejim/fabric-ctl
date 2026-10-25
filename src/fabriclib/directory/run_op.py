import json
import subprocess

from fabriclib.common.errors import ValidationError

# what the caller is told for each kind of refusal (directory_op's kinds)
MESSAGES = {"exists": "that name is already taken", "missing": "no such entry",
            "refused": "the directory refused the change (not permitted for fabric's agent)"}


def run_op(v, secrets, op, args=None, container="samba", server=None):
    """Purpose: one directory operation (manual 1.6.3, 1.6.5.16), run inside the DC by src/containers/samba/
             directory_op.py, signed in as this DC's fabric-agent account, fabric-agent-<dc_name> (2.1.6.82) — so AD's
             ACLs apply to every change fabric-agent makes (1.6.13.2). The request, the account's password included,
             goes on stdin, with this DC's name (the record its ids come from, 2.1.6.63).
    Inputs:  v — rendered vars (site_name, dc_name); secrets — fabric's secrets (ad_agent_password); op — str, an
             operation
             of the DC's directory_ops; args — dict of its arguments (JSON-able); container — the DC's container;
             server — None (this DC) or another DC's address to sign in at (a read-only DC's writable partner,
             2.1.6.52).
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with a message safe to show: "that name is already taken", "no such entry", "the
             directory refused the change …", "the directory refused it: …" (e.g. a password the policy refuses),
             an operation's own refusal word for word (e.g. "no such user: …"), or "the directory is not reachable"
             when the DC is not running; "this host has no domain controller set up" when the settings name none
             (no dc_name or site_name) or the secrets hold no ad_agent_password; subprocess.TimeoutExpired after
             60 s.
    Feeds:   fabriclib/directory/* (people, groups, devices, roles, networks)."""
    if not v.get("dc_name") or not v.get("site_name") or not secrets.get("ad_agent_password"):
        raise ValidationError("this host has no domain controller set up (no dc_name, site_name or agent account)")
    dc = v["dc_name"]
    request = {"op": op, "args": args or {}, "site": v["site_name"], "dc": dc, "account": f"fabric-agent-{dc}",
               "password": secrets["ad_agent_password"], **({"server": server} if server else {})}
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container,
                          "python3", "/fabric/directory_op.py"],
                         input=json.dumps(request), capture_output=True, text=True, timeout=60)
    if res.returncode != 0 or not res.stdout.strip():
        raise ValidationError("the directory is not reachable (is the samba service running?)")
    answer = json.loads(res.stdout.strip().splitlines()[-1])
    if "error" in answer:
        kind = answer.get("kind")
        if kind == "invalid":                 # the operation's own refusal: its message is meant for the person
            raise ValidationError(answer["error"])
        raise ValidationError(MESSAGES.get(kind) or f"the directory refused it: {answer['error']}")
    return answer["result"]
