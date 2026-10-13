import json
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.samba.writable_server import writable_server

# what the caller is told for each kind of refusal (directory_op's kinds)
MESSAGES = {"exists": "that name is already taken", "missing": "no such entry",
            "refused": "the directory refused the change (not permitted for this site)"}
# the operations that only read: answered by this site's own DC, read-only or not. Every other operation writes and,
# at a site whose DC is read-only, goes to the writable DC (2.1.6.52, revised 2026-10-13); a new operation not listed
# here is a write, so it can never be sent to a read-only DC by mistake
READS = frozenset({"get_person", "is_fabric_admin", "list_host_groups", "list_machines", "list_people",
                   "list_sudo_rules", "logon_groups", "read_devices", "read_networks", "read_plan", "site_info"})


def run_op(v, secrets, op, args=None, container="samba", server=None):
    """Purpose: one directory operation (manual 1.6.3, 1.6.5.16), run inside the DC by src/containers/samba/
             directory_op.py, signed in as this site's fabric-agent account — so AD's per-site limits apply to every
             change fabric-agent makes (1.6.3.6). The request, the account's password included, goes on stdin.
    Inputs:  v — rendered vars (site_name); secrets — fabric's secrets (ad_agent_password); op — str, an operation
             of the DC's directory_ops; args — dict of its arguments (JSON-able); container — the DC's container;
             server — None or another DC's address to sign in at. None: a read (READS) at this site's DC; a write
             at this site's DC, or at a site whose DC is read-only at its writable DC (`samba/writable_server`, the
             one routing point for every directory write, 2.1.6.52).
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with a message safe to show: "that name is already taken", "no such entry", "the
             directory refused the change …", "the directory refused it: …" (e.g. a password the policy refuses),
             an operation's own refusal word for word (e.g. "no such user: …"), or "the directory is not reachable"
             when the DC is not running; for a write at a read-only DC's site, writable_server's refusal (no writable
             DC known) before anything is asked, or "the writable domain controller … does not answer" (nothing
             changed); KeyError without ad_agent_password; subprocess.TimeoutExpired after 60 s.
    Feeds:   fabriclib/directory/* (people, groups, devices, roles, networks)."""
    site = v["site_name"]
    if server is None and op not in READS:      # this site's DC may be read-only: a write goes where it can be made
        server = writable_server(v, f"make this change ({op.replace('_', ' ')}) at")
    request = {"op": op, "args": args or {}, "site": site, "account": f"fabric-agent-{site}",
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
        if kind == "unreachable":
            raise ValidationError(f"the writable domain controller {server} does not answer, so the change could not "
                                  "be made (this site's own domain controller is read-only); nothing was changed: "
                                  "try again when the link to it is up")
        raise ValidationError(MESSAGES.get(kind) or f"the directory refused it: {answer['error']}")
    return answer["result"]
