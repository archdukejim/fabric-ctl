import base64
import datetime
import json
import os
import subprocess
import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.directory.run_op import run_op
from fabriclib.federation.common.post_upstream import post_upstream
from fabriclib.federation.constants import DC_TYPE_PREFIX, DC_TYPE_RECORD
from fabriclib.federation.plan_dc_type_change import plan_dc_type_change
from fabriclib.pki.common.ca_files import ca_files
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.samba.replication_healthy import replication_healthy
from fabriclib.samba.replication_status import replication_status
from fabriclib.samba.writable_server import writable_server
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets


def _decode_token(text):
    """Purpose: a change token as `request_dc_type` made it.
    Inputs:  text — "fabric-dctype-1.<base64url JSON>" (spaces and line breaks ignored).
    Returns: dict with id, secret, site, to, by, host, address, root_sha256, expires.
    Fails:   ValidationError "this is not a DC type change token" for anything else.
    Feeds:   change_dc_type."""
    text = "".join(str(text or "").split())
    try:
        if not text.startswith(DC_TYPE_PREFIX):
            raise ValueError
        raw = text[len(DC_TYPE_PREFIX):]
        body = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if not all(isinstance(body.get(k), str) and body[k] for k in ("id", "secret", "site", "to", "host",
                                                                       "address")):
            raise ValueError
        return body
    except (ValueError, TypeError):
        raise ValidationError("this is not a DC type change token (fabric-dctype-1.…)") from None


def _docker(args, stdin=None):
    """Purpose: one docker command, its output kept.
    Inputs:  args — list after "docker"; stdin — str or None.
    Returns: subprocess.CompletedProcess.
    Fails:   OSError when docker is missing; subprocess.TimeoutExpired after 10 minutes.
    Feeds:   change_dc_type (the default runner)."""
    return subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, timeout=600)


def _setup():
    """Purpose: run fabric's setup unattended, as `fabricctl setup --yes`: the DC joins (no provisioned data, a join
             account in the secrets) and the join account goes afterwards (setup/start_services).
    Inputs:  none.
    Returns: (bool ok, str output tail).
    Fails:   OSError.
    Feeds:   change_dc_type (the default)."""
    cli = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cli.py")
    res = subprocess.run([sys.executable, cli, "setup", "--yes"], capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr)[-2000:]


def _fsmo(docker, container):
    """Purpose: the FSMO roles this DC holds (`samba-tool fsmo show`: a line per role naming its owner's NTDS
             settings, which names the DC).
    Inputs:  docker — the runner; container — the DC's.
    Returns: list of role names held here; [] when it cannot be asked (the demote itself then refuses).
    Fails:   never.
    Feeds:   change_dc_type."""
    res = docker(["exec", container, "samba-tool", "fsmo", "show"])
    if res.returncode != 0:
        return []
    host = docker(["exec", container, "hostname", "-s"]).stdout.strip().lower()
    held = []
    for line in res.stdout.splitlines():
        role, _, owner = line.partition(" owner: ")
        if host and f"cn={host}," in owner.lower():
            held.append(role.strip())
    return held


def _record(config_dir):
    """Purpose: the change's record: which steps are done (never a password).
    Inputs:  config_dir — the install's config folder.
    Returns: dict {"id", "to", "done": [steps], "writable", "set_aside"}; {} when there is none.
    Fails:   never (an unreadable record counts as none).
    Feeds:   change_dc_type."""
    try:
        with open(os.path.join(config_dir, DC_TYPE_RECORD)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_record(config_dir, record):
    """Purpose: write the change's record (root, 0600).
    Inputs:  config_dir; record — dict.
    Returns: None.
    Fails:   OSError.
    Feeds:   change_dc_type."""
    write_file_if_changed(os.path.join(config_dir, DC_TYPE_RECORD), json.dumps(record, indent=1) + "\n", 0o600)


def change_dc_type(v, config_dir, actor, token_text=None, consent=None, show=print, op=None, post=post_upstream,
                   docker=_docker, setup=_setup, replication=None, load=load_secrets, save=save_secrets,
                   vars_io=None, container="samba", now=None):
    """Purpose: at a site, carry out the DC type change a site above requested (decision 2.1.9.23, manual
             1.9.8.22.2): the plan shown, consent asked, then each step not yet done (plan_dc_type_change): the token
             redeemed for a join account, the DC demoted at a writable DC, its leftover account deleted, its data set
             aside, the DC joined again with the new type under the same name (setup), the request removed. Each step
             is recorded when done, so a second run goes on from the first not done; a site already of the type only
             has its request removed.
    Inputs:  v — fabric vars (site_name, dc_name, ad_dc_type, ad_domain, ad_base_dn, ad_netbios, deploy_base_dir and
             what run_op and writable_server read); config_dir — the install's config folder; actor — who (audit);
             token_text — the change token (None: only the plan is returned, nothing changes); consent — callable
             (plan lines) -> bool, asked before anything changes (None: no consent, refused); show — callable(str) for
             progress; op, post, docker, setup, replication, load, save — run_op, post_upstream, the docker runner,
             the unattended setup, replication_status()'s answer, fabric's secrets (tests pass their own); vars_io —
             (load, save) for the settings (default: load_vars, save_vars under vars_lock); container — the DC's;
             now — datetime (tests).
    Returns: {"plan": plan_dc_type_change's answer, "done": [steps done in this run], "changed": bool}.
    Fails:   ValidationError: the plan's refusal (nothing changed); no consent (nothing changed); a step's failure,
             naming it (the steps before it are recorded as done; run again once fixed).
    Feeds:   run_federation_command (`fabricctl federation dc-type show|accept`).
    Notes:   audited FED_DC_TYPE_STEP per step and FED_DC_TYPE_CHANGED at the end; refusals FED_DC_TYPE_REFUSED."""
    me = v["site_name"]
    if op is None:
        stored = load(v=v)
        op = lambda name, args: run_op(v, stored, name, args, container)      # noqa: E731
    pending = op("read_dc_type_request", {}).get("request")
    record = _record(config_dir)
    if pending and record.get("id") not in (None, pending.get("id")):
        record = {}                           # an older change's record: a new request starts afresh
    done = list(record.get("done") or [])
    token = None
    if token_text is not None:
        token = _decode_token(token_text)
        root = ca_files(v)[0]
        token["root_ok"] = bool(token.get("root_sha256")) and os.path.exists(root) and \
            describe_cert(open(root).read())["sha256"].upper() == token["root_sha256"].upper()
    try:
        server = writable_server({**v, "ad_dc_type": "rodc"}, "change this site's DC type at")
        if server and server.lower() in (str(v.get("hostname_dc") or "").lower(), str(v.get("host_ip") or "")):
            server, why = None, "the only writable DC listed is this site's own: list another (ad_writable_servers)"
        else:
            why = ""
    except ValidationError as e:                      # the list is asked as a read-only DC's site would: said plainly
        server, why = None, str(e).replace("this site's domain controller is read-only and ", "")
    healthy = replication_healthy(replication_status(container) if replication is None else replication, now=now)
    fsmo = _fsmo(docker, container) if (pending or {}).get("to") == "rodc" and "demote" not in done else []
    plan = plan_dc_type_change(v, pending, token, (record.get("writable") or server, why), healthy, fsmo, done)
    result = {"plan": plan, "done": [], "changed": False}
    if plan["refused"]:
        write_audit(actor, "FED_DC_TYPE_REFUSED", f"site={me}: {plan['refused']}", "cli")
        raise ValidationError(plan["refused"])
    if token_text is None:
        return result
    if consent is None or not consent(plan["lines"]):
        raise ValidationError("not confirmed: nothing was changed")
    to, writable = plan["to"], record.get("writable") or server
    record.update({"id": pending["id"], "to": to, "writable": writable, "done": done})
    base = os.path.join(v["deploy_base_dir"], "samba")
    auth = os.path.join(base, "secrets", "join.auth")

    def step(name, fn):
        if name not in plan["steps"]:
            return
        show(f"{name}: {fn.__doc__}")
        fn()
        done.append(name)
        result["done"].append(name)
        result["changed"] = True
        _save_record(config_dir, record)
        write_audit(actor, "FED_DC_TYPE_STEP", f"site={me} to={to} step={name}", "cli")

    def redeem():
        """the change token redeemed for the join account"""
        answer = post(token["address"], token["host"], open(ca_files(v)[0]).read(), "/v1/dc-type",
                      {"id": token["id"], "secret": token["secret"], "site": me, "to": to})
        save({"ad_join": {"user": answer["join_user"], "password": answer["join_password"]}}, v=v)
        write_file_if_changed(auth, f"username={answer['join_user']}\npassword={answer['join_password']}\n"
                                    f"domain={v['ad_netbios']}\n", 0o600)
        record["dc_host"], record["dc_address"] = answer.get("dc_host", ""), answer.get("dc_address", "")

    def demote():
        """this DC demoted at the writable DC"""
        res = docker(["exec", container, "samba-tool", "domain", "demote", f"--server={writable}",
                      "-A", "/run/secrets/join.auth"])
        if res.returncode != 0:
            raise ValidationError(f"the demote at {writable} failed: {(res.stderr or res.stdout).strip()[-300:]}")

    def leftover():
        """the demoted DC's leftover account deleted"""
        dn = f"CN={v['dc_name'].upper()},CN=Computers,{v['ad_base_dn']}"
        res = docker(["exec", container, "ldbdel", "-H", f"ldap://{writable}", "-A", "/run/secrets/join.auth",
                      "--use-kerberos=off", dn])
        if res.returncode != 0 and "No such object" not in (res.stderr + res.stdout) \
                and "32" not in (res.stderr + res.stdout):
            raise ValidationError(f"the leftover account {dn} could not be deleted at {writable}: "
                                  f"{(res.stderr or res.stdout).strip()[-300:]}")

    def set_aside():
        """the DC stopped and its data set aside"""
        docker(["stop", container])
        stamp = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
        data, kept = os.path.join(base, "data"), os.path.join(base, f"data.before-dc-type-{stamp}")
        if os.path.isdir(data):
            os.replace(data, kept)
            os.chmod(kept, 0o700)
        record["set_aside"] = kept

    def join():
        """joined again with the new type under the same name"""
        load_v, save_v = vars_io or (load_vars, save_vars)
        with vars_lock():
            data = load_v()
            data["ad_dc_type"] = to
            if not data.get("ad_join_server"):
                data["ad_join_server"] = record.get("dc_address") or writable
                data["ad_join_server_name"] = record.get("dc_host") or writable
            save_v(data)
        ok, output = setup()
        if not ok:
            raise ValidationError(f"setup did not finish the join: {output[-600:]}")

    def finish():
        """the request removed from the domain"""
        op("set_dc_type_request", {"target": me, "request": None})

    step("token", redeem)
    step("demote", demote)
    step("leftover", leftover)
    step("set_aside", set_aside)
    step("join", join)
    step("done", finish)
    write_audit(actor, "FED_DC_TYPE_CHANGED", f"site={me} to={to} steps={','.join(result['done'])}", "cli")
    return result
