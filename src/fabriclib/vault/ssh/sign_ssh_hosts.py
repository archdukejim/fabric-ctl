import datetime
import glob
import json
import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.consent.plan_member import RECORD
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.constants import SETUP_CREDS
from fabriclib.vault.ssh.apply_host_ssh_cert import apply_host_ssh_cert
from fabriclib.vault.ssh.constants import HOST_MOUNT
from fabriclib.vault.ssh.host_principals import host_principals
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key
from fabriclib.vault.ssh.plan_host_certs import plan_host_certs
from fabriclib.vault.ssh.sign_ssh_host_key import sign_ssh_host_key

HOST_KEYS = "/etc/ssh/ssh_host_*_key.pub"


def _read_lines(pattern):
    """Purpose: the first line of each file matching a pattern (this host's host public keys).
    Inputs:  pattern — a glob.
    Returns: list of str, sorted by file name; DSA keys left out.
    Fails:   never (an unreadable file is left out).
    Feeds:   sign_ssh_hosts."""
    out = []
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as f:
                line = " ".join(f.readline().split()[:2])
        except OSError:
            continue
        if line and not line.startswith("ssh-dss"):
            out.append(line)
    return out


def _account(config_dir):
    """Purpose: this fabric host's own computer account, as the `member` step recorded it (manual 1.6.11.8).
    Inputs:  config_dir — the install's config folder.
    Returns: the account name (str) or None when the host is not a member of its domain.
    Fails:   never (an unreadable record counts as not a member).
    Feeds:   sign_ssh_hosts."""
    try:
        with open(os.path.join(config_dir, RECORD)) as f:
            return json.load(f).get("account") or None
    except (OSError, ValueError):
        return None


def sign_ssh_hosts(v, config_dir, actor="fabric", source="timer", login=approle_login, op=None,
                   sign=sign_ssh_host_key, apply=apply_host_ssh_cert, host_keys=HOST_KEYS, now=None):
    """Purpose: one run of SSH host certificates for the site (manual 1.6.11.9.8; decision 2.1.7.13). Off: only this
             host's own certificate and its trust of the host CA removed (the machines remove theirs on their own).
             On: each managed, enabled machine made able to publish its host keys (prepare_ssh_hosts); this host's
             own keys published on its account; every machine's published keys judged and signed by OpenBao's host
             CA where a certificate is missing, stale, about to run out (RENEW_DAYS) or names other principals, and
             written back to its account; a machine taken out of <site>-fabric-machines or disabled has its
             certificates withdrawn; then this host's own certificate and its trust of the host CA applied
             (apply_host_ssh_cert) while the host is a managed member of its domain (as the `member` step's consent
             says, 1.6.11.11), removed otherwise. One machine's refusal never stops the others.
    Inputs:  v — rendered vars (ssh_certificates, site_name, ad_domain, domain, hostname, and what bao_request and
             run_op read); config_dir — the install's config folder (RECORD: the host's account); actor, source —
             the audit's; login, op, sign, apply — approle_login, run_op (op(name, args); None: run_op with
             load_secrets()), sign_ssh_host_key, apply_host_ssh_cert (tests pass their own); host_keys — the glob of
             this host's host public keys; now — int seconds since 1970 UTC (None: now).
    Returns: {"on": bool, "ca_fingerprint", "prepared": [names], "machines": [{"name", "signed", "kept" (ints),
             "refused": [why], "withdrawn": bool, "error": str}], "host": [what changed on this host]}.
    Fails:   ValidationError: OpenBao locked or unreachable, the host CA not made (turn SSH certificates on again, or
             run the vault step), the directory unreachable (from run_op), sshd refusing (from apply_host_ssh_cert);
             OSError on this host's files or the audit log.
    Feeds:   samba/run_domain_command (`fabricctl domain ssh-hosts`, fabric-ssh-hosts.timer).
    Notes:   audited SSH_HOST_SIGN (each machine signed: its principals and serials) and SSH_HOST_WITHDRAW."""
    if not v.get("ssh_certificates"):
        return {"on": False, "ca_fingerprint": "", "prepared": [], "machines": [], "host": apply(v, [], "")}
    now = int(now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp())
    stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    token = login(v, SETUP_CREDS)
    status, data = bao_request(v, "GET", f"{HOST_MOUNT}/config/ca", token=token)
    ca = ((data.get("data") or {}).get("public_key") or "").strip() if status == 200 else ""
    if not ca:
        raise ValidationError("OpenBao has no SSH host CA: turn SSH certificates off and on again (web console, SSH), "
                              "or run `sudo fabricctl setup --step vault`")
    ca_fp = parse_ssh_key(ca)["fingerprint"]
    if op is None:
        secrets = load_secrets()
        op = lambda name, args: run_op(v, secrets, name, args)      # noqa: E731
    domains = [v.get("ad_domain"), v.get("domain")]
    account = _account(config_dir)
    own_keys = _read_lines(host_keys)
    prepared = op("prepare_ssh_hosts", {})["prepared"]
    if account:
        op("set_ssh_host", {"name": account, "keys": own_keys})
    machines, host_certs = [], None
    for h in op("list_ssh_hosts", {}):
        mine = bool(account) and h["name"] == str(account).rstrip("$").lower()
        row = {"name": h["name"], "signed": 0, "kept": 0, "refused": [], "withdrawn": False, "error": ""}
        try:
            if not h["managed"] or not h["enabled"]:
                if h["certs"]:
                    op("set_ssh_host", {"name": h["name"], "certs": []})
                    row["withdrawn"] = True
                    write_audit(actor, "SSH_HOST_WITHDRAW", f"{h['name']}: not managed or disabled", source)
                    machines.append(row)
                continue
            principals = host_principals(h["account"], domains)
            plan = plan_host_certs(h["keys"], h["certs"], principals, ca_fp, now)
            new = [sign(v, token, k, principals, f"fabric-host:{h['name']}:{stamp}") for k in plan["sign"]]
            certs = plan["keep"] + new
            if plan["changed"]:
                op("set_ssh_host", {"name": h["name"], "certs": certs})
            if new:
                write_audit(actor, "SSH_HOST_SIGN", f"{h['name']}: {len(new)} signed for {','.join(principals)}",
                            source)
            row.update(signed=len(new), kept=len(plan["keep"]), refused=[why for _, why in plan["refused"]])
            if mine:
                host_certs = certs
        except ValidationError as exc:
            row["error"] = str(exc)
        machines.append(row)
    # this host's own part only while it is a managed member (the `member` step's consent, 1.2.9.3): else removed
    return {"on": True, "ca_fingerprint": ca_fp, "prepared": prepared, "machines": machines,
            "host": apply(v, host_certs, ca) if host_certs is not None else apply(v, [], "")}
