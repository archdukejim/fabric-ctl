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
from fabriclib.vault.ssh.constants import HOST_CAS_PUBLISHED, HOST_MOUNT, HOST_REVOKED, MOUNT, USER_CAS_PUBLISHED
from fabriclib.vault.ssh.host_principals import host_principals
from fabriclib.vault.ssh.org_ssh_trust import org_ssh_trust
from fabriclib.vault.ssh.parse_ssh_cert import parse_ssh_cert
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key
from fabriclib.vault.ssh.plan_host_certs import plan_host_certs
from fabriclib.vault.ssh.publish_ssh_ca import publish_ssh_ca
from fabriclib.vault.ssh.sign_ssh_host_key import sign_ssh_host_key
from fabriclib.vault.ssh.update_revoked_keys import update_revoked_keys

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


def _gone(certs, keys, name, now):
    """Purpose: the certificates of keys a machine no longer holds a certificate for, still valid: to revoke.
    Inputs:  certs — the certificate lines fabric withdraws or replaces; keys — the key lines the machine keeps (their
             certificates are not revoked); name — the machine's; now — int seconds.
    Returns: list of {"key", "until", "name"} (update_revoked_keys' entries).
    Fails:   never (a certificate that does not parse is left out).
    Feeds:   sign_ssh_hosts."""
    kept = set()
    for k in keys:
        try:
            kept.add(parse_ssh_key(k)["fingerprint"])
        except ValidationError:
            continue
    out = []
    for c in certs:
        try:
            p = parse_ssh_cert(c)
        except ValidationError:
            continue
        if p["key_fingerprint"] not in kept and p["valid_before"] > now:
            out.append({"key": p["key_line"], "until": p["valid_before"], "name": name})
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
                   sign=sign_ssh_host_key, apply=apply_host_ssh_cert, host_keys=HOST_KEYS, now=None,
                   publish=publish_ssh_ca):
    """Purpose: one run of SSH host certificates for the site (manual 1.6.11.9.8; decision 2.1.7.13). Off: only this
             host's own certificate and its trust of the host CA removed (the machines remove theirs on their own).
             On: each managed, enabled machine made able to publish its host keys (prepare_ssh_hosts); this host's
             own keys published on its account; every machine's published keys judged and signed by OpenBao's host
             CA where a certificate is missing, stale, about to run out (RENEW_DAYS) or names other principals, and
             written back to its account; a machine taken out of <site>-fabric-machines or disabled has its
             certificates withdrawn, and the key of every certificate withdrawn or replaced before its end (the
             machine no longer publishes that key) revoked until then (update_revoked_keys, published as
             HOST_REVOKED for every client's @revoked lines, 1.6.11.9.12); then this host's own certificate and
             its trust of the host CA applied
             (apply_host_ssh_cert) while the host is a managed member of its domain (as the `member` step's consent
             says, 1.6.11.11), removed otherwise. One machine's refusal never stops the others. Also (2.1.7.14,
             1.6.11.9.16): this site's user and host CA keys and domain written to AD (`set_ssh_cas`), every site's
             read back (`read_ssh_cas`) and what this site's machines trust published (org_ssh_trust:
             USER_CAS_PUBLISHED, HOST_CAS_PUBLISHED), the host's own known-hosts block from the same lines; a
             failure there is reported in "org_error" and leaves the last published lists as they are.
    Inputs:  v — rendered vars (ssh_certificates, site_name, ad_domain, domain, hostname, and what bao_request and
             run_op read); config_dir — the install's config folder (RECORD: the host's account); actor, source —
             the audit's; login, op, sign, apply, publish — approle_login, run_op (op(name, args); None: run_op
             with load_secrets(), which sends its writes to the writable DC at a site whose own is read-only and
             list_ssh_hosts, a read, to this site's own DC: 2.1.6.52), sign_ssh_host_key, apply_host_ssh_cert,
             publish_ssh_ca (tests pass their own); host_keys — the glob of this host's host public keys; now — int
             seconds since 1970 UTC (None: now).
    Returns: {"on": bool, "ca_fingerprint", "prepared": [names], "machines": [{"name", "signed", "kept" (ints),
             "refused": [why], "withdrawn": bool, "error": str}], "revoked": [key lines still revoked],
             "host": [what changed on this host], "org": {"host_cas", "user_cas"} (how many trusted; {} when off or
             not published), "org_error": "" or why the organisation's CAs could not be published}.
    Fails:   ValidationError: OpenBao locked or unreachable, the host CA not made (turn SSH certificates on again, or
             run the vault step), a read-only DC's site with no writable DC known (from run_op, at the first write,
             before anything is written), the directory unreachable (from run_op), sshd refusing (from
             apply_host_ssh_cert); OSError on this host's files or the audit log.
    Feeds:   samba/run_domain_command (`fabricctl domain ssh-hosts`, fabric-ssh-hosts.timer).
    Notes:   audited SSH_HOST_SIGN (each machine signed: its principals and serials), SSH_HOST_WITHDRAW and
             SSH_HOST_REVOKE."""
    if not v.get("ssh_certificates"):
        publish(v, "", USER_CAS_PUBLISHED)          # this site's machines trust no fabric CA while off (2.1.7.14)
        publish(v, "", HOST_CAS_PUBLISHED)
        return {"on": False, "ca_fingerprint": "", "prepared": [], "machines": [], "revoked": [],
                "host": apply(v, [], ""), "org": {}, "org_error": ""}
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
        op = lambda name, args: run_op(v, secrets, name, args)      # noqa: E731 (run_op routes: 2.1.6.52)
    domains = [v.get("ad_domain"), v.get("domain")]
    account = _account(config_dir)
    own_keys = _read_lines(host_keys)
    prepared = op("prepare_ssh_hosts", {})["prepared"]
    if account:
        op("set_ssh_host", {"name": account, "keys": own_keys})
    machines, host_certs, revoke, signed_keys = [], None, [], set()
    for h in op("list_ssh_hosts", {}):
        mine = bool(account) and h["name"] == str(account).rstrip("$").lower()
        row = {"name": h["name"], "signed": 0, "kept": 0, "refused": [], "withdrawn": False, "error": ""}
        try:
            if not h["managed"] or not h["enabled"]:
                if h["certs"]:
                    op("set_ssh_host", {"name": h["name"], "certs": []})
                    row["withdrawn"] = True
                    revoke += _gone(h["certs"], [], h["name"], now)
                    write_audit(actor, "SSH_HOST_WITHDRAW", f"{h['name']}: not managed or disabled", source)
                    machines.append(row)
                continue
            principals = host_principals(h["account"], domains)
            plan = plan_host_certs(h["keys"], h["certs"], principals, ca_fp, now)
            new = [sign(v, token, k, principals, f"fabric-host:{h['name']}:{stamp}") for k in plan["sign"]]
            certs = plan["keep"] + new
            if plan["changed"]:
                op("set_ssh_host", {"name": h["name"], "certs": certs})
                revoke += _gone(h["certs"], h["keys"], h["name"], now)
            signed_keys.update(plan["sign"])
            if new:
                write_audit(actor, "SSH_HOST_SIGN", f"{h['name']}: {len(new)} signed for {','.join(principals)}",
                            source)
            row.update(signed=len(new), kept=len(plan["keep"]), refused=[why for _, why in plan["refused"]])
            if mine:
                host_certs = certs
        except ValidationError as exc:
            row["error"] = str(exc)
        machines.append(row)
    for e in revoke:
        write_audit(actor, "SSH_HOST_REVOKE", f"{e['name']}: {parse_ssh_key(e['key'])['fingerprint']} until "
                                              f"{datetime.datetime.fromtimestamp(e['until'], datetime.timezone.utc)}",
                    source)
    revoked = update_revoked_keys(config_dir, revoke, signed_keys, now)
    publish(v, "\n".join(revoked), HOST_REVOKED)        # none: withdrawn, so clients drop their @revoked lines
    org, org_error, org_lines = {}, "", None
    try:                    # the organisation's CAs (2.1.7.14): ours into AD, everyone's back, our machines' trust
        status, data = bao_request(v, "GET", f"{MOUNT}/config/ca", token=token)
        user_ca = ((data.get("data") or {}).get("public_key") or "").strip() if status == 200 else ""
        op("set_ssh_cas", {"user_ca": user_ca, "host_ca": ca, "domain": v.get("domain") or ""})
        trust = org_ssh_trust(v, user_ca, ca, op("read_ssh_cas", {})["sites"])
        publish(v, "\n".join(trust["user_cas"]), USER_CAS_PUBLISHED)
        publish(v, "\n".join(trust["known"]), HOST_CAS_PUBLISHED)
        org, org_lines = {"host_cas": len(trust["known"]) - 1, "user_cas": len(trust["user_cas"])}, trust["known"]
    except ValidationError as exc:
        org_error = f"the organisation's SSH CAs were not published (the last lists stay): {exc}"
    # this host's own part only while it is a managed member (the `member` step's consent, 1.2.9.3): else removed
    return {"on": True, "ca_fingerprint": ca_fp, "prepared": prepared, "machines": machines, "revoked": revoked,
            "host": (apply(v, host_certs, ca, revoked, org_lines=org_lines) if host_certs is not None
                     else apply(v, [], "")), "org": org, "org_error": org_error}
