#!/usr/bin/env python3
"""The fabric host's local-admin, set and kept by OpenBao (manual 1.7.1.4; decisions 2.1.7.16 to 2.1.7.20), against the
real pinned OpenBao image on a private test network, configured by fabric's own configure_openbao (so every call goes
as fabric-setup, with its real policy). The host's side is stood in for: useradd, chpasswd and userdel record what they
are given, the journal is a list of JSON lines and wtmp a file of real utmp records, the clock is the test's; the
sandbox runs them on a real host.

- setup: the mount `local-admin/` (10 versions) and the password policy, the account made, a first password of the
  policy kept in OpenBao and marked current only once the host took it; converging changes nothing; an account of
  that name fabric did not make refused, nothing changed
- a use seen (journal and wtmp, local-admin's only, since the password was set), audited; rotated only once the
  grace has passed, the new password set and current, the old one never again; a host refusing the new password: the
  old one stays current
- check-out: a reason required (one line, 200 characters), the current password, audited without it, marked for
  rotation; then rotated after the grace
- the policy: after-use / keep-until-checkout kept with the password and on the host, an unknown one refused;
  keep-until-checkout keeps the password while nothing uses or checks it out
- OpenBao sealed: the rotation due waits (the used password stays current, doctor's warning says so), a check-out is
  refused; unsealed, the next run rotates it
- the undo: the account removed, OpenBao's versions kept and marked removed, the record gone
- the SSH drop-in (2.1.7.19): off refuses local-admin, on lets its password in, idempotent, sshd's refusal put back,
  a file that is not fabric's left alone
- the SSH switch's alert (2.1.7.21): raised while on, acknowledged (audited, kept with the switch) it is no longer
  raised while the relaxation still shows the switch on; raised again once turned off and on

    sudo python3 tests/openbao/local_admin.py          (needs Docker, openssl, root)
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.localadmin.apply_local_admin_ssh import apply_local_admin_ssh  # noqa: E402
from fabriclib.localadmin.check_local_admin import check_local_admin  # noqa: E402
from fabriclib.localadmin.checkout_local_admin import checkout_local_admin  # noqa: E402
from fabriclib.localadmin.common.local_admin_token import local_admin_token  # noqa: E402
from fabriclib.localadmin.constants import DIGITS, LOWER, UPPER  # noqa: E402
from fabriclib.localadmin.ensure_local_admin import ensure_local_admin  # noqa: E402
from fabriclib.localadmin.find_local_admin_uses import UTMP, find_local_admin_uses  # noqa: E402
from fabriclib.localadmin.local_admin_checks import local_admin_checks  # noqa: E402
from fabriclib.localadmin.read_local_admin_secret import read_local_admin_secret  # noqa: E402
from fabriclib.localadmin.record import load_record  # noqa: E402
from fabriclib.localadmin.remove_local_admin import remove_local_admin  # noqa: E402
from fabriclib.localadmin.set_local_admin_policy import set_local_admin_policy  # noqa: E402
from fabriclib.vault.common.approle_login import approle_login  # noqa: E402
from fabriclib.vault.common.bao_request import bao_request  # noqa: E402
from fabriclib.vault.configure_openbao import configure_openbao  # noqa: E402

W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/localadmin"
NET, SUBNET, BAO_IP = "localadmin_net", "10.254.46.0/24", "10.254.46.90"
BAO, HOST = "localadmin-bao", "vault.lan.test"
FAILED = 0
AUDIT = []
SET = []                                        # (user, password) chpasswd was given
T0 = datetime.datetime(2026, 10, 22, 8, 0, tzinfo=datetime.timezone.utc)
CLOCK = {"now": T0}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:500]}"), flush=True)


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"failed: {cmd}\n{res.stdout}{res.stderr}")
    return res


def cleanup():
    sh(["docker", "rm", "-f", BAO], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def audit(actor, action, detail, source="cli", path=None):
    AUDIT.append((actor, action, detail, source))


def now():
    return CLOCK["now"]


def chpasswd(user, password):
    SET.append((user, password))


def refused(fn):
    try:
        fn()
        return ""
    except ValidationError as e:
        return str(e) or "refused"


def at(hours):
    CLOCK["now"] = T0 + datetime.timedelta(hours=hours)
    return CLOCK["now"]


cleanup()
shutil.rmtree(W, ignore_errors=True)
certs, CFG = os.path.join(W, "certs"), os.path.join(W, "config-install")
os.makedirs(certs)
os.makedirs(CFG)
os.makedirs(os.path.join(W, "keys"))
os.chdir(certs)
sh("openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root_ca.crt -days 2 -subj '/CN=Test Root' "
   "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign")
sh(f"openssl req -newkey rsa:2048 -nodes -keyout bao.key -out bao.csr -subj '/CN={HOST}'")
with open("bao.ext", "w") as f:
    f.write(f"subjectAltName=DNS:{HOST}\nextendedKeyUsage=serverAuth\n")
sh("openssl x509 -req -in bao.csr -CA root_ca.crt -CAkey root.key -CAcreateserial -out bao.crt -days 2 -extfile bao.ext")
sh(["chmod", "644", "bao.key"])
os.makedirs(os.path.join(W, "config"))
with open(os.path.join(W, "config", "test.hcl"), "w") as f:
    f.write('storage "inmem" {}\ndisable_mlock = true\nui = false\n'
            'listener "tcp" {\n  address = "0.0.0.0:8200"\n  tls_cert_file = "/openbao/certs/bao.crt"\n'
            '  tls_key_file = "/openbao/certs/bao.key"\n}\n')
lock = read_images_lock(os.path.join(REPO, "config"))
sh(["docker", "network", "create", "--subnet", SUBNET, NET])
sh(["docker", "run", "-d", "--name", BAO, "--network", NET, "--ip", BAO_IP, "--entrypoint", "bao",
    "-v", f"{certs}:/openbao/certs:ro", "-v", f"{W}/config:/openbao/config:ro", lock["openbao"]["ref"],
    "server", "-config=/openbao/config/test.hcl"])
V = {"ip_openbao": BAO_IP, "hostname_openbao": HOST, "openbao_ca_file": os.path.join(certs, "root_ca.crt"),
     "deploy_base_dir": W, "openbao_key_dir": os.path.join(W, "keys"), "fabric_subnet": SUBNET,
     "site_name": "lan", "hostname": "fabric", "dc_name": "dc-0001"}
for _ in range(30):
    try:
        if bao_request(V, "GET", "sys/health")[0] in (200, 429, 501, 503):
            break
    except ValidationError:
        pass
    time.sleep(1)
init = bao_request(V, "POST", "sys/init", body={"secret_shares": 1, "secret_threshold": 1})[1]
UNSEAL, ROOT = init["keys"][0], init["root_token"]
bao_request(V, "POST", "sys/unseal", body={"key": UNSEAL})
configure_openbao(V, ROOT)
token, why = local_admin_token(V)
check("OpenBao up and configured by fabric: a fabric-setup token (the real AppRole and policy)", token and not why, why)
PATH = "lan/fabric-host/fabric/local-admin"
NOT_THERE = {"exists": False}
ensure = dict(useradd=lambda group: NOT_THERE.update(exists=True, group=group), set_password=chpasswd,
              exists=lambda: NOT_THERE["exists"], audit=audit, now=now)

print("--- setup: the account and its first password (1.7.1.4.1, 1.7.1.4.2)")
done = ensure_local_admin(V, CFG, token, **ensure)
rec = load_record(CFG)
held = read_local_admin_secret(V, token, password=True)
mounts = bao_request(V, "GET", "sys/mounts", token=ROOT)[1]
conf = bao_request(V, "GET", "local-admin/config", token=ROOT)[1]["data"]
check("the KV v2 mount local-admin/ of its own (10 versions kept) and the password policy local-admin",
      mounts.get("local-admin/", {}).get("options", {}).get("version") == "2" and conf["max_versions"] == 10
      and bao_request(V, "GET", "sys/policies/password/local-admin", token=ROOT)[0] == 200, conf)
check("the account made in sudo (or wheel), recorded as fabric's; its first password set and current (version 1)",
      NOT_THERE.get("group") in ("sudo", "wheel") and rec["made"] and rec["version"] == 1 and held["current"] == 1
      and SET == [("local-admin", held["password"])] and rec["reason"] == "initial", (rec, held["current"], done))
pw1 = held["password"]
check("the password is the policy's: 24 characters, upper, lower and digits, nothing easily misread",
      len(pw1) == 24 and set(pw1) <= set(UPPER + LOWER + DIGITS) and any(c in UPPER for c in pw1)
      and any(c in LOWER for c in pw1) and any(c in DIGITS for c in pw1) and not set(pw1) & set("0O1lI"), pw1)
data = bao_request(V, "GET", f"local-admin/data/{PATH}", token=ROOT)[1]["data"]["data"]
check("its version says when, why and where: set_on, reason initial, host",
      data["reason"] == "initial" and data["host"] == "fabric" and data["set_on"] == T0.isoformat(), data)
check("audited LOCAL_ADMIN_INITIAL, never the password",
      AUDIT[-1][1] == "LOCAL_ADMIN_INITIAL" and pw1 not in json.dumps(AUDIT), AUDIT[-1:])
check("the record holds no password", pw1 not in open(os.path.join(CFG, "local-admin.json")).read())
check("converging again changes nothing (no new password)", ensure_local_admin(V, CFG, token, **ensure) == []
      and len(SET) == 1)
other = os.path.join(W, "config-other")
os.makedirs(other)
msg = refused(lambda: ensure_local_admin(V, other, token, **{**ensure, "exists": lambda: True}))
check("negative: an account local-admin fabric did not make is refused, saying so; nothing changed",
      "fabric did not make" in msg and not load_record(other)["made"] and len(SET) == 1, msg)
check("fabric-agent's AppRole cannot read it (only fabric-setup's policy reaches local-admin/)",
      bao_request(V, "GET", f"local-admin/data/{PATH}",
                  token=approle_login(V, "agent-approle.json"))[0] == 403)

print("--- a use, and the rotation after it (1.7.1.4.4)")
JOURNAL = []
calls = []


def journal_run(cmd, **kw):
    calls.append(cmd)
    return subprocess.CompletedProcess(cmd, 0, "\n".join(JOURNAL), "")


WTMP = os.path.join(W, "wtmp")


def wtmp_entry(user, when, line="tty1", host=""):
    return UTMP.pack(7, 1234, line.encode(), b"t1", user.encode(), host.encode(), 0, 0, 0, int(when.timestamp()), 0,
                     b"", b"")


with open(WTMP, "wb") as f:
    f.write(wtmp_entry("localop", T0 + datetime.timedelta(minutes=5)))
    f.write(wtmp_entry("local-admin", T0 - datetime.timedelta(hours=1)))       # before this password
JOURNAL.append(json.dumps({"MESSAGE": "pam_unix(sshd:session): session opened for user localop(uid=1001) by (uid=0)",
                           "__REALTIME_TIMESTAMP": str(int((T0 + datetime.timedelta(minutes=6)).timestamp() * 1e6))}))
find = lambda since: find_local_admin_uses(since, run=journal_run, wtmp=WTMP)    # noqa: E731
check("no use of local-admin since its password was set: another account's sign-ins and its own older one ignored",
      find(T0) == [] and "--since=@" + str(int(T0.timestamp())) in " ".join(calls[-1]), calls[-1:])
switch = {"ssh": False, "by": None, "when": None}
SSH = []
parts = dict(find_uses=find, token_fn=local_admin_token, set_password=chpasswd, read_switch=lambda v: switch,
             apply_ssh=lambda on, remove=False: SSH.append(on) or [], audit=audit, now=now)
at(1)
out = check_local_admin(V, CFG, **parts)
check("a run with no use changes nothing but applies SSH off and records the run",
      out["ok"] and len(SET) == 1 and SSH == [False] and load_record(CFG)["last_check"]["ok"], out)
JOURNAL.append(json.dumps({"MESSAGE": "pam_unix(login:session): session opened for user local-admin(uid=1002) by "
                           "LOGIN(uid=0)", "SYSLOG_IDENTIFIER": "login",
                           "__REALTIME_TIMESTAMP": str(int((T0 + datetime.timedelta(hours=2)).timestamp() * 1e6))}))
with open(WTMP, "ab") as f:
    f.write(wtmp_entry("local-admin", T0 + datetime.timedelta(hours=3), "pts/0", "10.0.0.9"))
uses = find(T0)
check("its sign-ins found in the journal (PAM's session line) and wtmp, the earliest first",
      len(uses) == 2 and uses[0][0] == T0 + datetime.timedelta(hours=2) and "login" in uses[0][1]
      and "from 10.0.0.9" in uses[1][1], uses)
at(4)
out = check_local_admin(V, CFG, **parts)
rec = load_record(CFG)
check("the timer marks the password used (when, how), audited LOCAL_ADMIN_USED; not rotated within the grace",
      rec["used"]["when"] == (T0 + datetime.timedelta(hours=2)).isoformat() and AUDIT[-1][1] == "LOCAL_ADMIN_USED"
      and len(SET) == 1 and rec["version"] == 1, (rec, out))
at(9)
check("…still not at 9 hours from the password (7 from the use)", check_local_admin(V, CFG, **parts)["ok"]
      and len(SET) == 1)
at(10.5)
out = check_local_admin(V, CFG, **parts)
rec, held = load_record(CFG), read_local_admin_secret(V, token, password=True)
check("8 hours after the use: a new password (version 2) set on the host and current; the record cleared",
      len(SET) == 2 and SET[-1][1] == held["password"] != pw1 and held["current"] == 2 and rec["version"] == 2
      and rec["used"] is None and rec["reason"] == "after use", (out, rec))
check("…audited LOCAL_ADMIN_ROTATE (after use, used), never a password",
      AUDIT[-1][1] == "LOCAL_ADMIN_ROTATE" and "used" in AUDIT[-1][2] and held["password"] not in json.dumps(AUDIT))
check("…OpenBao keeps the old version as history, its reason after use",
      bao_request(V, "GET", f"local-admin/data/{PATH}?version=1", token=ROOT)[1]["data"]["data"]["password"] == pw1
      and bao_request(V, "GET", f"local-admin/data/{PATH}", token=ROOT)[1]["data"]["data"]["reason"] == "after use")
pw2 = held["password"]
at(11)
check("the uses before the new password count no more", check_local_admin(V, CFG, **parts)["ok"]
      and load_record(CFG)["used"] is None and len(SET) == 2)


def refuse_password(user, password):
    raise ValidationError("chpasswd: Authentication token manipulation error")


JOURNAL.append(json.dumps({"MESSAGE": "pam_unix(sudo:session): session opened for user root(uid=0) by local-admin("
                           "uid=1002)", "__REALTIME_TIMESTAMP": str(int(at(12).timestamp() * 1e6))}))
check_local_admin(V, CFG, **parts)
at(21)
out = check_local_admin(V, CFG, **{**parts, "set_password": refuse_password})
held = read_local_admin_secret(V, token)
check("negative: a host refusing the new password: the run fails, said; the old password stays current (version 2)",
      not out["ok"] and "did not take" in " ".join(out["lines"]) and held["current"] == 2
      and load_record(CFG)["version"] == 2 and not load_record(CFG)["last_check"]["ok"], (out, held))
check("…doctor warns of the failed run",
      any("hourly check failed" in w for w in local_admin_checks(V, CFG, True, secret=read_local_admin_secret)[
          "warnings"]))
out = check_local_admin(V, CFG, **parts)
held = read_local_admin_secret(V, token, password=True)
check("…the next run rotates it (sudo by local-admin counted as a use)", out["ok"] and held["current"] == 4
      and SET[-1][1] == held["password"] and load_record(CFG)["version"] == 4, (out, held["current"]))
check("doctor: the account's current version is the host's", local_admin_checks(
    V, CFG, True, exists=lambda: True)["checks"][0][1])

print("--- check-out (1.7.1.4.5)")
kw = dict(token_fn=local_admin_token, audit=audit, now=now)
for bad, why in (("", "needs a reason"), ("a\nb", "one line"), ("x" * 201, "one line")):
    msg = refused(lambda: checkout_local_admin(V, CFG, None, "root", bad, **kw))
    check(f"negative: a check-out with {why!r} is refused, nothing recorded", why in msg
          and load_record(CFG)["checkout"] is None, msg)
NOT_THERE["exists"] = True
import fabriclib.localadmin.checkout_local_admin as m_co  # noqa: E402
m_co.account_exists = lambda name="local-admin": NOT_THERE["exists"]
at(30)
out = checkout_local_admin(V, CFG, None, "pat", "the DC host does not boot", **kw)
rec = load_record(CFG)
check("checked out by root (for the Enterprise Admin): the current password, its version, when it rotates",
      out["password"] == SET[-1][1] and out["version"] == 4 and out["rotates_after"] == at(38).isoformat()
      and rec["checkout"]["by"] == "pat" and rec["checkout"]["reason"] == "the DC host does not boot", out)
check("…audited LOCAL_ADMIN_CHECKOUT with the reason, never the password",
      AUDIT[-1][1] == "LOCAL_ADMIN_CHECKOUT" and "does not boot" in AUDIT[-1][2] and out["password"] not in
      json.dumps(AUDIT), AUDIT[-1:])
at(37.9)
check_local_admin(V, CFG, **parts)
check("…not rotated within the grace", read_local_admin_secret(V, token)["current"] == 4)
at(38)
check_local_admin(V, CFG, **parts)
check("…rotated 8 hours after the check-out (no sign-in needed), the check-out cleared",
      read_local_admin_secret(V, token)["current"] == 5 and load_record(CFG)["checkout"] is None
      and "checked out" in AUDIT[-1][2])
NOT_THERE["exists"] = False
msg = refused(lambda: checkout_local_admin(V, CFG, None, "root", "why", **kw))
check("negative: no local-admin on the host: a check-out is refused", "no local-admin" in msg, msg)
NOT_THERE["exists"] = True

print("--- the policy (1.7.1.4.3)")
msg = refused(lambda: set_local_admin_policy(V, CFG, "yearly", "root", audit=audit))
check("negative: an unknown policy is refused, naming the two", "after-use" in msg and "keep-until-checkout" in msg)
out = set_local_admin_policy(V, CFG, "keep-until-checkout", "root", audit=audit)
meta = bao_request(V, "GET", f"local-admin/metadata/{PATH}", token=ROOT)[1]["data"]["custom_metadata"]
check("keep-until-checkout: on the host's record and with the password in OpenBao, audited LOCAL_ADMIN_POLICY",
      out["changed"] and load_record(CFG)["policy"] == "keep-until-checkout" and meta["policy"] ==
      "keep-until-checkout" and meta["current"] == "5" and AUDIT[-1][1] == "LOCAL_ADMIN_POLICY", meta)
check("…set again: nothing changes", not set_local_admin_policy(V, CFG, "keep-until-checkout", "root",
                                                                audit=audit)["changed"])
at(24 * 400)
check_local_admin(V, CFG, **parts)
check("keep-until-checkout: a year later with no use nor check-out, the password is kept (no schedule)",
      read_local_admin_secret(V, token)["current"] == 5)
checkout_local_admin(V, CFG, None, "root", "sealing the site's envelope", **kw)
at(24 * 400 + 8)
check_local_admin(V, CFG, **parts)
check("…checked out: rotated after the grace, as after-use is", read_local_admin_secret(V, token)["current"] == 6)

print("--- OpenBao sealed (2.1.7.20)")
JOURNAL.append(json.dumps({"MESSAGE": "pam_unix(login:session): session opened for user local-admin(uid=1002) by "
                           "LOGIN(uid=0)", "__REALTIME_TIMESTAMP": str(int(at(24 * 400 + 9).timestamp() * 1e6))}))
check_local_admin(V, CFG, **parts)
bao_request(V, "PUT", "sys/seal", token=ROOT)
at(24 * 400 + 18)
out = check_local_admin(V, CFG, **parts)
rec = load_record(CFG)
check("sealed: the rotation due waits, said; the used password stays current; the record says since when and why",
      out["ok"] and "waits" in " ".join(out["lines"]) and rec["waiting"]["why"] == "OpenBao is sealed (locked)"
      and rec["version"] == 6 and len(SET) == 5, (out, rec["waiting"]))
warn = local_admin_checks(V, CFG, False)["warnings"]
check("…doctor and the console remind of it", any("waits" in w and "stays valid" in w for w in warn), warn)
msg = refused(lambda: checkout_local_admin(V, CFG, None, "root", "why", **kw))
check("negative: a check-out is refused while OpenBao is sealed (it holds the only copy)", "sealed" in msg, msg)
check("…doctor's check fails, saying OpenBao cannot be asked",
      not local_admin_checks(V, CFG, True, exists=lambda: True)["checks"][0][1])
at(24 * 400 + 19)
check_local_admin(V, CFG, **parts)
check("…a second run while sealed keeps waiting since the first", load_record(CFG)["waiting"]["since"]
      == rec["waiting"]["since"])
bao_request(V, "POST", "sys/unseal", body={"key": UNSEAL})
for _ in range(30):
    if bao_request(V, "GET", "sys/health")[0] == 200:
        break
    time.sleep(1)
token = local_admin_token(V)[0]
at(24 * 400 + 20)
out = check_local_admin(V, CFG, **parts)
check("unsealed: the next run rotates it; nothing waits any more",
      read_local_admin_secret(V, token)["current"] == 7 and load_record(CFG)["waiting"] is None
      and local_admin_checks(V, CFG, False)["warnings"] == [], out)

print("--- the SSH drop-in (1.7.1.4.6)")
sshd_dir = os.path.join(W, "sshd_config.d")
os.makedirs(sshd_dir)
dropin = os.path.join(sshd_dir, "05-fabric-local-admin.conf")
says, reloads = [], []
ssh_kw = dict(check=lambda: says.pop(0) if says else "",
              reload=lambda: reloads.append(1), dropin=dropin, folder=sshd_dir)
done = apply_local_admin_ssh(False, **ssh_kw)
check("off: sshd refuses local-admin (DenyUsers), sshd reloaded",
      "DenyUsers local-admin\n" in open(dropin).read() and reloads == [1] and "off" in done[0], done)
check("…applied again: nothing changes, nothing reloaded", apply_local_admin_ssh(False, **ssh_kw) == []
      and reloads == [1])
apply_local_admin_ssh(True, **ssh_kw)
text = open(dropin).read()
check("on: a Match block for local-admin alone: its password, no keys; closed by Match all",
      "Match User local-admin\n" in text and "PasswordAuthentication yes" in text and "AuthorizedKeysFile none" in text
      and text.rstrip().endswith("Match all") and "DenyUsers" not in text, text)
says[:] = ["", "line 3: Bad configuration option"]
msg = refused(lambda: apply_local_admin_ssh(False, **ssh_kw))
check("negative: sshd refusing the new drop-in: put back as it was, not reloaded, said",
      "put back" in msg and open(dropin).read() == text and len(reloads) == 2, msg)
says[:] = ["broken elsewhere"]
msg = refused(lambda: apply_local_admin_ssh(False, **ssh_kw))
check("negative: sshd already refusing its configuration: nothing changed", "as it is" in msg
      and open(dropin).read() == text, msg)
with open(dropin, "w") as f:
    f.write("DenyUsers nobody\n")
msg = refused(lambda: apply_local_admin_ssh(False, **ssh_kw))
check("negative: a drop-in of that name that is not fabric's is left alone", "not fabric's" in msg
      and open(dropin).read() == "DenyUsers nobody\n", msg)
os.remove(dropin)
check("no SSH server (no sshd_config.d): nothing written", apply_local_admin_ssh(
    True, **{**ssh_kw, "folder": os.path.join(W, "none")}) == [])

print("--- the SSH switch's alert, acknowledged (1.7.1.4.10, 2.1.7.21)")
import fabriclib.localadmin.ack_local_admin_ssh as m_ack  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402


def ssh_alerts():
    return [w for w in local_admin_checks(V, CFG, False)["warnings"] if "over SSH: on" in w]


def ssh_relaxed():
    return [r for r in relaxed_settings({}, CFG) if r["setting"] == "local-admin over SSH: on"]


switch.update({"ssh": True, "by": "fabric-admin", "when": "2026-10-22T09:00:00+00:00", "ack": None})
at(24 * 400 + 21)
check_local_admin(V, CFG, **parts)
check("on, not acknowledged: doctor and the console's reminders raise its alert (how to turn it off or acknowledge it)",
      len(ssh_alerts()) == 1 and "ssh ack" in ssh_alerts()[0] and "ssh off" in ssh_alerts()[0], ssh_alerts())
check("…and it is a relaxation (fabricctl status, the Overview)", len(ssh_relaxed()) == 1
      and "acknowledged" not in ssh_relaxed()[0]["effect"], ssh_relaxed())
stored = {"dc": "dc-0001", "ssh": True, "by": "fabric-admin", "when": switch["when"],
          "ack": {"by": "root", "when": "2026-10-22T10:00:00+00:00"}, "changed": True}
asked = []
m_ack.local_admin_request = lambda v, req, container="samba": asked.append(req) or stored
n = len(AUDIT)
done = m_ack.ack_local_admin_ssh(V, CFG, None, "root", audit=audit, now=now)
check("acknowledged (root, for the Enterprise Admin): asked of the DC with who and when, audited LOCAL_ADMIN_SSH_ACK, "
      "kept in this host's record", asked[-1]["op"] == "ack" and asked[-1]["by"] == "root" and asked[-1]["when"]
      and AUDIT[-1][1] == "LOCAL_ADMIN_SSH_ACK" and len(AUDIT) == n + 1
      and load_record(CFG)["ssh"]["ack"] == stored["ack"], (done, asked))
check("…its alert no longer raised", ssh_alerts() == [], ssh_alerts())
check("…while the switch is still shown as on: the relaxation says who acknowledged its alert and when",
      len(ssh_relaxed()) == 1 and "acknowledged by root at 2026-10-22T10:00:00" in ssh_relaxed()[0]["effect"],
      ssh_relaxed())
stored = {**stored, "changed": False}
m_ack.ack_local_admin_ssh(V, CFG, None, "root", audit=audit, now=now)
check("…acknowledged again: nothing audited", len(AUDIT) == n + 1)
switch["ack"] = stored["ack"]
check_local_admin(V, CFG, **parts)
check("the hourly run keeps the acknowledgement the domain holds", ssh_alerts() == []
      and load_record(CFG)["ssh"]["ack"] == stored["ack"])
switch.update({"ssh": False, "ack": None})
check_local_admin(V, CFG, **parts)
check("turned off: no alert, no relaxation", ssh_alerts() == [] and ssh_relaxed() == [])
switch.update({"ssh": True, "ack": None})
check_local_admin(V, CFG, **parts)
check("turned on again: the alert is raised again", len(ssh_alerts()) == 1 and len(ssh_relaxed()) == 1)
m_ack.local_admin_request = lambda v, req, container="samba": (_ for _ in ()).throw(
    ValidationError("local-admin over SSH is off for dc-0001's host: there is no alert to acknowledge"))
msg = refused(lambda: m_ack.ack_local_admin_ssh(V, CFG, None, "root", audit=audit, now=now))
check("negative: the DC refusing (the switch off there): said, nothing audited or recorded",
      "no alert to acknowledge" in msg and len(AUDIT) == n + 1 and not load_record(CFG)["ssh"].get("ack"), msg)
msg = refused(lambda: m_ack.ack_local_admin_ssh(V, CFG, None, "root", dc="web1", audit=audit, now=now))
check("negative: a dc that is not dc-NNNN refused before the DC is asked", "not a domain controller" in msg, msg)
switch.update({"ssh": False, "ack": None})
check_local_admin(V, CFG, **parts)

print("--- the undo (1.7.1.4.1)")
gone = []
done = remove_local_admin(V, CFG, userdel=lambda: gone.append(1) or "", apply_ssh=lambda on, remove=False: [],
                          exists=lambda: True, audit=audit, now=now)
meta = bao_request(V, "GET", f"local-admin/metadata/{PATH}", token=ROOT)[1]["data"]
check("undone: the account removed, OpenBao's versions kept as history and marked removed, the record gone",
      gone == [1] and meta["custom_metadata"]["current"] == "none" and meta["custom_metadata"].get("removed")
      and len(meta["versions"]) >= 7 and not os.path.exists(os.path.join(CFG, "local-admin.json"))
      and AUDIT[-1][1] == "LOCAL_ADMIN_REMOVE", (done, meta.get("custom_metadata")))
check("…a second undo has nothing to do", remove_local_admin(V, CFG, audit=audit) == [])
fresh = os.path.join(W, "config-busy")
os.makedirs(fresh)
with open(os.path.join(fresh, "local-admin.json"), "w") as f:
    json.dump({"made": True, "version": 1}, f)
msg = refused(lambda: remove_local_admin(None, fresh, userdel=lambda: "user local-admin is currently used by process "
                                         "42", exists=lambda: True, audit=audit))
check("negative: an account still signed in: refused, said; the record kept so the undo can finish later",
      "currently used" in msg and os.path.exists(os.path.join(fresh, "local-admin.json")), msg)

if os.environ.get("FABRIC_TEST_KEEP") != "1":
    cleanup()
print(f"\n{'all passed' if not FAILED else f'{FAILED} FAILED'}")
sys.exit(1 if FAILED else 0)
