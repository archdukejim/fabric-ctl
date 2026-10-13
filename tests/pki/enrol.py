#!/usr/bin/env python3
"""Device enrolment (manual 1.5.3, decision 2.1.5.12), without containers: a root and an intermediate laid out as an
install's (keys encrypted, as Step-CA's); the one-time SCEP challenge (single use, a retry of the same transaction
answered the same, reuse, expiry, another name and a withdrawn one refused; only its hash kept), the hook that only
Step-CA may call, the notification recorded as the person with the device linked, the Apple profile's contents, the
PKCS#12 (opens with its password, refused with a wrong one, AES-256 or the legacy form when asked), the list of
enrolments, revoking one, withdrawing a profile, and the settings' refusals.

    python3 tests/pki/enrol.py            (openssl; no Docker, no root)

Status: written for 0.9, not run yet (owner's direction of 2026-10-12; notes 2.3.5.4).
"""
import base64
import datetime
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.pki import revoke_cert as rc  # noqa: E402
from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
from fabriclib.pki.scep import answer_hook as ah  # noqa: E402
from fabriclib.pki.scep import check_challenge as chk  # noqa: E402
from fabriclib.pki.scep import create_challenge as cc  # noqa: E402
from fabriclib.pki.scep import enrol_p12 as ep  # noqa: E402
from fabriclib.pki.scep import record_scep_issue as rsi  # noqa: E402
from fabriclib.pki.scep import withdraw_challenge as wc  # noqa: E402
from fabriclib.pki.scep.check_scep_settings import check_scep_settings  # noqa: E402
from fabriclib.pki.scep.common import enrol_inputs as ei  # noqa: E402
from fabriclib.pki.scep.common.hash_challenge import hash_challenge  # noqa: E402
from fabriclib.pki.scep.constants import CHALLENGE_PATH, ISSUED_PATH, PROVISIONER  # noqa: E402
from fabriclib.pki.scep.enrol_apple import enrol_apple  # noqa: E402
from fabriclib.pki.scep.list_enrolments import list_enrolments  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp()
BASE = os.path.join(W, "opt")
CERTS = os.path.join(BASE, "stepca", "data", "certs")
SECRETS = os.path.join(BASE, "stepca", "data", "secrets")
STORE = os.path.join(W, "archive", "scep-challenges.json")
LEDGER = os.path.join(W, "issued.jsonl")
REVOKED = os.path.join(W, "revoked.jsonl")
for d in (CERTS, SECRETS, os.path.join(BASE, "nginx", "certs", "client-ca"), os.path.join(BASE, "freeradius", "certs")):
    os.makedirs(d)
PW = os.path.join(SECRETS, "password")
open(PW, "w").write("test-ca-password\n")
AUDIT = []
for mod in (cc, chk, ah, rsi, ep, wc, rc):
    mod.write_audit = lambda actor, event, detail, source="cli", **kw: AUDIT.append((actor, event, detail, source))
rc.pick_up_cert = lambda unit: "reloaded"
DEVICES = {"alice-iphone", "alice-pixel", "broken-link"}


def require_device(v, name):
    if name not in DEVICES:
        raise ValidationError(f"no device named {name!r}")


ei.require_device = require_device
LINKED = []


def link(v, actor, device, sha256, source="web"):
    if device == "broken-link":
        raise ValidationError("the directory did not answer")
    LINKED.append((actor, device, sha256, source))


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(*cmd, ok=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd}\n{res.stderr}")
    return res


def ext(name, body):
    path = os.path.join(W, f"{name}.ext")
    open(path, "w").write(body)
    return path


def refused(fn, *args, match="", **kw):
    """True only if fn raises a ValidationError whose message contains match."""
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {match!r}: {exc}")
    return False


# ---------------------------------------------------------------- a CA laid out as an install's
ROOT_KEY, INTER_KEY = os.path.join(SECRETS, "root_ca_key"), os.path.join(SECRETS, "intermediate_ca_key")
ROOT, INTER = os.path.join(CERTS, "root_ca.crt"), os.path.join(CERTS, "intermediate_ca.crt")
for k in (ROOT_KEY, INTER_KEY):
    sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-aes256", "-pass", f"file:{PW}",
       "-out", k)
sh("openssl", "req", "-x509", "-key", ROOT_KEY, "-passin", f"file:{PW}", "-days", "3650", "-subj", "/CN=Test Root CA",
   "-out", ROOT, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
sh("openssl", "req", "-new", "-key", INTER_KEY, "-passin", f"file:{PW}", "-subj", "/CN=Test Intermediate CA", "-out",
   os.path.join(W, "inter.csr"))
sh("openssl", "x509", "-req", "-in", os.path.join(W, "inter.csr"), "-CA", ROOT, "-CAkey", ROOT_KEY, "-passin",
   f"file:{PW}", "-CAcreateserial", "-days", "1825", "-out", INTER, "-extfile",
   ext("ca", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
             "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"))
LEAF = ext("leaf", "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=clientAuth,serverAuth\n")
MINTED = []


def leaf_cert(cn, days=365, sans="", kty="RSA", size=2048):
    """A leaf from the intermediate, as Step-CA would issue it: (cert path, key path)."""
    key, csr, crt = (os.path.join(W, f"{cn}-{len(MINTED)}.{x}") for x in ("key", "csr", "crt"))
    sh("openssl", "genpkey", "-algorithm", kty, "-pkeyopt", f"rsa_keygen_bits:{size}", "-out", key)
    sh("openssl", "req", "-new", "-key", key, "-subj", f"/CN={cn}", "-out", csr)
    extfile = LEAF if not sans else ext(f"san-{len(MINTED)}", open(LEAF).read() + f"subjectAltName={sans}\n")
    sh("openssl", "x509", "-req", "-in", csr, "-CA", INTER, "-CAkey", INTER_KEY, "-passin", f"file:{PW}",
       "-CAcreateserial", "-days", str(days), "-out", crt, "-extfile", extfile)
    return crt, key


def mint(v, cn, sans=(), days=365, kty="RSA", size=4096):
    """mint_offline_cert's stand-in: Step-CA's offline signing done with openssl (a bundle: leaf + intermediate)."""
    crt, key = leaf_cert(cn, days=days, size=size)
    open(crt, "a").write(open(INTER).read())
    MINTED.append((cn, days, kty, size))
    return crt, key


V = {"deploy_base_dir": BASE, "service_users": {}, "install_webui": True, "domain": "lan.test",
     "hostname_stepca": "ca.lan.test", "hostname_radius": "radius.lan.test", "ca_name": "Test CA",
     "scep_challenge_minutes": 60, "scep_cert_days": 365, "pki_manual_max_days": 1825}
NOW = datetime.datetime.now(datetime.timezone.utc)
ROOT_DER = subprocess.run(["openssl", "x509", "-in", ROOT, "-outform", "DER"], capture_output=True, check=True).stdout


def ask(challenge, cn, transaction):
    """The SCEPCHALLENGE webhook body Step-CA sends."""
    return {"scepChallenge": challenge, "scepTransactionID": transaction,
            "x509CertificateRequest": {"subject": {"commonName": cn}}}


def store_records():
    return json.load(open(STORE)) if os.path.exists(STORE) else []


# ---------------------------------------------------------------- the Apple profile
print("--- the Apple profile (1.5.3.5)")
check("negative: no profile before setup made the SCEP decrypter (RA) certificate",
      refused(enrol_apple, V, "alice", "alice-iphone", store=STORE, match="not set up"))
open(os.path.join(CERTS, "scep_ra.crt"), "w").write(open(INTER).read())       # its presence is what is checked
r = enrol_apple(V, "alice", "Alice-iPhone", "alice-iphone", ssid="home-secure", wired=True, store=STORE)
profile = plistlib.loads(base64.b64decode(r["profile_b64"]))
by_type = {p["PayloadType"]: p for p in profile["PayloadContent"]}
scep = by_type.get("com.apple.security.scep", {}).get("PayloadContent", {})
challenge = scep.get("Challenge", "")
# covers: agent:post.pki.enrol.apple +
check("profile: the root CA (DER), SCEP to Step-CA's provisioner for this name, Wi-Fi and wired EAP-TLS",
      r["filename"] == "alice-iphone.mobileconfig" and r["cn"] == "alice-iphone"
      and by_type["com.apple.security.root"]["PayloadContent"] == ROOT_DER
      and scep.get("URL") == f"http://ca.lan.test/scep/{PROVISIONER}" and scep.get("Subject") == [[["CN", "alice-iphone"]]]
      and scep.get("Key Type") == "RSA" and scep.get("Keysize") == 2048 and len(challenge) == 32
      and by_type["com.apple.wifi.managed"]["SSID_STR"] == "home-secure"
      and by_type["com.apple.wifi.managed"]["EAPClientConfiguration"]["AcceptEAPTypes"] == [13]
      and by_type["com.apple.wifi.managed"]["EAPClientConfiguration"]["TLSTrustedServerNames"] == ["radius.lan.test"]
      and by_type["com.apple.wifi.managed"]["PayloadCertificateUUID"] == by_type["com.apple.security.scep"]["PayloadUUID"]
      and "com.apple.firstactiveethernet.managed" in by_type, profile)
ids = [p["PayloadIdentifier"] for p in profile["PayloadContent"]]
check("profile: every payload has its own identifier and UUID", len(set(ids)) == len(ids) == 4
      and len({p["PayloadUUID"] for p in profile["PayloadContent"]}) == 4, ids)
recs = store_records()
store_text = open(STORE).read()
check("the store keeps the challenge's SHA-256 only, root-only (0600), bound to the person, the name and the device",
      challenge not in store_text and recs[-1]["hash"] == hash_challenge(challenge) and recs[-1]["by"] == "alice"
      and recs[-1]["cn"] == "alice-iphone" and recs[-1]["device"] == "alice-iphone" and recs[-1]["state"] == "open"
      and oct(os.stat(STORE).st_mode & 0o777) == "0o600", recs)
made = datetime.datetime.fromisoformat(recs[-1]["made"])
# covers: setting:scep_challenge_minutes +
check("the challenge expires scep_challenge_minutes (60) after it was made",
      datetime.datetime.fromisoformat(recs[-1]["expires"]) - made == datetime.timedelta(minutes=60), recs[-1])
short = cc.create_challenge({**V, "scep_challenge_minutes": 5}, "alice", "alice-mac", store=STORE)
check("...and 5 minutes when set so", datetime.datetime.fromisoformat(short["expires"])
      - datetime.datetime.fromisoformat(store_records()[-1]["made"]) == datetime.timedelta(minutes=5), short)
before = open(STORE).read()
for args, why in ((("bad name!",), "letters, digits and dashes"), (("x" * 64,), "letters, digits and dashes"),
                  (("ok-name", "no-such-device"), "no device named"),
                  (("ok-name", "", "s" * 33), "at most 32 bytes"), (("ok-name", "", "bad\nssid"), "control")):
    # covers: agent:post.pki.enrol.apple -
    check(f"negative: profile refused ({why}), no challenge made",
          refused(enrol_apple, V, "alice", *args, store=STORE, match=why) and open(STORE).read() == before)
check("negative: no enrolment without the web console (its hook lives there)",
      refused(enrol_apple, {**V, "install_webui": False}, "alice", "ok-name", store=STORE, match="web console"))

# ---------------------------------------------------------------- the one-time challenge
print("--- the challenge: single use (1.5.3.4)")
ok, why = chk.check_challenge(ask(challenge, "alice-iphone", "tx-1"), store=STORE)
check("first use for its name: allowed, spent, audited as the person who made it (never the challenge itself)",
      ok and store_records()[0]["state"] == "used" and store_records()[0]["transaction"] == "tx-1"
      and AUDIT[-1][:2] == ("alice", "SCEP_CHALLENGE_USED") and challenge not in str(AUDIT), (why, AUDIT[-1:]))
ok, why = chk.check_challenge(ask(challenge, "alice-iphone", "tx-1"), store=STORE)
check("the same transaction asked again (Step-CA's retry): the same answer", ok, why)
ok, why = chk.check_challenge(ask(challenge, "alice-iphone", "tx-2"), store=STORE)
check("negative: reused by another request: refused (already used), audited",
      not ok and "already used" in why and AUDIT[-1][1] == "SCEP_CHALLENGE_REFUSED", why)
ok, why = chk.check_challenge(ask(challenge, "mallory-laptop", "tx-1"), store=STORE)
check("negative: reused with the first transaction but another name: refused", not ok and "already used" in why, why)
other = cc.create_challenge(V, "alice", "alice-ipad", store=STORE)
ok, why = chk.check_challenge(ask(other["challenge"], "mallory-laptop", "tx-3"), store=STORE)
check("negative: a challenge used for another name than its profile's: refused, and spent",
      not ok and "not the profile's" in why
      and next(c for c in store_records() if c["id"] == other["id"])["state"] == "used", why)
ok, why = chk.check_challenge(ask(other["challenge"], "alice-ipad", "tx-4"), store=STORE)
check("...so the right name after that is refused too", not ok and "already used" in why, why)
old = cc.create_challenge(V, "alice", "alice-old", store=STORE, now=NOW - datetime.timedelta(hours=2))
ok, why = chk.check_challenge(ask(old["challenge"], "alice-old", "tx-5"), store=STORE)
check("negative: expired (made 2 hours ago, 60 minutes to live): refused", not ok and "expired" in why, why)
ok, why = chk.check_challenge(ask("not-a-challenge-of-ours", "x", "tx-6"), store=STORE)
check("negative: unknown challenge refused, audited as step-ca", not ok and "no such challenge" in why
      and AUDIT[-1][0] == "step-ca", why)
ok, why = chk.check_challenge({"scepTransactionID": "tx-7"}, store=STORE)
check("negative: no challenge in the request refused", not ok and "no challenge" in why, why)

# ---------------------------------------------------------------- withdrawing
print("--- withdrawing a profile (1.5.3.7)")
w1 = cc.create_challenge(V, "alice", "alice-watch", store=STORE)
check("negative: another person may not withdraw alice's profile",
      refused(wc.withdraw_challenge, "bob", w1["id"], store=STORE, match="only the person who made"))
# covers: agent:post.pki.enrolments.*.withdraw +
check("alice withdraws her own: it is refused from then on",
      wc.withdraw_challenge("alice", w1["id"], store=STORE)["cn"] == "alice-watch"
      and not chk.check_challenge(ask(w1["challenge"], "alice-watch", "tx-8"), store=STORE)[0])
w2 = cc.create_challenge(V, "alice", "alice-tv", store=STORE)
check("someone with pki:revoke withdraws anyone's", wc.withdraw_challenge("carol", w2["id"], may_withdraw_any=True,
                                                                         store=STORE)["id"] == w2["id"])
# covers: agent:post.pki.enrolments.*.withdraw -
check("negative: withdrawing a used, a withdrawn or an unknown profile is refused",
      refused(wc.withdraw_challenge, "alice", recs[0]["id"], store=STORE, match="can no longer be used")
      and refused(wc.withdraw_challenge, "alice", w1["id"], store=STORE, match="can no longer be used")
      and refused(wc.withdraw_challenge, "alice", "ffff", store=STORE, match="no open profile"))

# ---------------------------------------------------------------- the hooks: only Step-CA
print("--- the webhooks: only Step-CA may call them (1.5.3.3)")
stepca_crt, _ = leaf_cert("ca.lan.test", sans="DNS:ca.lan.test,DNS:localhost,IP:127.0.0.1")
service_crt, _ = leaf_cert("mgr.lan.test", sans="DNS:mgr.lan.test,DNS:ca.lan.test")
STEPCA_PEM = urllib.parse.quote(open(stepca_crt).read())
fresh = cc.create_challenge(V, "alice", "alice-laptop", store=STORE)
for verify, pem, label in (("NONE", "", "no client certificate"), ("FAILED:unable to verify", STEPCA_PEM,
                                                                     "an unverified certificate"),
                           ("SUCCESS", urllib.parse.quote(open(service_crt).read()), "another service's certificate"),
                           ("SUCCESS", "garbage", "an unreadable certificate")):
    st, answer = ah.answer_hook(V, CHALLENGE_PATH, verify, pem, ask(fresh["challenge"], "alice-laptop", "tx-9"),
                                store=STORE)
    check(f"negative: {label}: 403, audited, the challenge not touched",
          st == 403 and AUDIT[-1][1] == "SCEP_HOOK_REFUSED"
          and next(c for c in store_records() if c["id"] == fresh["id"])["state"] == "open", (st, answer))
st, answer = ah.answer_hook(V, "/hooks/scep/other", "SUCCESS", STEPCA_PEM, {}, store=STORE)
check("negative: another path: 404", st == 404, st)
st, answer = ah.answer_hook(V, CHALLENGE_PATH, "SUCCESS", STEPCA_PEM, ["not", "an", "object"], store=STORE)
check("negative: a body that is not an object: 400", st == 400, st)
st, answer = ah.answer_hook(V, CHALLENGE_PATH, "SUCCESS", STEPCA_PEM, ask(fresh["challenge"], "alice-laptop", "tx-9"),
                            store=STORE)
check("Step-CA's own certificate: the challenge hook answers allow", st == 200 and answer == {"allow": True}, answer)
st, answer = ah.answer_hook(V, CHALLENGE_PATH, "SUCCESS", STEPCA_PEM, ask(fresh["challenge"], "alice-laptop", "tx-10"),
                            store=STORE)
check("negative: ...and allow false, with fabric's reason, when it is reused",
      st == 200 and answer["allow"] is False and "already used" in answer["error"]["message"], answer)

print("--- the notification: recorded as the person, linked to the device")
issued_crt, _ = leaf_cert("alice-iphone", days=365)
der = subprocess.run(["openssl", "x509", "-in", issued_crt, "-outform", "DER"], capture_output=True, check=True).stdout
note = {"scepTransactionID": "tx-1", "x509Certificate": {"raw": base64.b64encode(der).decode()}}
st, answer = ah.answer_hook(V, ISSUED_PATH, "SUCCESS", STEPCA_PEM, note, store=STORE, ledger=LEDGER, link=link)
entry = json.loads(open(LEDGER).read().splitlines()[-1])
info = describe_cert(open(issued_crt).read())
check("notification: in the ledger as kind scep, by alice, linked to alice-iphone (its SHA-256)",
      st == 200 and answer["recorded"] and entry["kind"] == "scep" and entry["actor"] == "alice"
      and entry["device"] == "alice-iphone" and LINKED[-1] == ("alice", "alice-iphone", info["sha256"], "scep")
      and store_records()[0]["serial"] == info["serial"], (answer, entry, LINKED[-1:]))
broken = cc.create_challenge(V, "alice", "broken-link", device="broken-link", store=STORE)
chk.check_challenge(ask(broken["challenge"], "broken-link", "tx-11"), store=STORE)
crt2, _ = leaf_cert("broken-link")
der2 = subprocess.run(["openssl", "x509", "-in", crt2, "-outform", "DER"], capture_output=True, check=True).stdout
st, answer = ah.answer_hook(V, ISSUED_PATH, "SUCCESS", STEPCA_PEM, {"scepTransactionID": "tx-11", "x509Certificate": {
    "raw": base64.b64encode(der2).decode()}}, store=STORE, ledger=LEDGER, link=link)
rec = next(c for c in store_records() if c["id"] == broken["id"])
check("a link the directory refuses: the certificate still recorded (no device), the error kept and shown",
      st == 200 and json.loads(open(LEDGER).read().splitlines()[-1])["device"] == ""
      and "did not answer" in rec["link_error"], (answer, rec))
before = open(LEDGER).read()
st, answer = ah.answer_hook(V, ISSUED_PATH, "SUCCESS", STEPCA_PEM, {"scepTransactionID": "tx-x", "scepErrorCode": 2,
                                                                     "scepErrorDescription": "badRequest"},
                            store=STORE, ledger=LEDGER, link=link)
check("a failure notification: audited, nothing recorded", st == 200 and answer["recorded"] is False
      and open(LEDGER).read() == before and AUDIT[-1][1] == "SCEP_FAILED", answer)
check("negative: a notification whose certificate is not base64 is refused",
      refused(ah.answer_hook, V, ISSUED_PATH, "SUCCESS", STEPCA_PEM, {"scepTransactionID": "t",
                                                                      "x509Certificate": {"raw": "!!"}},
              store=STORE, ledger=LEDGER, link=link, match="not base64"))

# ---------------------------------------------------------------- the PKCS#12
print("--- the PKCS#12 for Android and other devices (1.5.3.6)")


def p12_open(b64, password, tag):
    path, pw = os.path.join(W, f"{tag}.p12"), os.path.join(W, f"{tag}.pw")
    open(path, "wb").write(base64.b64decode(b64))
    fd = os.open(pw, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(password)
    res = subprocess.run(["openssl", "pkcs12", "-in", path, "-passin", f"file:{pw}", "-info", "-nodes"],
                         capture_output=True, text=True)
    return res.returncode == 0, res.stdout + res.stderr


p = ep.enrol_p12({**V, "scep_cert_days": 30}, "alice", "Alice-Pixel", "alice-pixel", ledger=LEDGER, mint=mint,
                 link=link)
opened, out = p12_open(p["p12_b64"], p["p12_password"], "modern")
# covers: agent:post.pki.enrol.p12 +
check("p12: opens with its password; the key, the certificate for alice-pixel and the chain inside; AES-256, SHA-256 MAC",
      opened and "PRIVATE KEY" in out and "CN=alice-pixel" in out.replace(" = ", "=") and "Test Intermediate CA" in out
      and "AES-256-CBC" in out and "sha256" in out.lower() and len(p["p12_password"]) == 20, out[-600:])
wrong, out = p12_open(p["p12_b64"], p["p12_password"] + "x", "wrong")
check("negative: p12: refused with a wrong password", not wrong, out[-300:])
# covers: setting:scep_cert_days +
check("its certificate lives scep_cert_days (30); a 2048-bit RSA key", MINTED[-1][1:] == (30, "RSA", 2048), MINTED[-1])
entry = json.loads(open(LEDGER).read().splitlines()[-1])
ledger_and_audit = open(LEDGER).read() + json.dumps(AUDIT)
check("p12: in the ledger as enrol-p12 by alice with the device, linked; the password kept nowhere",
      entry["kind"] == "enrol-p12" and entry["actor"] == "alice" and entry["device"] == "alice-pixel"
      and LINKED[-1][1] == "alice-pixel" and p["p12_password"] not in ledger_and_audit
      and AUDIT[-1][1] == "PKI_ENROL_P12", entry)
old_p = ep.enrol_p12(V, "alice", "old-android", ledger=LEDGER, mint=mint, link=link, legacy=True)
opened, out = p12_open(old_p["p12_b64"], old_p["p12_password"], "legacy")
check("p12 for Android 11 and older: opens, 3DES and a SHA-1 MAC, said in the result",
      opened and "3-KeyTripleDES" in out and "sha1" in out.lower() and old_p["legacy"] is True, out[-600:])
before = open(LEDGER).read()
for args, kw, why in ((("bad name!",), {}, "letters, digits and dashes"), (("ok-name", "no-such-device"), {},
                                                                           "no device named")):
    # covers: agent:post.pki.enrol.p12 -
    check(f"negative: p12 refused ({why}), nothing minted or recorded",
          refused(ep.enrol_p12, V, "alice", *args, ledger=LEDGER, mint=mint, link=link, match=why)
          and open(LEDGER).read() == before)
check("negative: p12 refused for more days than pki_manual_max_days",
      refused(ep.enrol_p12, {**V, "scep_cert_days": 4000}, "alice", "ok-name", ledger=LEDGER, mint=mint, link=link,
              match="") and open(LEDGER).read() == before)

# ---------------------------------------------------------------- the list, and revoking
print("--- the list of enrolments, and revoking (1.5.3.7)")
listed = list_enrolments(store=STORE, ledger=LEDGER, revoked=REVOKED)
# covers: agent:get.pki.enrolments +
check("list: the open profiles (not the used, withdrawn or expired) and every certificate from enrolment",
      {c["cn"] for c in listed["challenges"]} == {"alice-mac"}
      and {e["kind"] for e in listed["issued"]} == {"scep", "enrol-p12"} and len(listed["issued"]) == 4
      and all("hash" not in c for c in listed["challenges"]), listed)
check("list: the failed link is shown with its certificate",
      any(e.get("link_error") for e in listed["issued"] if e["subject"].endswith("broken-link")), listed["issued"])
done = rc.revoke_cert(V, "carol", p["info"]["serial"], "keyCompromise", ledger=LEDGER, revoked=REVOKED)
state = {e["serial"]: e["status"] for e in list_enrolments(store=STORE, ledger=LEDGER, revoked=REVOKED)["issued"]}
check("revoke the p12's certificate: listed as revoked, in the published CRL",
      done["reason"] == "keyCompromise" and state[p["info"]["serial"]] == "revoked"
      and os.path.exists(os.path.join(BASE, "nginx", "www", "certs", "crl", "intermediate.crl")), state)
with open(STORE, "w") as f:
    f.write("{not json")
# covers: agent:get.pki.enrolments -
try:
    list_enrolments(store=STORE, ledger=LEDGER, revoked=REVOKED)
    said = "listed"
except (ValueError, OSError) as exc:
    said = str(exc) or type(exc).__name__
check("negative: a damaged store is refused, never read as empty (and never started over)", said != "listed"
      and open(STORE).read() == "{not json", said)

# ---------------------------------------------------------------- the settings
print("--- the settings (1.5.2.1.29, 1.5.2.1.30)")
for key, bad, why in (("scep_challenge_minutes", "2", "from 5 to 1440"), ("scep_challenge_minutes", "x", "from 5"),
                      ("scep_challenge_minutes", "2000", "1440"), ("scep_cert_days", "0", "from 1"),
                      ("scep_cert_days", "4000", "pki_manual_max_days")):
    # covers: setting:scep_challenge_minutes setting:scep_cert_days -
    check(f"negative: {key} {bad!r} refused at apply",
          refused(check_scep_settings, {"pki_manual_max_days": 1825, key: bad}, match=why))
fv = {"pki_manual_max_days": "1825", "scep_challenge_minutes": "15", "scep_cert_days": "90"}
check_scep_settings(fv)
check("whole numbers in range are accepted, as numbers", fv["scep_challenge_minutes"] == 15 and fv["scep_cert_days"] == 90,
      fv)

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
