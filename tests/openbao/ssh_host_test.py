#!/usr/bin/env python3
"""SSH host certificates (manual 1.6.11.9.6 to 1.6.11.9.11; decision 2.1.7.13), container-free: certificates made by
ssh-keygen read back (kind, key, principals, validity, CA); a machine's names from its account; which keys are signed
and which certificates kept (missing, renewing, another CA, other names, a user certificate, keys refused); the
known-hosts lines; the fabric host's own files (sshd checked before and after, put back when refused, off removes
them, the owner's lines kept); one signing run with stand-ins for OpenBao and the directory (off, on, a machine's
refusal not stopping the others, a second run keeping everything, OpenBao without a host CA); and the command
`fabricctl domain ssh-hosts`. The real OpenBao is tests/openbao/ssh_ca.py; the real DC and joined machines,
tests/samba/linux_join.py.

    python3 tests/openbao/ssh_host_test.py         (needs ssh-keygen; on Linux: the audit log uses syslog)
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.vault.ssh import apply_host_ssh_cert as ahc  # noqa: E402
from fabriclib.vault.ssh import sign_ssh_hosts as shs  # noqa: E402
from fabriclib.vault.ssh.host_principals import host_principals  # noqa: E402
from fabriclib.vault.ssh.known_hosts_block import BEGIN, END, known_hosts_block  # noqa: E402
from fabriclib.vault.ssh.parse_ssh_cert import parse_ssh_cert  # noqa: E402
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key  # noqa: E402
from fabriclib.vault.ssh.plan_host_certs import plan_host_certs  # noqa: E402
import fabriclib.samba.run_domain_command as m_rdc  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp(prefix="ssh-host-test-")
AUDIT = []
shs.write_audit = lambda actor, event, detail, source="cli", **kw: AUDIT.append((event, detail))


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def refused(fn, *args, match="", **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        return match.lower() in str(exc).lower()
    return False


def keygen(name, kind="ed25519", bits=None):
    path = os.path.join(W, name)
    subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", name, "-f", path]
                   + (["-b", str(bits)] if bits else []), check=True)
    return open(path + ".pub").read().strip()


def certify(ca, name, principals, validity="+30d", host=True):
    """A certificate for <name>.pub signed by the CA key <ca>, as ssh-keygen makes it."""
    path = os.path.join(W, name)
    subprocess.run(["ssh-keygen", "-q", "-s", os.path.join(W, ca), "-I", f"test:{name}", "-n", ",".join(principals),
                    "-V", validity] + (["-h"] if host else []) + [path + ".pub"], check=True)
    return open(path + "-cert.pub").read().strip()


CA = keygen("ca")
OTHER_CA = keygen("other_ca")
CA_FP = parse_ssh_key(CA)["fingerprint"]
HOST_KEY = keygen("ws1")
HOST_ECDSA = keygen("ws1e", "ecdsa")
NAMES = ["ws1", "ws1.ad.lan.test", "ws1.lan.test"]
NOW = int(time.time())

# ---------------------------------------------------------------- reading certificates
print("--- certificates read back")
c = parse_ssh_cert(certify("ca", "ws1", NAMES))
check("a host certificate: kind, the key it certifies, its names, 30 days, the CA that signed it",
      c["kind"] == "host" and c["key_fingerprint"] == parse_ssh_key(HOST_KEY)["fingerprint"]
      and c["principals"] == NAMES and 29 * 86400 < c["valid_before"] - NOW <= 30 * 86400 + 120
      and c["ca_fingerprint"] == CA_FP and c["key_id"] == "test:ws1", c)
ce = parse_ssh_cert(certify("ca", "ws1e", ["ws1"]))
check("an ECDSA host certificate: its key found too", ce["type"] == "ecdsa-sha2-nistp256"
      and ce["key_fingerprint"] == parse_ssh_key(HOST_ECDSA)["fingerprint"], ce)
keygen("alice")
cu = parse_ssh_cert(certify("ca", "alice", ["alice"], "+8h", host=False))
check("a user certificate reads as a user certificate", cu["kind"] == "user" and cu["principals"] == ["alice"], cu)
line = certify("ca", "ws1", NAMES)
check("negative: a damaged certificate is refused, not misread",
      refused(parse_ssh_cert, line.split()[0] + " " + line.split()[1][:60], match="damaged"))
check("negative: a public key is not a certificate", refused(parse_ssh_cert, HOST_KEY, match="not an SSH certificate"))
check("negative: base64 that does not decode", refused(parse_ssh_cert, line.split()[0] + " %%%%", match="decode"))

# ---------------------------------------------------------------- names
print("--- a machine's names")
check("from the account: short, .ad_domain, .domain, lower case, each once",
      host_principals("WS1$", ["AD.lan.test", "lan.test", "lan.test.", ""]) == NAMES,
      host_principals("WS1$", ["AD.lan.test", "lan.test", "lan.test.", ""]))
check("negative: localhost is never certified", refused(host_principals, "LOCALHOST$", ["lan.test"], match="not a host"))
check("negative: a name that is not a host name is refused",
      refused(host_principals, "ws_1$", ["lan.test"], match="not a host"))

# ---------------------------------------------------------------- the plan
print("--- which keys are signed, which certificates kept")
p = plan_host_certs([HOST_KEY], [], NAMES, CA_FP, NOW)
check("no certificate yet: the key is signed", p["sign"] == [" ".join(HOST_KEY.split()[:2])] and p["changed"], p)
good = certify("ca", "ws1", NAMES)
p = plan_host_certs([HOST_KEY], [good], NAMES, CA_FP, NOW)
check("a valid certificate of today's CA with its names: kept, nothing changes",
      p["keep"] == [" ".join(good.split()[:2])] and not p["sign"] and not p["changed"], p)
p = plan_host_certs([HOST_KEY], [certify("ca", "ws1", NAMES, "+5d")], NAMES, CA_FP, NOW)
check("5 days left (fewer than 10): signed again", p["sign"] and not p["keep"] and p["changed"], p)
p = plan_host_certs([HOST_KEY], [certify("other_ca", "ws1", NAMES)], NAMES, CA_FP, NOW)
check("signed by another CA: signed again", p["sign"] and not p["keep"], p)
p = plan_host_certs([HOST_KEY], [certify("ca", "ws1", ["ws1", "evil.lan.test"])], NAMES, CA_FP, NOW)
check("other names than fabric's: signed again", p["sign"] and not p["keep"], p)
p = plan_host_certs([HOST_KEY], [certify("ca", "ws1", NAMES, host=False)], NAMES, CA_FP, NOW)
check("a user certificate in the host's attribute: not kept", p["sign"] and not p["keep"], p)
p = plan_host_certs([HOST_KEY], [certify("ca", "ws1", NAMES, "+1d:+30d")], NAMES, CA_FP, NOW)
check("not begun yet (starts tomorrow): signed again", p["sign"] and not p["keep"], p)
rsa_small = keygen("small", "rsa", 2048)
p = plan_host_certs([rsa_small, "ssh-dss AAAAB3NzaC1kc3MAAACBAP== old", "nonsense"], [], NAMES, CA_FP, NOW)
check("negative: RSA under 3072 bits, DSA and nonsense are refused, never signed",
      not p["sign"] and len(p["refused"]) == 3 and any("3072" in why for _, why in p["refused"]), p)
second = keygen("ws1b")
p = plan_host_certs([HOST_KEY, second, HOST_ECDSA], [], NAMES, CA_FP, NOW)
check("negative: a second Ed25519 key is refused (one per family); the ECDSA one is signed",
      len(p["sign"]) == 2 and len(p["refused"]) == 1 and "second ed25519" in p["refused"][0][1], p)
p = plan_host_certs([HOST_ECDSA], [good], NAMES, CA_FP, NOW)
check("a certificate of a key no longer published is dropped", not p["keep"] and p["sign"] and p["changed"], p)

# ---------------------------------------------------------------- known hosts
print("--- the known-hosts lines")
block = known_hosts_block(CA + " comment", ["ad.lan.test", "LAN.test", "lan.test", ""])
lines = block.splitlines()
check("the domain's names, then short names only, between fabric's markers",
      lines[0] == BEGIN and lines[-1] == END
      and lines[1] == "@cert-authority *.ad.lan.test,*.lan.test " + " ".join(CA.split()[:2])
      and lines[2] == "@cert-authority *,!*.*,!*:* " + " ".join(CA.split()[:2]), block)

# ---------------------------------------------------------------- the fabric host's own files
print("--- the fabric host's own certificate and trust")
etc = os.path.join(W, "etc-ssh")
os.makedirs(os.path.join(etc, "sshd_config.d"))
ahc.SSHD_DIR = os.path.join(etc, "sshd_config.d")
ahc.DROPIN = os.path.join(ahc.SSHD_DIR, "11-fabric-host-cert.conf")
ahc.CERT_FILE = os.path.join(etc, "fabric-host-cert-{}.pub")
ahc.KNOWN_HOSTS = os.path.join(etc, "ssh_known_hosts")
with open(ahc.KNOWN_HOSTS, "w") as f:
    f.write("router.example.org ssh-ed25519 AAAAOWNERSLINE\n")
sshd = {"before": "", "after": ""}
reloads = []


def sshd_says():
    """sshd -t stood in: "after" once the renewed certificate is on disk, "before" until then."""
    path = ahc.CERT_FILE.format("ed25519")
    new = sshd.get("renewed") and os.path.exists(path) and sshd["renewed"] in open(path).read()
    return sshd["after"] if new else sshd["before"]


V = {"ad_domain": "ad.lan.test", "domain": "lan.test"}
host_cert = certify("ca", "ws1", NAMES)
done = ahc.apply_host_ssh_cert(V, [host_cert], CA, check=sshd_says, reload=lambda: reloads.append(1))
dropin = open(ahc.DROPIN).read() if os.path.exists(ahc.DROPIN) else ""
known = open(ahc.KNOWN_HOSTS).read()
check("on: the certificate beside the keys, HostCertificate in fabric's drop-in, sshd reloaded",
      open(ahc.CERT_FILE.format("ed25519")).read().strip() == " ".join(host_cert.split()[:2])
      and f"HostCertificate {ahc.CERT_FILE.format('ed25519')}" in dropin and reloads == [1], (done, dropin))
check("...and the host CA trusted in ssh_known_hosts, the owner's own line kept",
      known.startswith("router.example.org ssh-ed25519 AAAAOWNERSLINE\n") and BEGIN in known
      and "@cert-authority *.ad.lan.test,*.lan.test" in known, known)
check("a second run changes nothing", ahc.apply_host_ssh_cert(V, [host_cert], CA, check=sshd_says,
                                                             reload=lambda: reloads.append(1)) == [] and reloads == [1])
sshd["after"] = "line 2: Bad configuration option"
renewed = certify("ca", "ws1", NAMES, "+29d")
sshd["renewed"] = renewed.split()[1]
check("negative: sshd refuses the new configuration: refused, the files put back, nothing reloaded",
      refused(ahc.apply_host_ssh_cert, V, [renewed], CA, check=sshd_says, reload=lambda: reloads.append(1),
              match="put back")
      and open(ahc.CERT_FILE.format("ed25519")).read().strip() == " ".join(host_cert.split()[:2])
      and open(ahc.DROPIN).read() == dropin and reloads == [1])
sshd["after"], sshd["before"] = "", "line 9: broken already"
check("negative: sshd already refuses its configuration: refused before anything is changed",
      refused(ahc.apply_host_ssh_cert, V, [renewed], CA, check=sshd_says, reload=lambda: reloads.append(1),
              match="before fabric changes anything")
      and open(ahc.CERT_FILE.format("ed25519")).read().strip() == " ".join(host_cert.split()[:2]))
sshd["before"] = ""
done = ahc.apply_host_ssh_cert(V, [], "", check=sshd_says, reload=lambda: reloads.append(1))
check("off: the certificate, the drop-in and fabric's lines removed; the owner's line kept",
      not os.path.exists(ahc.CERT_FILE.format("ed25519")) and not os.path.exists(ahc.DROPIN)
      and open(ahc.KNOWN_HOSTS).read() == "router.example.org ssh-ed25519 AAAAOWNERSLINE\n", done)
with open(ahc.DROPIN, "w") as f:
    f.write("HostCertificate /etc/ssh/mine.pub\n")
check("negative: a drop-in of the same name that is not fabric's is refused, left alone",
      refused(ahc.apply_host_ssh_cert, V, [host_cert], CA, check=sshd_says, reload=lambda: None, match="not fabric's")
      and open(ahc.DROPIN).read() == "HostCertificate /etc/ssh/mine.pub\n")
os.remove(ahc.DROPIN)

# ---------------------------------------------------------------- one signing run, with stand-ins
print("--- one signing run (OpenBao and the directory stood in)")
cfg = os.path.join(W, "config")
os.makedirs(cfg)
with open(os.path.join(cfg, "member.json"), "w") as f:
    f.write('{"account": "FAB1"}')
for k in ("fab1", "ws2", "ws3"):
    keygen(k)
hostkeys = os.path.join(W, "hostkeys")
os.makedirs(hostkeys)
with open(os.path.join(hostkeys, "ssh_host_ed25519_key.pub"), "w") as f:
    f.write(open(os.path.join(W, "fab1.pub")).read())
DIR = {"fab1": {"name": "fab1", "account": "FAB1$", "ou": "fabric-hosts", "managed": True, "enabled": True,
                "prepared": True, "keys": [], "certs": []},
       "ws1": {"name": "ws1", "account": "WS1$", "ou": "machines", "managed": True, "enabled": True,
               "prepared": False, "keys": [HOST_KEY], "certs": []},
       "ws2": {"name": "ws2", "account": "WS2$", "ou": "machines", "managed": False, "enabled": True,
               "prepared": False, "keys": [open(os.path.join(W, "ws2.pub")).read().strip()],
               "certs": [certify("ca", "ws2", ["ws2"])]},
       "ws3": {"name": "ws3", "account": "WS3$", "ou": "machines", "managed": True, "enabled": True,
               "prepared": True, "keys": [open(os.path.join(W, "ws3.pub")).read().strip()], "certs": []},
       "old": {"name": "old", "account": "OLD$", "ou": "machines", "managed": True, "enabled": False,
               "prepared": True, "keys": [HOST_KEY], "certs": []}}
CALLS = []


def op(name, args):
    CALLS.append((name, args))
    if name == "prepare_ssh_hosts":
        done = [n for n, h in DIR.items() if h["managed"] and h["enabled"] and not h["prepared"]]
        for n in done:
            DIR[n]["prepared"] = True
        return {"prepared": done}
    if name == "list_ssh_hosts":
        return [dict(h) for h in DIR.values()]
    if name == "set_ssh_host":
        h = DIR[args["name"].lower()]
        if "keys" in args:
            h["keys"] = list(args["keys"])
        if "certs" in args:
            h["certs"] = list(args["certs"])
        return {"name": args["name"], "changed": True}
    raise AssertionError(name)


def sign(v, token, key_line, principals, key_id):
    if "ws3" in principals:
        raise ValidationError("OpenBao did not sign the host key: stand-in refusal")
    with open(os.path.join(W, "tosign.pub"), "w") as f:
        f.write(key_line + "\n")
    return certify("ca", "tosign", principals)


shs.bao_request = lambda v, method, path, token=None, body=None: (200, {"data": {"public_key": CA}})
applied = []
run_v = {"ssh_certificates": True, "ad_domain": "ad.lan.test", "domain": "lan.test", "hostname": "fab1",
         "site_name": "lan"}
kw = dict(login=lambda v, creds: "token", op=op, sign=sign,
          apply=lambda v, certs, ca: applied.append((list(certs), ca)) or ["applied"],
          host_keys=os.path.join(hostkeys, "ssh_host_*_key.pub"), now=NOW)
off = shs.sign_ssh_hosts({**run_v, "ssh_certificates": False}, cfg, **kw)
check("off: nothing asked of OpenBao or the directory; this host's part removed",
      off["on"] is False and not CALLS and applied == [([], "")], (off, CALLS))
applied.clear()
res = shs.sign_ssh_hosts(run_v, cfg, **kw)
rows = {m["name"]: m for m in res["machines"]}
ws1 = [parse_ssh_cert(x) for x in DIR["ws1"]["certs"]]
check("on: ws1 prepared, its key signed for its names and written back to its account",
      res["prepared"] == ["ws1"] and rows["ws1"]["signed"] == 1 and len(ws1) == 1
      and ws1[0]["principals"] == NAMES and ws1[0]["kind"] == "host", (res, DIR["ws1"]))
check("this host's keys published on its account and signed; its certificate applied here with the host CA",
      DIR["fab1"]["keys"] == [" ".join(open(os.path.join(W, "fab1.pub")).read().split()[:2])]
      and rows["fab1"]["signed"] == 1 and applied and applied[-1][1] == CA
      and parse_ssh_cert(applied[-1][0][0])["principals"] == ["fab1", "fab1.ad.lan.test", "fab1.lan.test"],
      (rows.get("fab1"), applied))
check("negative: ws2 is not managed: its certificate withdrawn, audited", rows["ws2"]["withdrawn"]
      and DIR["ws2"]["certs"] == [] and ("SSH_HOST_WITHDRAW", "ws2: not managed or disabled") in AUDIT, rows["ws2"])
check("negative: a disabled machine is not signed", "old" not in rows and DIR["old"]["certs"] == [], rows)
check("negative: OpenBao refusing ws3 is reported for ws3; the others are signed",
      "stand-in refusal" in rows["ws3"]["error"] and rows["ws1"]["signed"] == 1, rows["ws3"])
check("audited: SSH_HOST_SIGN for each machine signed",
      any(e == "SSH_HOST_SIGN" and d.startswith("ws1: 1 signed for ws1,ws1.ad.lan.test,ws1.lan.test")
          for e, d in AUDIT), AUDIT)
CALLS.clear()
again = shs.sign_ssh_hosts(run_v, cfg, **kw)
check("a second run: every valid certificate kept, nothing signed or written",
      all(m["signed"] == 0 for m in again["machines"] if m["name"] != "ws3")
      and not [c for c in CALLS if c[0] == "set_ssh_host" and "certs" in c[1]], (again, CALLS))
DIR["fab1"]["managed"] = False
applied.clear()
shs.sign_ssh_hosts(run_v, cfg, **kw)
check("this host taken out of lan-fabric-machines: its own part removed (no consent beyond the member step)",
      applied == [([], "")] and DIR["fab1"]["certs"] == [], applied)
DIR["fab1"]["managed"] = True
shs.bao_request = lambda v, method, path, token=None, body=None: (404, {"errors": []})
check("negative: OpenBao has no host CA: refused, saying how to make it",
      refused(shs.sign_ssh_hosts, run_v, cfg, match="no SSH host CA", **kw))

# ---------------------------------------------------------------- the command
print("--- fabricctl domain ssh-hosts")


def domain_cmd(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = m_rdc.run_domain_command(run_v, list(argv))
    return code, out.getvalue()


# covers: cli:domain.ssh-hosts -
check("negative: an unknown option is a usage error (exit 2)", domain_cmd("ssh-hosts", "--now")[0] == 2)
m_rdc.sign_ssh_hosts = lambda v, config_dir, actor, source: (_ for _ in ()).throw(
    ValidationError("OpenBao is locked"))
code, text = domain_cmd("ssh-hosts", "--scheduled")
check("negative: OpenBao locked: refused (exit 1), saying why", code == 1 and "refused: OpenBao is locked" in text,
      (code, text))
m_rdc.sign_ssh_hosts = lambda v, config_dir, actor, source: {
    "on": True, "ca_fingerprint": CA_FP, "prepared": ["ws1"], "host": ["/etc/ssh/fabric-host-cert-ed25519.pub: written"],
    "machines": [{"name": "ws1", "signed": 1, "kept": 0, "refused": [], "withdrawn": False, "error": ""},
                 {"name": "ws2", "signed": 0, "kept": 0, "refused": [], "withdrawn": True, "error": ""}]}
code, text = domain_cmd("ssh-hosts")
# covers: cli:domain.ssh-hosts +
check("on: says the CA, what it prepared, signed and withdrew, and what changed here (exit 0)",
      code == 0 and CA_FP in text and "ws1: may publish its host keys now" in text and "ws1: 1 signed, 0 kept" in text
      and "ws2: certificates withdrawn" in text and "fabric-host-cert-ed25519.pub: written" in text, text)
m_rdc.sign_ssh_hosts = lambda v, config_dir, actor, source: {"on": False, "ca_fingerprint": "", "prepared": [],
                                                              "machines": [], "host": []}
code, text = domain_cmd("ssh-hosts", "--scheduled")
check("off: says so (exit 0)", code == 0 and "SSH certificates are off" in text, text)

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
