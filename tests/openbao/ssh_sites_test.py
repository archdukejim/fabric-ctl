#!/usr/bin/env python3
"""SSH between sites (decision 2.1.7.14; manual 1.6.11.9.13 to 1.6.11.9.16), container-free: who gets a certificate and
which principals it names (`<user>@<site>`, one per site whose `<site>-ssh-users` the person is in), refused for
anyone in no such group, for root and while off; the SSH page's answer; what a site's machines trust from the
organisation's CAs (every site's host CA for its own names, the user CAs of this site and of the writable-DC sites
only); the known-hosts block from those lines; and the machines' principals command, rendered from the join script
and run: `<user>@<its site>` for a plain name, nothing otherwise. The real DC and machines: tests/samba/linux_join.py
and tests/samba/dc.py (written, not run).

    python3 tests/openbao/ssh_sites_test.py         (needs ssh-keygen and bash; on Linux: the audit log uses syslog)
"""
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.vault.ssh import sign_ssh_key as ssk  # noqa: E402
from fabriclib.vault.ssh.known_hosts_block import BEGIN, END, known_hosts_block  # noqa: E402
from fabriclib.vault.ssh.org_ssh_trust import org_ssh_trust  # noqa: E402
from fabriclib.vault.ssh.ssh_overview import ssh_overview  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp(prefix="fabric-ssh-sites-")
AUDIT = []
ssk.write_audit = lambda actor, event, detail, source="web", **kw: AUDIT.append((actor, event, detail))


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def refused(fn, *args, match="", **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        return match.lower() in str(exc).lower()
    return False


def keygen(name):
    path = os.path.join(W, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path], check=True)
    return " ".join(open(path + ".pub").read().split()[:2])


# ---------------------------------------------------------------- the certificate's principals
print("--- who gets a certificate, naming which sites")
GROUPS = {"alice": ["site3", "site2"], "carol": ["site2"], "bob": []}    # each person's sites' SSH users groups
asked = []


def sites_check(v, user):
    """Stands in for the directory's in-chain membership of every site's <site>-ssh-users (ssh_user_sites)."""
    return GROUPS.get(user, [])


def bao(v, method, path, token=None, body=None):
    asked.append((path, body))
    return 200, {"data": {"signed_key": "ssh-ed25519-cert-v01@openssh.com AAAAstandin", "serial_number": "42"}}


ssk.bao_request = bao
login = lambda v, creds: "token"    # noqa: E731
V = {"ssh_certificates": True, "site_name": "site2", "ad_domain": "ad.test", "domain": "site2.test"}
alice_pub = keygen("alice")
# covers: agent:post.ssh.sign +
cert = ssk.sign_ssh_key(V, "alice", alice_pub, sites_check=sites_check, login=login)
check("a member of site2's and site3's SSH users groups (asking at site2): one certificate naming alice@site2 and "
      "alice@site3, sorted, audited with them",
      cert["principals"] == ["alice@site2", "alice@site3"] and asked[-1][1]["valid_principals"]
      == "alice@site2,alice@site3" and asked[-1][1]["cert_type"] == "user" and AUDIT[-1][:2] == ("alice", "SSH_SIGN")
      and "alice@site2,alice@site3" in AUDIT[-1][2], (cert, asked[-1], AUDIT[-1]))
check("never the bare user name (a machine with no principals check would take it for any site)",
      "alice" not in asked[-1][1]["valid_principals"].split(","), asked[-1])
cert = ssk.sign_ssh_key(V, "carol", alice_pub, sites_check=sites_check, login=login)
check("a member of site2's only: carol@site2 only (site3's machines will refuse her)", cert["principals"]
      == ["carol@site2"], cert)
asked.clear()
# covers: agent:post.ssh.sign -
check("negative: bob, in no site's SSH users group: refused, saying where to ask, audited, OpenBao never asked",
      refused(ssk.sign_ssh_key, V, "bob", alice_pub, sites_check=sites_check, login=login, match="SSH users group")
      and AUDIT[-1][:2] == ("bob", "SSH_SIGN_REFUSED") and not asked, AUDIT[-1])
GROUPS["root"] = ["site2"]
check("negative: a user named root: refused even in a group, audited",
      refused(ssk.sign_ssh_key, V, "rOOt", alice_pub, sites_check=sites_check, login=login, match="root")
      and AUDIT[-1][1] == "SSH_SIGN_REFUSED" and not asked)
check("negative: SSH certificates off: refused", refused(ssk.sign_ssh_key, {**V, "ssh_certificates": False}, "alice",
                                                         alice_pub, sites_check=sites_check, login=login, match="off"))
check("negative: a private key: refused before the directory is asked",
      refused(ssk.sign_ssh_key, V, "alice", open(os.path.join(W, "alice")).read(), sites_check=sites_check,
              login=login, match="private key"))

print("--- the SSH page")
DEPLOY = os.path.join(W, "deploy")
os.makedirs(os.path.join(DEPLOY, "nginx", "www", "certs"))
ov = ssh_overview({**V, "deploy_base_dir": DEPLOY}, "alice", sites_check=sites_check)
check("alice may sign; the page names her sites", ov["may_sign"] and ov["sites"] == ["site2", "site3"], ov)
ov = ssh_overview({**V, "deploy_base_dir": DEPLOY}, "bob", sites_check=sites_check)
check("negative: bob may not, and is told why", not ov["may_sign"] and ov["sites"] == []
      and "SSH users group" in ov["why_not"], ov)


def broken(v, user):
    raise ValidationError("the directory is not reachable")


ov = ssh_overview({**V, "deploy_base_dir": DEPLOY}, "alice", sites_check=broken)
check("negative: the directory unreachable: may not, said", not ov["may_sign"] and "could not be asked" in ov["why_not"])

# ---------------------------------------------------------------- the organisation's CAs
print("--- what a site's machines trust")
CA = {s: {"user": keygen(f"{s}-user-ca"), "host": keygen(f"{s}-host-ca")} for s in ("site1", "site2", "site3", "rodc4")}
ORG = [{"site": "site1", "user_ca": CA["site1"]["user"], "host_ca": CA["site1"]["host"], "domain": "site1.test",
        "writable": True},
       {"site": "site2", "user_ca": CA["site2"]["user"], "host_ca": CA["site2"]["host"], "domain": "site2.test",
        "writable": True},
       {"site": "site3", "user_ca": CA["site3"]["user"], "host_ca": CA["site3"]["host"], "domain": "Site3.Test.",
        "writable": True},
       {"site": "rodc4", "user_ca": CA["rodc4"]["user"], "host_ca": CA["rodc4"]["host"], "domain": "rodc4.test",
        "writable": False},
       {"site": "junk", "user_ca": "not a key", "host_ca": "ssh-dss AAAA", "domain": "junk.test", "writable": True}]
t = org_ssh_trust(V, CA["site2"]["user"], CA["site2"]["host"], ORG)
check("site2 trusts its own host CA for the domain's names and short names, first",
      t["known"][0] == f"@cert-authority *.ad.test,*.site2.test {CA['site2']['host']}"
      and t["known"][1] == f"@cert-authority *,!*.*,!*:* {CA['site2']['host']}", t["known"][:2])
check("a site2 client verifies a site3 machine's host certificate through site3's host CA, for site3's names only",
      f"@cert-authority *.ad.test,*.site3.test {CA['site3']['host']}" in t["known"]
      and not any(CA["site3"]["host"] in line and "*,!*" in line for line in t["known"]), t["known"])
check("every site's host CA is trusted, a read-only DC's site's too (trust proves identity only)",
      all(any(CA[s]["host"] in line for line in t["known"]) for s in ("site1", "site3", "rodc4")), t["known"])
check("user CAs: site2's own first, then the writable-DC sites'; never a read-only DC's site's",
      t["user_cas"][0] == CA["site2"]["user"] and CA["site1"]["user"] in t["user_cas"]
      and CA["site3"]["user"] in t["user_cas"] and CA["rodc4"]["user"] not in t["user_cas"], t["user_cas"])
check("negative: keys that do not parse (or DSA) are left out", len(t["known"]) == 5 and len(t["user_cas"]) == 3
      and not any("junk" in line for line in t["known"]), t)
t_rodc = org_ssh_trust({**V, "site_name": "rodc4", "domain": "rodc4.test"}, CA["rodc4"]["user"], CA["rodc4"]["host"],
                       ORG)
check("a read-only DC's site trusts its own user CA for its own machines", t_rodc["user_cas"][0] == CA["rodc4"]["user"],
      t_rodc)
t_off = org_ssh_trust(V, "", "", ORG)
check("nothing of this site's own (its CAs not made here): only the others', no short-name line",
      len(t_off["known"]) == 3 and not any("*,!*" in line or CA["site2"]["host"] in line for line in t_off["known"])
      and t_off["user_cas"] == [CA["site1"]["user"], CA["site3"]["user"]], t_off)
block = known_hosts_block(CA["site2"]["host"], ["ad.test", "site2.test"], [CA["site1"]["host"]], t["known"])
lines = block.splitlines()
check("the known-hosts block from the organisation's lines, the @revoked lines after them",
      lines[0] == BEGIN and lines[-1] == END and lines[1:6] == t["known"]
      and lines[6] == f"@revoked * {CA['site1']['host']}", lines)
check("without the organisation's lines: the site's own two, as before",
      known_hosts_block(CA["site2"]["host"], ["ad.test", "site2.test"]).splitlines()[1:3]
      == t["known"][:2])

# ---------------------------------------------------------------- the machines' principals command
print("--- the principals command on a site's machines")
text = open(os.path.join(REPO, "templates", "nginx", "www", "certs", "join-linux.sh.j2"), encoding="utf-8").read()
body = re.search(r"<<PRINCIPALS_EOF \|\| true\n(.*?)\nPRINCIPALS_EOF\n", text, re.S).group(1)
script = os.path.join(W, "fabric-ssh-principals")
made = subprocess.run(["bash", "-c", f"cat <<PRINCIPALS_EOF\n{body}\nPRINCIPALS_EOF\n"], capture_output=True,
                      text=True, env={**os.environ, "SITE": "site3"})
with open(script, "w") as f:
    f.write(made.stdout)


def principals(user):
    return subprocess.run(["bash", script, user], capture_output=True, text=True).stdout


check("site3's machine accepts alice@site3 for alice (the principal alice's certificate carries)",
      principals("alice") == "alice@site3\n", principals("alice"))
check("negative: carol's certificate (carol@site2 only) matches nothing site3 accepts for carol",
      "carol@site2" not in principals("carol"))
for bad in ("", "a b", "x;rm", "a\nb", "$(id)"):
    check(f"negative: a user name that is not plain ({bad!r}): no principal at all", principals(bad) == "",
          principals(bad))
check("the drop-in names the command, as root-owned with an absolute path (sshd's requirement)",
      "AuthorizedPrincipalsCommand $PRINCIPALS %u" in text and "PRINCIPALS=/usr/local/sbin/fabric-ssh-principals"
      in text and 'chown root:root "$PRINCIPALS"' in text)

print("\nall passed (0 failures)" if not FAILED else f"\nFAILED ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
