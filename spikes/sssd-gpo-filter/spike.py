"""Spike (throwaway, never merged): does sssd's ad_gpo_access_control = enforcing honour a GPO's security filtering
(Apply Group Policy granted only to a computer group), and how does it combine one user right set by two GPOs linked
at the same OU? Answers the question design 1.6.13.4 rests on. A real Samba AD DC (tests/samba/start_dc) and a real
Ubuntu 24.04 member joined by fabric's join-linux.sh, as tests/samba/linux_join.py runs them.
    sudo python3 spikes/sssd-gpo-filter/spike.py          (SPIKE_KEEP=1 leaves the containers)
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "tests", "samba")]
from start_dc import start_dc  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

W = "/tmp/fabric-spike-gpo-filter"
NET, SUBNET, IP, WEB_IP = "gpofilter_net", "10.254.61.0/24", "10.254.61.10", "10.254.61.20"
DC, WEB, MACHINE = "gpof-dc", "gpof-certs", "gpofws"
BOX = f"gpof-{MACHINE}"
PW = "Correct-Horse-9-" + random_password(8)
T0 = time.time()
LOG = []


def note(msg):
    line = f"[{time.time() - T0:7.1f}s] {msg}"
    print(line, flush=True)
    LOG.append(line)


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"failed: {cmd[:6]}\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    return res


def on(box, script, stdin=None):
    res = sh(["docker", "exec", "-i", box, "bash", "-c", script], ok=False, input=stdin)
    return res.returncode, res.stdout + res.stderr


def dc_op(**args):
    code = "import json\nARGS = json.loads(" + repr(json.dumps(args)) + ")\n" + open(os.path.join(HERE, "dc_gpo.py")).read()
    res = sh(["docker", "exec", "-i", DC, "python3", "-"], input=code, ok=False)
    for line in res.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise SystemExit(f"dc_op {args.get('op')} failed:\n{res.stdout[-1500:]}{res.stderr[-2500:]}")


def samba_tool(*args):
    return sh(["docker", "exec", DC, "samba-tool", *args, "-s", "/data/etc/smb.conf"], ok=False)


def cleanup():
    sh(["docker", "rm", "-f", DC, WEB, BOX], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def allowed(user, service="sshd"):
    """sssd's access check through PAM's account phase (where ad_gpo_access_control runs): sshd maps to
    SeRemoteInteractiveLogonRight, login to SeInteractiveLogonRight (sssd's default ad_gpo_map_* lists)."""
    code, out = on(BOX, f"pamtester {service} {user} acct_mgmt")
    return code == 0


def state(label, users=("gu1", "gu2"), services=("sshd",)):
    res = {f"{u}/{s}": ("allow" if allowed(u, s) else "deny") for u in users for s in services}
    note(f"{label}: {res}")
    return res


def gpo_log(since_marker):
    """sssd's own words about GPO filtering and rights since a marker line."""
    code, out = on(BOX, f"cat /var/log/sssd/sssd_*.log | sed -n '/{since_marker}/,$p' | grep -iE 'gpo|sid' "
                        "| sed -E 's/^\\([^)]*\\) //' | cut -c1-260 | tail -60")
    return out


def mark(label):
    m = f"SPIKEMARK-{label}-{int(time.time())}"
    on(BOX, f"for f in /var/log/sssd/sssd_*.log; do echo '{m}' >> \"$f\"; done")
    return m


def poll(cond, limit, every=15):
    start = time.time()
    while time.time() - start < limit:
        if cond():
            return round(time.time() - start)
        time.sleep(every)
    return None


def restart_sssd():
    on(BOX, "systemctl restart sssd")       # the shim: kills sssd, clears its cache, starts it as its unit does
    time.sleep(10)


cleanup()
results = {}
try:
    dc = start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
    V, SECRETS = dc["v"], dc["secrets"]
    BASE = V["ad_base_dn"]
    MACHINES = f"OU=machines,{BASE}"
    note("DC converged")
    for uid in ("adam", "gu1", "gu2"):
        run_op(V, SECRETS, "create_person", {"uid": uid, "first": uid.title(), "last": "Test",
                                              "email": f"{uid}@lan.test", "password": "Ot-" + random_password(20),
                                              "gid": 5000, "home_base": "/home", "shell": "/bin/bash"}, DC)
    run_op(V, SECRETS, "add_group_member", {"group": "directory-admins", "uid": "adam"}, DC)
    set_pw = ("import sys\nsys.path.insert(0, '/fabric')\nfrom open_samdb import open_samdb\n"
              "samdb, lp = open_samdb('/data/etc/smb.conf')\nimport sys as s\npw = s.stdin.readline().strip()\n")
    sh(["docker", "exec", "-i", DC, "python3", "-c", set_pw + "samdb.setpassword('(sAMAccountName=adam)', pw, "
        "force_change_at_next_login=False)\nprint('set')"], input=PW + "\n")
    for g in ("G1", "G2", "G3", "UG1"):          # computer groups G1-G3; UG1 a group of people (gu1)
        samba_tool("group", "add", g, f"--groupou=OU=groups")
    samba_tool("group", "addmembers", "UG1", "gu1")
    shown = dc_op(op="show", link_dn=MACHINES)
    results["samba"] = shown["samba"]
    note(f"what D1 links at OU=machines before the spike: {json.dumps(shown['gpos'])}")

    # the member, joined as linux_join.py joins one (a server: OU=servers,OU=machines)
    os.makedirs(os.path.join(W, "www", "certs"), exist_ok=True)
    with open(os.path.join(W, "www", "certs", "root-ca.crt"), "w") as f:
        f.write(open(dc["root_ca"]).read())
    sh(["docker", "run", "-d", "--name", WEB, "--network", NET, "--ip", WEB_IP, "-v", f"{W}/www:/srv:ro",
        "--entrypoint", "python3", "fabric/samba:test", "-m", "http.server", "80", "--directory", "/srv"])
    fp = sh(["openssl", "x509", "-in", dc["root_ca"], "-noout", "-fingerprint", "-sha256"]).stdout.strip().split("=")[1]
    with open(os.path.join(W, "join-linux.sh"), "w") as f:
        f.write(dc["env"].get_template("nginx/www/certs/join-linux.sh.j2").render(
            **{**V, "install_keycloak": True, "signin_kerberos": True}))
    shim = open(os.path.join(REPO, "tests", "samba", "linux_join.py")).read()
    shim = shim[shim.index('SHIM = r"""') + 11:]
    shim = shim[:shim.index('"""')]
    with open(os.path.join(W, "systemctl"), "w") as f:
        f.write(shim)
    os.chmod(os.path.join(W, "systemctl"), 0o755)
    sh(["docker", "run", "-d", "--name", BOX, "--hostname", MACHINE, "--network", NET,
        f"--add-host={V['hostname_dc']}:{IP}", f"--add-host={V['hostname_stepca']}:{WEB_IP}",
        f"--add-host={V['hostname_ntp']}:{IP}", "--cap-add", "DAC_READ_SEARCH",
        "-v", f"{W}/join-linux.sh:/root/join-linux.sh:ro", "-v", f"{W}/systemctl:/usr/local/sbin/systemctl:ro",
        "ubuntu:24.04", "sleep", "infinity"])
    code, out = on(BOX, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq "
                        "pamtester sudo procps libcap2-bin openssh-server ldb-tools >/dev/null; mkdir -p /run/sshd")
    code, out = on(BOX, f"bash /root/join-linux.sh {fp} --user adam", stdin=PW + "\n")
    if code:
        raise SystemExit("join failed: " + out[-1500:])
    note("joined: " + out.strip().splitlines()[-1])
    # sssd's own log of its GPO decisions (debug level only; nothing else in the join's sssd.conf changes)
    on(BOX, "sed -i '/^\\[domain\\//a debug_level = 6' /etc/sssd/sssd.conf")
    for g in ("G1", "G2"):
        samba_tool("group", "addmembers", g, f"{MACHINE.upper()}$")
    restart_sssd()
    results["versions"] = on(BOX, "sssd --version; dpkg-query -W sssd-ad; . /etc/os-release; echo $PRETTY_NAME")[1]
    results["sssd.conf"] = on(BOX, "cat /etc/sssd/sssd.conf")[1]
    note(f"versions: {results['versions']!r}")
    results["baseline"] = state("baseline, no spike GPO (both rights)", services=("sshd", "login"))

    # case 4: a GPO filtered to a group the member is not in (G3): ignored
    r = dc_op(op="gpo", name="spike: C4 G3 only", link_dn=MACHINES, filter="G3",
              rights={"SeRemoteInteractiveLogonRight": ["gu1"]})
    note(f"C4 GPO {r['guid']} sd: {r['sd_after']}")
    note(f"C4 default sd (as ensure_gpo made it): {r['sd_before']}")
    time.sleep(7)
    m = mark("C4")
    results["case4"] = state("C4: GPO granting remote to gu1, filtered to G3 (member not in G3)")
    results["case4_log"] = gpo_log(m)
    dc_op(op="unlink", name="spike: C4 G3 only", link_dn=MACHINES)

    # control: the same GPO unfiltered (Authenticated Users apply it) is enforced
    r = dc_op(op="gpo", name="spike: C0 unfiltered", link_dn=MACHINES, filter=None,
              rights={"SeRemoteInteractiveLogonRight": ["gu1"]})
    time.sleep(7)
    results["control"] = state("C0 control: same GPO unfiltered (AU apply)")
    dc_op(op="unlink", name="spike: C0 unfiltered", link_dn=MACHINES)

    # case 1: filtered to G1 (holds the member), remote log-on to gu1 only
    r = dc_op(op="gpo", name="spike: C1 G1", link_dn=MACHINES, filter="G1",
              rights={"SeRemoteInteractiveLogonRight": ["gu1"]})
    note(f"C1 GPO {r['guid']} sd: {r['sd_after']}")
    time.sleep(7)
    m = mark("C1")
    results["case1"] = state("C1: GPO remote->gu1 filtered to G1 (member in G1)", services=("sshd", "login"))
    results["case1_log"] = gpo_log(m)

    # case 3: a second GPO, filtered to G2 (member in it too), remote log-on to gu2 only; both linked at OU=machines
    r = dc_op(op="gpo", name="spike: C3 G2", link_dn=MACHINES, filter="G2",
              rights={"SeRemoteInteractiveLogonRight": ["gu2"]})
    note(f"C3 gPLink (C1 then C3 in the string): {r['gplink']}")
    time.sleep(7)
    m = mark("C3a")
    results["case3_order_a"] = state("C3a: C1(G1,gu1) and C3(G2,gu2) linked, C3 last in gPLink")
    results["case3a_log"] = gpo_log(m)
    r = dc_op(op="order", link_dn=MACHINES, names=["spike: C3 G2", "spike: C1 G1"])
    note(f"C3 gPLink swapped (C3 then C1): {r['gplink']}")
    time.sleep(7)
    m = mark("C3b")
    results["case3_order_b"] = state("C3b: same two, C1 last in gPLink")
    results["case3b_log"] = gpo_log(m)
    dc_op(op="unlink", name="spike: C3 G2", link_dn=MACHINES)
    time.sleep(7)
    results["case1_again"] = state("C1 alone again (C3 unlinked)")

    # case 5 (extra): a GPO filtered to a group of people (UG1 holds gu1, not the machine), remote log-on to gu2 only
    dc_op(op="unlink", name="spike: C1 G1", link_dn=MACHINES)
    dc_op(op="gpo", name="spike: C5 UG1", link_dn=MACHINES, filter="UG1",
          rights={"SeRemoteInteractiveLogonRight": ["gu2"]})
    time.sleep(7)
    m = mark("C5")
    results["case5"] = state("C5: GPO remote->gu2 filtered to UG1 (a people group with gu1; the machine not in it)")
    results["case5_log"] = gpo_log(m)
    dc_op(op="unlink", name="spike: C5 UG1", link_dn=MACHINES)
    r = dc_op(op="gpo", name="spike: C1 G1", link_dn=MACHINES, filter="G1",
              rights={"SeRemoteInteractiveLogonRight": ["gu1"]})
    time.sleep(7)
    results["case1_relinked"] = state("C1 relinked")

    # case 2: the member removed from G1: when does sssd notice, and what then?
    samba_tool("group", "removemembers", "G1", f"{MACHINE.upper()}$")
    note("C2: machine removed from G1")
    t = poll(lambda: allowed("gu2"), 900)
    results["case2_removed_seconds"] = t
    note(f"C2: gu2 allowed again after {t}s (None: not within 900s, sssd untouched)")
    if t is None:
        on(BOX, "sss_cache -E")
        time.sleep(7)
        results["case2_after_sss_cache"] = state("C2 after sss_cache -E")
        if results["case2_after_sss_cache"]["gu2/sshd"] == "deny":
            restart_sssd()
            results["case2_after_restart"] = state("C2 after sssd restart (cache cleared)")
    m = mark("C2")
    results["case2"] = state("C2: member not in G1 (C1 the only spike GPO)")
    results["case2_log"] = gpo_log(m)
    samba_tool("group", "addmembers", "G1", f"{MACHINE.upper()}$")
    note("C2r: machine added back to G1")
    t = poll(lambda: not allowed("gu2"), 900)
    results["case2_readded_seconds"] = t
    note(f"C2r: gu2 denied again after {t}s (None: not within 900s, sssd untouched)")
    if t is None:
        on(BOX, "sss_cache -E")
        time.sleep(7)
        results["case2r_after_sss_cache"] = state("C2r after sss_cache -E")
        if results["case2r_after_sss_cache"]["gu2/sshd"] == "allow":
            restart_sssd()
            results["case2r_after_restart"] = state("C2r after sssd restart")
    results["host_entry"] = on(BOX, f"ls /var/lib/sss/db/; ldbsearch -H /var/lib/sss/db/cache_*.ldb "
                                    f"'(name={MACHINE.upper()}$*)' memberof originalMemberOf dataExpireTimestamp "
                                    f"lastUpdate 2>&1 | head -30")[1]
finally:
    with open(os.path.join(W, "results.json"), "w") as f:
        json.dump({"results": results, "log": LOG}, f, indent=1)
    print("RESULTS " + json.dumps(results, indent=1))
    if not os.environ.get("SPIKE_KEEP"):
        cleanup()
