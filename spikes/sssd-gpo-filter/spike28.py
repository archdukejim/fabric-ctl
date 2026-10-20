"""Spike (throwaway, never merged), follow-up: why sssd 2.8 (Debian 12) drops a GPO security-filtered to a computer
group, and which filtering form it applies. A real Samba AD DC and real Debian 12 (sssd 2.8.x) and Debian 13
(sssd 2.9+/2.10, the control) members joined by fabric's join-linux.sh, as spike.py runs them. One GPO giving
SeRemoteInteractiveLogonRight to gu1 only, linked at OU=machines; its DACL changed per case. Applied: gu2 is refused
over SSH. Not applied: gu2 allowed (no other GPO there sets the right).
    sudo python3 spikes/sssd-gpo-filter/spike28.py        (SPIKE_KEEP=1 leaves the containers)
Names are spike28-* so they never meet another suite's.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "tests", "samba")]
import start_dc as start_dc_mod  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

start_dc_mod.IMAGE = "spike28/samba:test"          # never retag the image other suites use
W = "/var/tmp/spike28-work"
NET, SUBNET, IP, WEB_IP = "spike28-net", "10.254.128.0/24", "10.254.128.10", "10.254.128.20"
DC, WEB = "spike28-dc", "spike28-certs"
MEMBERS = {"sd12": "debian:12", "sd13": "debian:13"}
BOX = {m: f"spike28-{m}" for m in MEMBERS}
PW = "Correct-Horse-9-" + random_password(8)
APPLY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
GPO = "spike28: remote to gu1"
SPIKE_NAMES = ["G1", "UG1", "SD12$", "SD13$"]
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
    sh(["docker", "rm", "-f", DC, WEB, *BOX.values()], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def allowed(m, user, service="sshd"):
    code, _ = on(BOX[m], f"pamtester {service} {user} acct_mgmt")
    return code == 0


def mark(label):
    tag = "SPIKEMARK-" + "".join(c for c in label.split(":")[0] if c.isalnum()) + f"-{int(time.time())}"
    for b in BOX.values():
        on(b, f"for f in /var/log/sssd/sssd_*.log; do echo '{tag}' >> \"$f\"; done")
    return tag


def gpo_log(m, tag):
    _, out = on(BOX[m], f"cat /var/log/sssd/sssd_*.log | sed -n '/{tag}/,$p' | grep -E "
                        "'ad_gpo_evaluate_dacl|ad_gpo_filter_gpos_by_dacl|group_sids|user_sid|host_sid|RESULTANT|"
                        "allowed_sids|access denied|applicable|Trustee|ad_gpo_access_check' "
                        "| sed -E 's/^\\([^)]*\\) //' | cut -c1-240 | tail -60")
    return out


def case(label, aces, users=("gu1", "gu2")):
    dc_op(op="aces", name=GPO, aces=aces, spike_names=SPIKE_NAMES)
    time.sleep(7)
    tag = mark(label)
    res = {}
    for m in MEMBERS:
        r = {u: ("allow" if allowed(m, u) else "deny") for u in users}
        applied = r["gu2"] == "deny" and r["gu1"] == "allow"
        res[m] = {"sshd": r, "applied": applied}
        res[m]["log"] = gpo_log(m, tag)
    note(f"{label}: aces={aces} -> " + ", ".join(f"{m}: {res[m]['sshd']} applied={res[m]['applied']}" for m in MEMBERS))
    return res


cleanup()
results = {}
try:
    dc = start_dc_mod.start_dc(os.path.join(W, "dc"), DC, NET, SUBNET, IP)
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
              "samdb, lp = open_samdb('/data/etc/smb.conf')\npw = sys.stdin.readline().strip()\n")
    sh(["docker", "exec", "-i", DC, "python3", "-c", set_pw + "samdb.setpassword('(sAMAccountName=adam)', pw, "
        "force_change_at_next_login=False)\nprint('set')"], input=PW + "\n")
    for g in ("G1", "UG1"):
        samba_tool("group", "add", g, "--groupou=OU=groups")
    samba_tool("group", "addmembers", "UG1", "gu2")     # people only: the GPO applies when gu2 signs in
    shown = dc_op(op="show", link_dn=MACHINES)
    results["samba"] = shown["samba"]
    note(f"linked at OU=machines before the spike: {json.dumps(shown['gpos'])}")

    os.makedirs(os.path.join(W, "www", "certs"), exist_ok=True)
    with open(os.path.join(W, "www", "certs", "root-ca.crt"), "w") as f:
        f.write(open(dc["root_ca"]).read())
    sh(["docker", "run", "-d", "--name", WEB, "--network", NET, "--ip", WEB_IP, "-v", f"{W}/www:/srv:ro",
        "--memory", "128m", "--entrypoint", "python3", start_dc_mod.IMAGE, "-m", "http.server", "80",
        "--directory", "/srv"])
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
    for m, image in MEMBERS.items():
        sh(["docker", "run", "-d", "--name", BOX[m], "--hostname", m, "--network", NET, "--memory", "512m",
            f"--add-host={V['hostname_dc']}:{IP}", f"--add-host={V['hostname_stepca']}:{WEB_IP}",
            f"--add-host={V['hostname_ntp']}:{IP}", "--cap-add", "DAC_READ_SEARCH",
            "-v", f"{W}/join-linux.sh:/root/join-linux.sh:ro", "-v", f"{W}/systemctl:/usr/local/sbin/systemctl:ro",
            image, "sleep", "infinity"])
        code, out = on(BOX[m], "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq "
                               "pamtester sudo procps libcap2-bin openssh-server ldb-tools >/dev/null; mkdir -p /run/sshd")
        code, out = on(BOX[m], f"bash /root/join-linux.sh {fp} --user adam --unmanaged", stdin=PW + "\n")
        if code:
            raise SystemExit(f"{m} join failed: " + out[-1500:])
        note(f"{m} joined: " + out.strip().splitlines()[-1])
        on(BOX[m], "sed -i '/^\\[domain\\//a debug_level = 9' /etc/sssd/sssd.conf")
        samba_tool("group", "addmembers", "G1", f"{m.upper()}$")
        results[f"{m}_versions"] = on(BOX[m], "sssd --version; dpkg-query -W sssd-ad; . /etc/os-release; "
                                              "echo $PRETTY_NAME")[1]
        note(f"{m}: {results[m + '_versions']!r}")
    for m in MEMBERS:
        on(BOX[m], "systemctl restart sssd")
    time.sleep(10)
    results["sids"] = dc_op(op="sids", names=["G1", "UG1", "SD12$", "SD13$", "gu1", "gu2"])
    note(f"sids: {results['sids']}")
    results["sssd.conf"] = on(BOX["sd12"], "cat /etc/sssd/sssd.conf")[1]
    results["baseline"] = {m: {u: allowed(m, u) for u in ("gu1", "gu2")} for m in MEMBERS}
    note(f"baseline (no spike GPO, True = allowed): {results['baseline']}")

    AU_READ = "(A;CI;RPLCLORC;;;AU)"
    dc_op(op="gpo", name=GPO, link_dn=MACHINES, rights={"SeRemoteInteractiveLogonRight": ["gu1"]},
          aces=[AU_READ, f"(OA;CI;CR;{APPLY};;AU)"], spike_names=SPIKE_NAMES)
    time.sleep(7)
    results["control_unfiltered"] = case("control: unfiltered (AU Read + Apply)", [AU_READ, f"(OA;CI;CR;{APPLY};;AU)"])
    # fabric's form today (set_gpo_filter): AU Read, the group Read + Apply
    results["A_fabric"] = case("A fabric: AU Read; G1 Read + Apply (object ACE)",
                               [AU_READ, "(A;CI;RPLCLORC;;;{G1})", f"(OA;CI;CR;{APPLY};;{{G1}})"])
    # (a) the machines' own SIDs as well
    results["a_plus_host_sids"] = case("a: fabric's + each machine's SID Read + Apply",
                                       [AU_READ, "(A;CI;RPLCLORC;;;{G1})", f"(OA;CI;CR;{APPLY};;{{G1}})",
                                        "(A;CI;RPLCLORC;;;{SD12$})", f"(OA;CI;CR;{APPLY};;{{SD12$}})",
                                        "(A;CI;RPLCLORC;;;{SD13$})", f"(OA;CI;CR;{APPLY};;{{SD13$}})"])
    results["a_host_sids_apply_only"] = case("a2: AU Read; each machine's SID Apply only (no group)",
                                             [AU_READ, f"(OA;CI;CR;{APPLY};;{{SD12$}})",
                                              f"(OA;CI;CR;{APPLY};;{{SD13$}})"])
    results["a_one_host"] = case("a3: AU Read; SD12$ Apply only (SD13 not named)",
                                 [AU_READ, f"(OA;CI;CR;{APPLY};;{{SD12$}})"])
    # (b) the entry's form
    results["b_plain_group"] = case("b1: AU Read; G1 plain allow with CR (no object type)",
                                    [AU_READ, "(A;CI;RPLCLORCCR;;;{G1})"])
    results["b_no_ci_group"] = case("b2: AU Read; G1 Read + Apply, no inheritance flag",
                                    [AU_READ, "(A;;RPLCLORC;;;{G1})", f"(OA;;CR;{APPLY};;{{G1}})"])
    results["b_plain_host"] = case("b3: AU Read; machines' SIDs plain allow with CR (no object type)",
                                   [AU_READ, "(A;CI;RPLCLORCCR;;;{SD12$})", "(A;CI;RPLCLORCCR;;;{SD13$})"])
    results["b_obj_no_guid_host"] = case("b4: AU Read; machines' SIDs object ACE with CR and no object type",
                                         [AU_READ, "(OA;CI;CR;;;{SD12$})", "(OA;CI;CR;;;{SD13$})"])
    # (c) Authenticated Users' Read removed
    results["c_no_au_group"] = case("c1: no AU entry; G1 Read + Apply",
                                    ["(A;CI;RPLCLORC;;;{G1})", f"(OA;CI;CR;{APPLY};;{{G1}})"])
    results["c_no_au_host"] = case("c2: no AU entry; machines' SIDs Read + Apply",
                                   ["(A;CI;RPLCLORC;;;{SD12$})", f"(OA;CI;CR;{APPLY};;{{SD12$}})",
                                    "(A;CI;RPLCLORC;;;{SD13$})", f"(OA;CI;CR;{APPLY};;{{SD13$}})"])
    # (d) whose SIDs sssd matches: a group of people (UG1 holds gu2; neither machine in it)
    results["d_user_group"] = case("d: AU Read; UG1 (people: gu2) Read + Apply",
                                   [AU_READ, "(A;CI;RPLCLORC;;;{UG1})", f"(OA;CI;CR;{APPLY};;{{UG1}})"])
    # (e) sssd.conf options on the 2.8 member, with fabric's form
    on(BOX["sd12"], "sed -i '/^\\[domain\\//a ad_gpo_ignore_unreadable = True' /etc/sssd/sssd.conf; "
                    "systemctl restart sssd")
    time.sleep(10)
    results["e_ignore_unreadable"] = case("e: sd12 ad_gpo_ignore_unreadable = True; fabric's form",
                                          [AU_READ, "(A;CI;RPLCLORC;;;{G1})", f"(OA;CI;CR;{APPLY};;{{G1}})"])
    # the machine-SID form keeps fabric's security: a machine taken out of G1 but whose SID entry is left stays in
    samba_tool("group", "removemembers", "G1", "SD12$")
    results["f_removed_from_group_sid_kept"] = case(
        "f: SD12$ out of G1; fabric's form + both machines' SID Apply (stale entry for SD12$)",
        [AU_READ, "(A;CI;RPLCLORC;;;{G1})", f"(OA;CI;CR;{APPLY};;{{G1}})",
         f"(OA;CI;CR;{APPLY};;{{SD12$}})", f"(OA;CI;CR;{APPLY};;{{SD13$}})"])
    results["f_removed_entry_dropped"] = case(
        "f2: SD12$ out of G1; fabric's form + SD13$'s SID Apply (entry compiled from membership)",
        [AU_READ, "(A;CI;RPLCLORC;;;{G1})", f"(OA;CI;CR;{APPLY};;{{G1}})", f"(OA;CI;CR;{APPLY};;{{SD13$}})"])
finally:
    os.makedirs(W, exist_ok=True)
    with open(os.path.join(W, "results.json"), "w") as f:
        json.dump({"results": results, "log": LOG}, f, indent=1)
    print("SUMMARY\n" + "\n".join(LOG))
    if not os.environ.get("SPIKE_KEEP"):
        cleanup()
