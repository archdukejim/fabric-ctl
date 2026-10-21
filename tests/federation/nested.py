#!/usr/bin/env python3
"""Nested sites and re-parenting (manual 1.9.5.1) with the real Step-CA image:

the root site `lan` (a root of path length 2: one level of nesting) invites `lab` with --nest 1; lab, now
a site that may hold sites, invites `lab2` (nested under it); lab2 is then re-parented under the root.
Each upstream runs as its own install (tests/federation/role.py, its own tree, vars, secrets and
registry); the joining side runs join_upstream exactly as `fabricctl setup --join` / `reparent` do.
Includes what must be refused (nesting deeper than a CA allows, a site that may not nest inviting).

    sudo python3 tests/federation/nested.py      (needs Docker, openssl, root; run by tests/federation/run.py)
"""
import json
import os
import shutil
import socket
import subprocess
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/federation-nested"
IMAGE = subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
                       capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
USERS = {"step": {"uid": STEP_UID, "gid": STEP_UID}}
ROLE = os.path.join(REPO, "tests", "federation", "role.py")
FAILED = 0
SERVERS = []


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, ok=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def step(home, *args):
    return sh(["docker", "run", "--rm", "--network", "none", "-v", f"{home}:/home/step", "--user",
               f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, *args])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def install(name, site, domain, password, extra=None):
    """An install tree of its own (code, config) and a Step-CA data folder for site `site`."""
    tree = f"{W}/{name}"
    subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", tree], check=True)
    os.makedirs(f"{tree}/fabric/config")
    data = f"{tree}/stepca/data"
    for d in ("certs", "secrets", "artifacts", "config"):
        os.makedirs(f"{data}/{d}")
    with open(f"{data}/secrets/password", "w") as f:
        f.write(password)
    v = {"deploy_base_dir": tree, "image_stepca": IMAGE, "service_users": USERS, "site_name": site, "domain": domain,
         "org_domain": "lan.test", "ldap_base_dn": "dc=lan", "host_ip": "127.0.0.1",
         "hostname_federation": f"federation.{domain}", "federation_endpoint": True, "cert_intermediate_days": 1095,
         "ldap_organizational_units": [{"name": "accounts"}, {"name": "groups"}], "ad_domain": "ad.lan.test",
         "hostname_dc": f"dc.{domain}", "ad_password_policy": {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0, "maximum_age_days": 0, "lockout_threshold": 5, "lockout_minutes": 15, "lockout_window_minutes": 15}, **(extra or {})}
    with open(f"{tree}/fabric/config/vars.yaml", "w") as f:
        yaml.safe_dump(v, f)
    return tree, data, v


def role(tree, *args):
    out = sh([sys.executable, ROLE, tree, *map(str, args)]).stdout.strip().splitlines()[-1]
    return json.loads(out)


def serve(tree, data, host, issuer_crt, issuer_key, root_pem):
    """The install's federation endpoint (TLS, a certificate from its own CA chain) and its certs page."""
    step(data, "certificate", "create", host, "/home/step/fed.crt", "/home/step/fed.key", "--profile", "leaf",
         "--ca", issuer_crt, "--ca-key", issuer_key, "--ca-password-file", "/home/step/secrets/password",
         "--no-password", "--insecure", "--san", host, "--bundle")
    os.makedirs(f"{tree}/www/certs", exist_ok=True)
    with open(f"{tree}/www/certs/root-ca.crt", "w") as f:
        f.write(root_pem)
    https, http_ = free_port(), free_port()
    p = subprocess.Popen([sys.executable, ROLE, tree, "serve", str(https), str(http_), f"{data}/fed.crt",
                          f"{data}/fed.key", f"{tree}/www"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert p.stdout.readline().strip() == "ready"
    SERVERS.append(p)
    return https, http_


def pathlen(pem_or_path):
    pem = open(pem_or_path).read() if os.path.exists(pem_or_path) else pem_or_path
    return ca_path_len(pem)


def become_upstream(data, staged, root_pem):
    """Lay a joined site's staged CA out as its Step-CA data (what setup's pki step does), so it can sign."""
    with open(f"{data}/certs/root_ca.crt", "w") as f:
        f.write(root_pem)
    shutil.copy(staged["ica_crt_path"], f"{data}/certs/intermediate_ca.crt")
    shutil.copy(staged["ica_parents_path"], f"{data}/certs/ca_parents.crt")
    shutil.copy(staged["ica_key_path"], f"{data}/secrets/intermediate_ca_key")
    sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])


try:
    shutil.rmtree(W, ignore_errors=True)
    main_tree = f"{W}/main"
    subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", main_tree], check=True)
    sys.path.insert(0, f"{main_tree}/fabric/lib")
    from fabriclib.common.errors import ValidationError  # noqa: E402
    from fabriclib.federation.join_upstream import join_upstream  # noqa: E402
    from fabriclib.pki.common.ca_path_len import ca_path_len  # noqa: E402
    from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
    from fabriclib.pki.replace_site_ca import replace_site_ca  # noqa: E402

    # ------------------------------------------------------------ the root site `lan`: a root of path length 2
    lan, lan_data, _ = install("lan", "lan", "lan.test", "Root-Pw-1")
    with open(f"{lan_data}/root.tpl", "w") as f:
        json.dump({"subject": {"commonName": "Lan Root CA"}, "issuer": {"commonName": "Lan Root CA"},
                   "keyUsage": ["certSign", "crlSign"], "basicConstraints": {"isCA": True, "maxPathLen": 2}}, f)
    sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", lan_data])
    step(lan_data, "certificate", "create", "Lan Root CA", "/home/step/certs/root_ca.crt",
         "/home/step/secrets/root_ca_key", "--template", "/home/step/root.tpl", "--kty", "EC", "--curve", "P-256",
         "--not-after", "87600h", "--password-file", "/home/step/secrets/password")
    ROOT = f"{lan_data}/certs/root_ca.crt"
    ROOT_PEM = open(ROOT).read()
    shutil.copy(ROOT, f"{lan_data}/certs/intermediate_ca.crt")          # unused by the root's signing
    cap = role(lan, "capacity")
    check("root (path length 2): signs flat, sites it signs may nest one level", cap == {"as_parent": False, "max_nest": 1},
          cap)
    deep = role(lan, "invite", "deep", 2)
    check("root: --nest 2 is refused (deeper than the root allows)", "more than this install's CA allows" in
          deep.get("error", ""), deep)
    inv_lab = role(lan, "invite", "lab", 1)
    check("root: invites lab flat, allowed one level below it", inv_lab.get("nest") == 1 and not inv_lab.get("nested"),
          inv_lab)
    lan_https, lan_http = serve(lan, lan_data, "federation.lan.test", "/home/step/certs/root_ca.crt",
                                "/home/step/secrets/root_ca_key", ROOT_PEM)

    # ------------------------------------------------------------ lab joins the root (--nest 1)
    SITE = {"image_stepca": IMAGE, "service_users": USERS}
    lab, lab_data, _ = install("lab", "lab", "lab.lan.test", "Lab-Pw-1")
    res = join_upstream(SITE, inv_lab["invitation"], "Lab-Pw-1", f"{lab}/fabric/config/site-ca", "lab.lan.test",
                        "127.0.0.2", config_dir=f"{lab}/fabric/config", audit_path=f"{lab}/audit.log",
                        http_port=lan_http, https_port=lan_https)
    lab_ca = res["vars"]["ica_crt_path"]
    check("lab: its CA is signed by the root with path length 1 (it may hold one level of sites)",
          pathlen(lab_ca) == 1 and describe_cert(open(lab_ca).read())["issuer"] == describe_cert(ROOT_PEM)["subject"])
    check("lab: flat under the root (no parent CAs), the organisation's base DN",
          res["vars"]["site_ca_depth"] == 0 and res["vars"]["ldap_base_dn"] == "dc=lan"
          and open(res["vars"]["ica_parents_path"]).read() == "", res["vars"])

    # ------------------------------------------------------------ lab invites lab2: nested under lab
    become_upstream(lab_data, res["vars"], ROOT_PEM)
    cap = role(lab, "capacity")
    check("lab: signs as a parent; sites it signs may not nest further", cap == {"as_parent": True, "max_nest": 0}, cap)
    too_deep = role(lab, "invite", "lab2", 1)
    check("lab: --nest 1 for lab2 is refused (lab's CA allows none below lab2)",
          "more than this install's CA allows" in too_deep.get("error", ""), too_deep)
    inv_lab2 = role(lab, "invite", "lab2", 0)
    check("lab: invites lab2, nested under lab", inv_lab2.get("nested") is True, inv_lab2)
    lab_https, lab_http = serve(lab, lab_data, "federation.lab.lan.test", "/home/step/certs/intermediate_ca.crt",
                                "/home/step/secrets/intermediate_ca_key", ROOT_PEM)
    lab2, lab2_data, _ = install("lab2", "lab2", "lab2.lan.test", "Lab2-Pw-1")
    res2 = join_upstream(SITE, inv_lab2["invitation"], "Lab2-Pw-1", f"{lab2}/fabric/config/site-ca", "lab2.lan.test",
                         "127.0.0.3", config_dir=f"{lab2}/fabric/config", audit_path=f"{lab2}/audit.log",
                         http_port=lab_http, https_port=lab_https)
    v2 = res2["vars"]
    lab2_ca = open(v2["ica_crt_path"]).read()
    check("lab2: its CA is signed by lab's CA, path length 0",
          pathlen(lab2_ca) == 0 and describe_cert(lab2_ca)["issuer"] == describe_cert(open(lab_ca).read())["subject"])
    check("lab2: one parent CA (lab's) between its CA and the root", v2["site_ca_depth"] == 1
          and open(v2["ica_parents_path"]).read().strip() == open(lab_ca).read().strip(), v2)
    check("lab2: its CA chains to the organisation's root through lab",
          sh(["openssl", "verify", "-CAfile", ROOT, "-untrusted", v2["ica_parents_path"], v2["ica_crt_path"]],
             ok=False).returncode == 0)
    lab_reg = yaml.safe_load(open(f"{lab}/fabric/config/federation.yaml"))
    lab2_reg = yaml.safe_load(open(f"{lab2}/fabric/config/federation.yaml"))
    check("records: lab lists lab2 with parent lab; lab2's upstream is lab",
          lab_reg["sites"]["lab2"]["parent"] == "lab" and lab2_reg["upstream"]["site_name"] == "lab", (lab_reg, lab2_reg))
    become_upstream(lab2_data, v2, ROOT_PEM)
    step(lab2_data, "certificate", "create", "pc.lab2.lan.test", "/home/step/leaf.crt", "/home/step/leaf.key",
         "--profile", "leaf", "--ca", "/home/step/certs/intermediate_ca.crt", "--ca-key",
         "/home/step/secrets/intermediate_ca_key", "--ca-password-file", "/home/step/secrets/password",
         "--no-password", "--insecure", "--san", "pc.lab2.lan.test")
    with open(f"{lab2_data}/chain.pem", "w") as f:
        f.write(lab2_ca + open(lab_ca).read())
    check("lab2: a device certificate it issues verifies against the root",
          sh(["openssl", "verify", "-CAfile", ROOT, "-untrusted", f"{lab2_data}/chain.pem", f"{lab2_data}/leaf.crt"],
             ok=False).returncode == 0)
    no = role(lab2, "invite", "lab3", 0)
    check("lab2: a site whose CA has path length 0 cannot invite sites", "cannot sign sites" in no.get("error", ""), no)

    # ------------------------------------------------------------ lab2 re-parented under the root
    inv_back = role(lan, "invite", "lab2", 0)
    res3 = join_upstream(SITE, inv_back["invitation"], "Lab2-Pw-1", f"{lab2}/fabric/config/site-ca-lan",
                         "lab2.lan.test", "127.0.0.3", config_dir=f"{lab2}/fabric/config",
                         audit_path=f"{lab2}/audit.log", http_port=lan_http, https_port=lan_https, replace=True)
    v3 = res3["vars"]
    check("reparent: lab2's new CA is signed by the root directly, no parent CAs",
          describe_cert(open(v3["ica_crt_path"]).read())["issuer"] == describe_cert(ROOT_PEM)["subject"]
          and v3["site_ca_depth"] == 0, v3)
    with open(f"{lab2_data}/config/ca.json", "w") as f:
        json.dump({"crt": "/home/step/certs/intermediate_ca.crt"}, f)
    replace_site_ca({"deploy_base_dir": lab2, "service_users": USERS}, v3)
    check("reparent: Step-CA's files switch to the new CA (old ones kept), ca.json names the chain",
          open(f"{lab2_data}/certs/intermediate_ca.crt").read().strip() == open(v3["ica_crt_path"]).read().strip()
          and open(f"{lab2_data}/certs/ca_parents.crt").read() == ""
          and os.path.exists(f"{lab2_data}/certs/intermediate_ca.crt.old-1")
          and json.load(open(f"{lab2_data}/config/ca.json"))["crt"] == "/home/step/certs/intermediate_chain.crt")
    check("reparent: lab2's upstream is now the root",
          yaml.safe_load(open(f"{lab2}/fabric/config/federation.yaml"))["upstream"]["site_name"] == "lan")
    other = dict(v3, ca_crt_path=v2["ica_crt_path"])
    try:
        replace_site_ca({"deploy_base_dir": lab2, "service_users": USERS}, other)
        refused = False
    except ValidationError as e:
        refused = "another root" in str(e)
    check("reparent: a CA for another root is refused", refused)

    # ------------------------------------------------------------ a relay node: lab3 joins through edge
    bad = role(lan, "invite-via", "lab3", "nowhere")
    check("relay: a node that is not a site of this install is refused", "no site nowhere joined here" in
          bad.get("error", ""), bad)
    inv_edge = role(lan, "invite", "edge", 0)
    edge, edge_data, _ = install("edge", "edge", "edge.lan.test", "Edge-Pw-1")
    res_e = join_upstream(SITE, inv_edge["invitation"], "Edge-Pw-1", f"{edge}/fabric/config/site-ca", "edge.lan.test",
                          "127.0.0.1", config_dir=f"{edge}/fabric/config", audit_path=f"{edge}/audit.log",
                          http_port=lan_http, https_port=lan_https)
    become_upstream(edge_data, res_e["vars"], ROOT_PEM)
    edge_https, edge_http = serve(edge, edge_data, "federation.edge.lan.test", "/home/step/certs/intermediate_ca.crt",
                                  "/home/step/secrets/intermediate_ca_key", ROOT_PEM)
    inv_lab3 = role(lan, "invite-via", "lab3", "edge")
    body3 = json.loads(__import__("base64").urlsafe_b64decode(inv_lab3["invitation"].split(".", 1)[1] + "==="))
    check("relay: the invitation names edge's endpoint and the organisation's root",
          body3["via"] == "edge" and body3["host"] == "federation.edge.lan.test" and body3["address"] == "127.0.0.1"
          and body3["root_sha256"] == describe_cert(ROOT_PEM)["sha256"], body3)
    lab3, lab3_data, _ = install("lab3", "lab3", "lab3.lan.test", "Lab3-Pw-1")
    res_3 = join_upstream(SITE, inv_lab3["invitation"], "Lab3-Pw-1", f"{lab3}/fabric/config/site-ca", "lab3.lan.test",
                          "127.0.0.5", config_dir=f"{lab3}/fabric/config", audit_path=f"{lab3}/audit.log",
                          http_port=edge_http, https_port=edge_https)
    lab3_ca = open(res_3["vars"]["ica_crt_path"]).read()
    check("relay: lab3's CA is signed by the root (the relay signs nothing), flat",
          describe_cert(lab3_ca)["issuer"] == describe_cert(ROOT_PEM)["subject"] and res_3["vars"]["site_ca_depth"] == 0)
    lan_reg = yaml.safe_load(open(f"{lan}/fabric/config/federation.yaml"))
    lab3_reg = yaml.safe_load(open(f"{lab3}/fabric/config/federation.yaml"))
    check("relay: the root records lab3 as joined through edge; lab3's upstream is the root, through edge",
          lan_reg["sites"]["lab3"]["via"] == "edge" and lab3_reg["upstream"]["site_name"] == "lan"
          and lab3_reg["upstream"]["relay"]["site"] == "edge", (lan_reg["sites"].get("lab3"), lab3_reg["upstream"]))
    check("relay: edge holds no record of lab3 (it only forwarded) and audited the relay",
          "lab3" not in (yaml.safe_load(open(f"{edge}/fabric/config/federation.yaml")) or {}).get("sites", {})
          and "FED_JOIN_RELAYED" in open(f"{edge}/fabric/archive/audit.log").read())
    dropped = role(lab3, "drop-relay")
    check("relay direct: lab3 stops using the relay; a second time is refused",
          dropped.get("site") == "edge" and "relay" not in yaml.safe_load(open(f"{lab3}/fabric/config/federation.yaml"))[
              "upstream"] and "does not use a relay" in role(lab3, "drop-relay").get("error", ""), dropped)
finally:
    for p in SERVERS:
        p.kill()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
