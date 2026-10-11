"""Start a real domain controller for a test suite, as an install runs it (manual 1.6.5): fabric's image built from a
copy of its build folder staged with a host's plain modes, the compose file's hardening, fabric's deploy_samba, a test
PKI (a root CA and the DC's certificate naming its address), then converge_domain. Used by tests/keycloak (and any
suite that needs AD)."""
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.samba.converge_domain import converge_domain  # noqa: E402
from fabriclib.samba.deploy_samba import deploy_samba  # noqa: E402
from fabriclib.secrets.random_password import random_password  # noqa: E402

IMAGE = "fabric/samba:test"
POLICY = {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0, "maximum_age_days": 0,
          "lockout_threshold": 5, "lockout_minutes": 15, "lockout_window_minutes": 15}


def _sh(cmd, **kw):
    """Run a command; raise with its stderr when it fails."""
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if res.returncode:
        raise RuntimeError(f"{cmd[:4]}: {res.stderr.strip()[-400:]}")
    return res


def start_dc(work, container, network, subnet, ip, domain="lan.j-j.family", ad_domain="ad.j-j.family",
             hostname="dc1", site="lan", extra_vars=None, dc_name=""):
    """Purpose: a converged DC of a test domain on a test network, and what a suite needs to talk to it.
    Inputs:  work — a scratch folder (made anew); container — the DC's name; network/subnet — a Docker network (made
             if missing); ip — the DC's address there; domain, ad_domain, hostname, site — the install's settings;
             extra_vars — more settings for the render (e.g. Keycloak's); dc_name — the DC's own name ("": the
             default, dc-<hostname>, so every suite's DC has a name unlike its host's, 2.1.6.45).
    Returns: dict {"v": rendered vars (deploy_base_dir = work), "secrets", "env" (jinja env), "root_ca", "root_key"
             (the test PKI's files), "container"}.
    Fails:   RuntimeError when a step fails or the DC is not healthy within 5 minutes."""
    shutil.rmtree(work, ignore_errors=True)
    certs = os.path.join(work, "stepca", "data", "certs")
    os.makedirs(certs)
    context = os.path.join(work, "build")
    shutil.copytree(os.path.join(REPO, "packaging", "images", "samba"), context)
    for name in os.listdir(context):
        os.chmod(os.path.join(context, name), 0o644)
    debian = read_images_lock(os.path.join(REPO, "config"))["debian"]["ref"]
    _sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}", context])
    env = jinja_env(os.path.join(REPO, "templates"))
    v = yaml.safe_load(env.get_template("vars.yaml.j2").render(
        domain=domain, hostname=hostname, host_ip=ip, lan_cidr=subnet, lan_gateway=subnet.rsplit(".", 1)[0] + ".1",
        site_name=site, ad_domain=ad_domain, ad_password_policy=POLICY, deploy_base_dir=work, dc_name=dc_name,
        ad_ntp_signd_dir=os.path.join(work, "ntp_signd"),
        ip_fabric_gateway=ip,                # on a test network the clients reach the DC at its own address
        **(extra_vars or {})))               # never the host's own
    root_ca, root_key = os.path.join(certs, "root_ca.crt"), os.path.join(certs, "root.key")
    _sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root_key, "-out", root_ca, "-days", "2",
         "-subj", "/CN=Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    secrets = {n: random_password() for n in ("ad_admin_password", "ad_agent_password", "ad_keycloak_password",
                                              "ad_radius_password")}
    deploy_samba(v, secrets, env)
    dc_tls(v, root_ca, root_key)
    if subprocess.run(["docker", "network", "inspect", network], capture_output=True).returncode:
        _sh(["docker", "network", "create", "--subnet", subnet, network])
    run_dc(v, container, network, env)
    converge_domain(v, os.path.join(work, "federation.yaml"), secrets, container=container)
    return {"v": v, "secrets": secrets, "env": env, "root_ca": root_ca, "root_key": root_key, "container": container}


def dc_tls(v, root_ca, root_key):
    """Purpose: a DC's certificate from the test PKI, where deploy_samba's folder has it (as setup's certificate step
             puts it): its name, the AD domain and its address.
    Inputs:  v — the DC's rendered vars (deploy_base_dir, hostname_dc, ad_domain, host_ip); root_ca, root_key — files.
    Returns: None.
    Fails:   RuntimeError when openssl fails."""
    tls = os.path.join(v["deploy_base_dir"], "samba", "tls")
    shutil.copy(root_ca, os.path.join(tls, "root_ca.crt"))
    _sh(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{tls}/privkey.pem", "-out", f"{tls}/dc.csr",
         "-subj", f"/CN={v['hostname_dc']}"])
    with open(f"{tls}/dc.ext", "w") as f:
        f.write(f"subjectAltName=DNS:{v['hostname_dc']},DNS:{v['ad_domain']},IP:{v['host_ip']}\n"
                "extendedKeyUsage=serverAuth\n")
    _sh(["openssl", "x509", "-req", "-in", f"{tls}/dc.csr", "-CA", root_ca, "-CAkey", root_key, "-CAcreateserial",
         "-out", f"{tls}/fullchain.pem", "-days", "2", "-extfile", f"{tls}/dc.ext"])
    os.chmod(f"{tls}/privkey.pem", 0o600)


def run_dc(v, container, network, env, tries=60):
    """Purpose: run a DC from fabric's image with the rendered compose file's hardening, environment and mounts, on a
             test network at its address, and wait until it is healthy.
    Inputs:  v — the DC's rendered vars (after deploy_samba); container — its name; network — a Docker network; env —
             the jinja env; tries — 5-second waits (a join takes longer than a provisioning).
    Returns: None.
    Fails:   RuntimeError when the DC is not healthy in time (its log's end)."""
    compose = yaml.safe_load(env.get_template("samba/docker-compose.yml.j2").render(**v))["services"]["samba"]
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    run = ["docker", "run", "-d", "--name", container, "--hostname", v["hostname"], "--network", network,
           "--ip", v["host_ip"], "--read-only", "--memory", compose["mem_limit"], "--cap-drop", "ALL"]
    run += [x for c in compose["cap_add"] for x in ("--cap-add", c)]
    run += [x for o in compose["security_opt"] for x in ("--security-opt", o)]
    run += [x for t in compose["tmpfs"] for x in ("--tmpfs", t)]
    run += [x for k, val in compose["environment"].items() for x in ("-e", f"{k}={val}")]
    run += [x for m in compose["volumes"] for x in ("-v", m)]
    run += ["--health-cmd", shlex.join(compose["healthcheck"]["test"][1:]), "--health-interval", "10s",
            "--health-start-period", "180s", IMAGE]
    _sh(run)
    for _ in range(tries):
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", container],
                               capture_output=True, text=True).stdout.strip()
        if state == "healthy":
            return
        time.sleep(5)
    raise RuntimeError(f"{container} not healthy: " + subprocess.run(["docker", "logs", container],
                                                                    capture_output=True, text=True).stdout[-1500:])


if __name__ == "__main__":          # a quick look: start one and print what a suite gets
    out = start_dc("/tmp/start-dc", "startdc-test", "startdc_net", "10.254.31.0/24", "10.254.31.10")
    print(json.dumps({k: out[k] for k in ("root_ca", "container")}))
