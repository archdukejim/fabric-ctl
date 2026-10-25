"""Start fabric's BIND beside a test DC, serving the AD zone from the DC's database through DLZ (manual 1.6.5.6), as an
install runs it: fabric's BIND image, the files write_bind_dlz makes, mounted as the rendered compose file mounts
them, around a minimal named.conf; BIND shares the DC's network (on an install both have the host's address)."""
import os
import subprocess
import sys
import time

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "tests", "common")]
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.samba.write_bind_dlz import write_bind_dlz  # noqa: E402
import test_run as testrun  # noqa: E402

IMAGE = "fabric/bind9:" + testrun.name("samba-test")     # per worktree (manual 3.1.2.6)


def start_bind(v, env, dc_container, name):
    """Purpose: a BIND answering the AD zone at the DC's address.
    Inputs:  v — the DC's rendered vars (deploy_base_dir, after the domain exists there); env — the jinja env;
             dc_container — the DC's container (BIND joins its network namespace); name — BIND's container.
    Returns: None.
    Fails:   RuntimeError when the image does not build or BIND does not answer the AD zone in time."""
    write_bind_dlz(v)
    debian = read_images_lock(os.path.join(REPO, "config"))["debian"]["ref"]
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode:
        b = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={debian}",
                            f"{REPO}/packaging/images/bind9"], capture_output=True, text=True)
        if b.returncode:
            raise RuntimeError(f"BIND image: {b.stderr[-400:]}")
    etc = os.path.join(v["deploy_base_dir"], "bindtest")
    os.makedirs(etc, exist_ok=True)
    with open(os.path.join(etc, "named.conf"), "w") as f:
        f.write('options {\n directory "/var/cache/bind";\n listen-on port 53 { any; };\n listen-on-v6 { none; };\n'
                ' recursion no;\n allow-query { any; };\n include "/etc/bind-samba/options.conf";\n};\n'
                'include "/etc/bind-samba/dlz.conf";\n')
    os.chmod(os.path.join(etc, "named.conf"), 0o644)
    os.chmod(etc, 0o755)
    compose = yaml.safe_load(env.get_template("bind9/docker-compose.yml.j2").render(**v))["services"]["bind9"]
    mounts = [m for m in compose["volumes"] if m.split(":")[1] in ("/etc/bind-samba", "/data/bind-dns", "/etc/samba")]
    testrun.remove("container", name)
    run = ["docker", "run", "-d", "--name", name, *testrun.labels(), "--network", f"container:{dc_container}",
           "--user", "600:600",
           "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m",
           "--tmpfs", "/run/named:uid=600,gid=600,mode=0755,size=4m", "--tmpfs", "/tmp:size=8m",
           "--tmpfs", "/var/cache/bind:uid=600,gid=600,size=8m"]
    run += [x for t in compose["tmpfs"] if t.startswith("/var/tmp") for x in ("--tmpfs", t)]
    run += [x for m in mounts for x in ("-v", m)] + ["-v", f"{etc}:/etc/bind:ro", IMAGE]
    r = subprocess.run(run, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"BIND: {r.stderr[-400:]}")
    for _ in range(30):
        dig = subprocess.run(["docker", "exec", dc_container, "dig", "+short", "@127.0.0.1", "SRV",
                              f"_ldap._tcp.{v['ad_domain']}"], capture_output=True, text=True)
        if dig.stdout.strip():
            return
        time.sleep(2)
    raise RuntimeError("BIND does not answer the AD zone: " + subprocess.run(
        ["docker", "logs", name], capture_output=True, text=True).stderr[-600:])
