import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.deploy.compose_builds import compose_builds
from fabriclib.dns.install_zone_file import install_zone_file
from fabriclib.dns.reload_zone import reload_zone
from fabriclib.dns.rndc import rndc


def finish_without_start(paths, state, bind_ids):
    """Purpose: the end of a deploy run by `fabricctl setup`: start nothing, but leave a live stack consistent —
             zones swapped safely, changed images built — and say which services setup must restart.
    Inputs:  paths — deploy_paths() (base); state — what the install steps found: restart (set), rebuild (folders),
             daemon_reload, bind9_config, zones [(zone, src, dst)], nginx, webui, agent, federation_unit, scephook_unit
             (bools);
             bind_ids — (uid, gid) of the bind user.
    Returns: the set of units to restart (setup's start step restarts them).
    Fails:   ValidationError when an image build fails (with the end of its output).
    Feeds:   apply_deployment (start_services=False).
    Notes:   with BIND running and its configuration changed (it will restart), each changed zone is frozen to sync
             its journal before the new file goes in; with BIND running otherwise, zones are swapped live; with BIND
             down they are just installed. No --pull: setup never takes a new base image implicitly."""
    restart = set(state["restart"])
    bind9_up = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", "bind9"],
                              capture_output=True, text=True).stdout.strip() == "true"
    if bind9_up and (state["bind9_config"] or "bind9" in restart):
        for zone, src, dst in state["zones"]:
            rndc(["freeze", zone])           # sync the journal; the restart loads the new file
            install_zone_file(src, dst, *bind_ids)
        restart.add("bind9")
    elif bind9_up:
        for zone, src, dst in state["zones"]:
            reload_zone(zone, src, dst, *bind_ids)
    else:
        for zone, src, dst in state["zones"]:
            install_zone_file(src, dst, *bind_ids)
    for flag, unit in (("nginx", "nginx"), ("webui", "fabric-web"), ("agent", "fabric-agent"),
                       ("federation_unit", "fabric-federation"), ("scephook_unit", "fabric-scep-hook")):
        if state[flag]:
            restart.add(unit)
    if state["daemon_reload"]:
        subprocess.run(["systemctl", "daemon-reload"], timeout=30)
    for folder in sorted(state["rebuild"]):
        compose = os.path.join(paths["base"], folder, "docker-compose.yml")
        verb = "build" if compose_builds(compose) else "pull"     # fabric's published images are pulled
        print(f"{'Building' if verb == 'build' else 'Pulling'} {folder} image...")
        res = subprocess.run(["docker", "compose", "-f", compose, verb], capture_output=True, text=True, timeout=1800)
        if res.returncode != 0:
            raise ValidationError(f"{verb} of the {folder} image failed:\n{res.stdout[-1500:]}{res.stderr[-1500:]}")
    print("Configuration deployed (services not started).")
    return restart
