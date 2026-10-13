import time

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.try_vars_lock import try_vars_lock as _try_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.options.plan_digest import plan_digest
from fabriclib.ipam.options.read_usn import read_usn
from fabriclib.ipam.options.render_kea import render_kea
from fabriclib.ipam.options.watch_state import load_watch_state, save_watch_state
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp
from fabriclib.ipam.read_plan import read_plan
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.security.refresh_firewall import refresh_firewall


def poll_plan(v, container="samba", secrets=None, render=render_kea, firewall=refresh_firewall, usn=read_usn,
              read=read_plan, force=False, take_lock=None):
    """Purpose: one run of the plan poll (decision 2.1.10.24, manual 1.10.4.26): the DC's USN read; when it moved, the
             site's plan and option sets read and, when what Kea is rendered from changed, Kea alone re-rendered and
             restarted (render_kea) and the host firewall brought in line when the served subnets changed. Never a
             full apply: a change DNS needs is reported and waits for the next apply. Audited when Kea is re-rendered.
    Inputs:  v — fabric vars (site_name, install_kea); container — the DC's container; secrets — fabric's secrets
             (default loaded only once the USN moved); render, firewall, usn, read — the steps (render_kea,
             refresh_firewall, read_usn, read_plan; tests give their own); force — read the plan even when the USN
             did not move (Sync now, decision 2.1.10.29); take_lock — function() -> the held settings' lock or None
             (default common/try_vars_lock; Sync now, which already holds it, gives one that hands it back).
    Returns: {"state": "off" (Kea not installed), "not upgraded" (the subnets still in the settings), "unchanged" (the
             USN did not move), "same plan" (it moved, Kea's input did not), "busy" (an apply holds the settings),
             "rendered"; "kea_restarted" (bool), "firewall" (bool: brought in line), "dns_pending" (bool: published
             names or subnets changed since the last apply rendered DNS), "usn"}.
    Fails:   ValidationError: the DC not giving its USN, the plan not readable, OpenBao locked (load_secrets), the
             settings or Kea's check refusing (render_kea), the firewall step failing; SetupError when Kea does not
             come back healthy. The USN is kept only after a run that succeeded, so the next run tries again.
    Feeds:   run_option_command (`fabricctl ipam watch [--scheduled]`, fabric-plan-watch.timer); ipam/sync/sync_plan
             (Sync now, force=True)."""
    if not v.get("install_kea"):
        return {"state": "off"}
    if "subnets" in (load_vars(deploy_paths()["vars"]).get("dhcp") or {}):
        return {"state": "not upgraded"}
    state = load_watch_state("plan-watch")
    now = usn(container)
    if now == state.get("usn") and not force:
        pending = bool(state.get("dns")) and state["dns"] != load_watch_state("plan-dns").get("dns")
        return {"state": "unchanged", "usn": now, "dns_pending": pending}
    secrets = secrets if secrets is not None else load_secrets()
    site = v["site_name"]
    digest = plan_digest(plan_to_dhcp(site_plan(read(v, secrets, of=site, container=container), site)))
    dns_pending = digest["dns"] != load_watch_state("plan-dns").get("dns")
    out = {"usn": now, "dns_pending": dns_pending, "kea_restarted": False, "firewall": False}
    if digest["kea"] == state.get("kea"):
        save_watch_state("plan-watch", {**state, "usn": now, "dns": digest["dns"]})
        return {**out, "state": "same plan"}
    lock = (take_lock or _try_lock)()
    if lock is None:
        return {**out, "state": "busy"}
    try:
        done = render(secrets, container=container)
    finally:
        lock.close()
    out["kea_restarted"] = done["changed"]
    if done["subnets"] != state.get("subnets"):
        ok, output = firewall()
        if not ok:
            raise ValidationError(f"Kea is rendered from the plan, but the host firewall was not brought in line: "
                                  f"{output[-500:]}")
        out["firewall"] = True
    save_watch_state("plan-watch", {"usn": now, "kea": digest["kea"], "subnets": done["subnets"], "dns": digest["dns"],
                                    "rendered": time.strftime("%Y-%m-%d %H:%M:%S")})
    write_audit("root", "IPAM_WATCH_RENDER", f"site={site} usn={now} kea_restarted={out['kea_restarted']} "
                f"firewall={out['firewall']} dns_pending={dns_pending}", "timer")
    return {**out, "state": "rendered"}
