import os

from fabriclib.common.copy_tree_with_perms import copy_tree_with_perms
from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import DEPLOY_BASE_DIR, SECRETS_FILE, VARS_FILE
from fabriclib.common.service_user import service_user
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.deploy_paths import deploy_paths
from fabriclib.deploy.install_bind9_files import install_bind9_files
from fabriclib.deploy.render_deployment import render_deployment
from fabriclib.dns.changed_names import changed_names
from fabriclib.dns.landing_cert_stale import landing_cert_stale
from fabriclib.dns.reload_zone import file_serial, reload_zone
from fabriclib.dns.rndc import rndc
from fabriclib.dns.served_serial import served_serial
from fabriclib.dns_filter.flush_published_names import flush_published_names
from fabriclib.ipam.options.watch_state import save_watch_state


def apply_dns(actor, source="web"):
    """Purpose: DNS' own Apply (decision 2.1.8.24, manual 1.8.6.5): render everything as an apply does, then install
             only BIND's files and the landing page; `rndc reconfig` when BIND's configuration changed (TSIG keys,
             ACLs, the zone list) and each changed zone swapped in under the running BIND. Nothing restarts; nothing
             else is installed (another service's changed file waits for the next full apply). Health-gated (2.1.14.15):
             it stops at the first part BIND does not take.
    Inputs:  actor — who asked (audit); source — "web" (default) or "cli". Holds vars_lock; sets env
             CUSTOM_VARS_PATH, SECRETS_FILE_OVERRIDE, DEPLOY_BASE_DIR to this install's, as a full apply
             does (menu/apply_and_report).
    Returns: {"config": bool (BIND's configuration changed and was reloaded), "zones": [names swapped in],
             "landing": bool (the landing page's files written), "landing_cert": landing_cert_stale's answer (None, or
             the names a full apply would issue its certificate for, 2.1.8.29), "flushed": how many names the
             filtering resolver forgot (flush_published_names, 2.1.10.46, 2.1.4.9), "flush_error": why it did not
             forget the rest, or None}.
    Fails:   ValidationError (nothing installed yet) for what the apply's render refuses (settings, secrets, a template)
             and for a file that cannot be written (OSError, said); ValidationError once installed: BIND refusing
             `rndc reconfig`, or not serving a changed zone's new serial (named). An APPLY_DNS audit entry is written
             when it finishes or fails after the render. On 0.9.0, once BIND serves the address plan's names,
             what DNS was rendered from is kept for the plan poll (plan-dns.json, 2.3.10.5.6), as a full apply does.
    Feeds:   agent/post_pending (the zones page's finish, through fabric-agent)."""
    os.environ.update({"CUSTOM_VARS_PATH": VARS_FILE, "SECRETS_FILE_OVERRIDE": SECRETS_FILE,
                       "DEPLOY_BASE_DIR": DEPLOY_BASE_DIR})
    with vars_lock():
        paths = deploy_paths()
        try:
            p = render_deployment(paths)
            final_vars = p["final_vars"]
            bind = install_bind9_files(paths, final_vars)
            names = changed_names(bind["zones"])       # before they are swapped in (2.1.10.46, 2.1.4.9)
            src = os.path.join(paths["render"], "nginx/www/landing")
            landing = False
            if os.path.isdir(src):             # the landing page's links follow the zone's records (1.4.2.4)
                uid, gid = service_user(final_vars, "nginx")
                landing = bool(copy_tree_with_perms(src, os.path.join(paths["base"], "nginx/www/landing"), uid, gid,
                                                    0o644, 0o755))
        except OSError as exc:                 # said on the Review, as BIND's own refusals are
            write_audit(actor, "APPLY_DNS", f"failed: {exc}", source)
            raise ValidationError(f"DNS' files could not be written: {exc}")
        try:
            if bind["config"]:
                res = rndc(["reconfig"], timeout=90)
                if res is None or res.returncode != 0:
                    why = (res.stderr or res.stdout).strip() if res else "BIND did not answer (is bind9 running?)"
                    raise ValidationError(f"BIND did not take its new configuration: {why}")
            done = []
            bind_ids = service_user(final_vars, "bind")
            for zone, rendered, deployed in bind["zones"]:
                reload_zone(zone, rendered, deployed, *bind_ids)
                want = file_serial(rendered)
                if want and served_serial(zone) != want:
                    raise ValidationError(f"BIND does not serve {zone}'s new records (serial {want})"
                                          + (f"; done before it: {', '.join(done)}" if done else ""))
                done.append(zone)
            flushed = flush_published_names(final_vars, names)   # the resolver forgets old answers (2.1.10.46, 2.1.4.9)
        except ValidationError as exc:
            write_audit(actor, "APPLY_DNS", f"failed: {exc}", source)
            raise
    if p.get("dns_digest") is not None:    # BIND serves the plan's names now: the poll may count DNS current
        save_watch_state("plan-dns", {"dns": p["dns_digest"]})
    write_audit(actor, "APPLY_DNS", f"config={'yes' if bind['config'] else 'no'} zones={','.join(done) or '-'} "
                                    f"landing={'yes' if landing else 'no'} flushed={flushed['flushed']}", source)
    return {"config": bool(bind["config"]), "zones": done, "landing": landing,
            "landing_cert": landing_cert_stale(paths["base"], final_vars), "flushed": flushed["flushed"],
            "flush_error": flushed["error"]}
