import os
import re
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.deploy.check_fixed_identity import HOSTNAME_MARKER
from fabriclib.localadmin.common.local_admin_token import local_admin_token
from fabriclib.localadmin.constants import REASON_MAX
from fabriclib.localadmin.follow_rename import follow_rename
from fabriclib.localadmin.record import load_record

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _hostnamectl(name):
    """Purpose: the host's own name set, as root (2.1.6.96's rule never refuses root's hostnamectl).
    Inputs:  name — the new name.
    Returns: None.
    Fails:   ValidationError with hostnamectl's complaint; OSError without it.
    Feeds:   rename_host (its default)."""
    res = subprocess.run(["hostnamectl", "set-hostname", name], capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise ValidationError((res.stderr or res.stdout).strip()[-300:] or f"hostnamectl: exit {res.returncode}")


def _name_problem(name, v):
    """Purpose: why a name cannot be this host's (manual 4.2.4.3 step 1): one host-name label, never only digits or
             localhost, and its account in the domain (the first 15 characters, 1.6.11.8) never the DC's own name
             (2.1.6.51). A computer of that name already in the domain is the member step's to refuse (1.6.11.8).
    Inputs:  name — the asked name (lower case); v — vars (dc_name, hostname_dc).
    Returns: str, the problem; "" when the name can be used.
    Fails:   never.
    Feeds:   rename_host."""
    if not _LABEL.match(name):
        return f"{name!r}: one label of 1-63 letters, digits or hyphens, not starting or ending with a hyphen"
    if name.isdigit() or name == "localhost":
        return f"{name!r}: not only digits, and not localhost"
    dc = str(v.get("dc_name") or str(v.get("hostname_dc") or "").split(".")[0]).lower()
    if dc and name[:15].rstrip("-") == dc:
        return f"{name!r} would take the domain controller's own name, {dc}, in the domain (2.1.6.51)"
    return ""


def rename_host(v, config_dir, new, reason, actor, vars_file=None, lock_file=None, set_hostname=_hostnamectl,
                token_fn=local_admin_token, follow=follow_rename, audit=write_audit):
    """Purpose: a domain controller's host renamed through break glass, the only way (decision 2.1.6.104, manual
             1.6.11.14, 4.2.4.3): the name checked, a reason given, and OpenBao answering when the host's local-admin
             must follow it, all before anything changes; then the host renamed (hostnamectl), `hostname` set in
             vars.yaml, the recorded name (<config>/.hostname, which an apply holds the host to) moved, the
             local-admin given a new password under the new name (localadmin/follow_rename), and the rename audited
             HOST_RENAME with who and why. The apply and the host's own join follow it (4.2.4.3 steps 4 and 5). Run
             again with the same name after a failure, it does what is left and changes nothing done.
    Inputs:  v — rendered vars (hostname, hostname_dc, dc_name; OpenBao's address); config_dir — the install's config
             folder; new — the new name; reason — why (one line, up to 200 characters); actor — who runs it (the
             person behind sudo); vars_file, lock_file — vars.yaml and its lock (default <config>/vars.yaml and
             <config>/.vars.lock); set_hostname, token_fn, follow, audit — the parts (tests give their own).
    Returns: {"from": old name, "to": new name, "changed": [str]}.
    Fails:   ValidationError, nothing changed: no domain controller on this host (rename it by 4.2.4.3 as any host),
             a name refused (_name_problem), the same name with nothing left to do, no reason or one longer than a
             line of 200 characters, OpenBao not answering while local-admin must follow; ValidationError from
             hostnamectl or follow_rename part-way (said; run it again to finish); OSError writing.
    Feeds:   run_admin_command (`fabricctl admin rename-host`)."""
    if not v.get("hostname_dc"):
        raise ValidationError("this host runs no domain controller: rename it by manual 4.2.4.3 without break glass "
                              "(set hostname: in vars.yaml, then apply)")
    new = str(new or "").strip().lower()
    reason = str(reason or "").strip()
    problem = _name_problem(new, v)
    if problem:
        raise ValidationError(problem)
    if not reason or "\n" in reason or len(reason) > REASON_MAX:
        raise ValidationError(f"--reason is required: one line of up to {REASON_MAX} characters")
    vars_file = vars_file or os.path.join(config_dir, "vars.yaml")
    lock_file = lock_file or os.path.join(config_dir, ".vars.lock")
    marker = os.path.join(config_dir, HOSTNAME_MARKER)
    recorded = open(marker).read().strip() if os.path.exists(marker) else str(v.get("hostname") or "")
    old = str(v.get("hostname") or "") if recorded == new else recorded
    v_old, v_new = {**v, "hostname": old}, {**v, "hostname": new}
    left_for_local_admin = load_record(config_dir)["made"] and load_record(config_dir).get("host") != new
    if recorded == new and str(v.get("hostname") or "") == new and not left_for_local_admin:
        raise ValidationError(f"this host is already {new}: nothing to rename (manual 4.2.4.3 step 4 follows: the "
                              "apply, then the member step)")
    if left_for_local_admin:
        token, why = token_fn(v_new)
        if token is None:
            raise ValidationError(f"OpenBao must answer, so the host's local-admin can follow the new name: {why}; "
                                  "nothing changed")
    changed = []
    set_hostname(new)
    changed.append(f"the host's own name: {new} (hostnamectl)")
    with vars_lock(lock_file):
        data = load_vars(vars_file)
        if data.get("hostname") != new:
            data["hostname"] = new
            save_vars(data, vars_file)
            changed.append(f"vars.yaml: hostname: {new}")
    if recorded != new:
        with open(marker + ".new", "w") as f:
            f.write(new + "\n")
        os.replace(marker + ".new", marker)
        changed.append(f"the name an apply holds this host to: {new} (was {recorded})")
        audit(actor, "HOST_RENAME", f"from={old} to={new} reason={reason}", "cli")
    changed += follow(v_old, v_new, config_dir, actor=actor, token_fn=token_fn)
    return {"from": old, "to": new, "changed": changed}
