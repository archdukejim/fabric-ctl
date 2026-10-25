import datetime
import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW, heading, ok
from fabriclib.consent.groups import GROUPS
from fabriclib.consent.load_consent import load_consent
from fabriclib.consent.plan_host_changes import plan_host_changes
from fabriclib.consent.save_consent import save_consent
from fabriclib.localadmin.remove_local_admin import remove_local_admin
from fabriclib.setup.errors import SetupError
from fabriclib.undo.remove_host_account import remove_host_account
from fabriclib.undo.undo_firewall import undo_firewall
from fabriclib.undo.undo_member import undo_member
from fabriclib.undo.undo_resolver import undo_resolver
from fabriclib.undo.undo_runtime import undo_runtime
from fabriclib.undo.undo_time import undo_time
from fabriclib.undo.undo_trust import undo_trust

# what undoing each group does, said before asking (manual 1.2.9.5)
UNDO = {
    "runtime": ("put /etc/docker/daemon.json back as it was before fabric hardened it (without a kept copy: remove "
                "the keys still holding fabric's values), then restart Docker — containers keep running "
                "(live-restore is on until then)", lambda ctx: undo_runtime(ctx.config_dir)),
    "firewall": ("remove the ufw rules fabric added (NTP, DHCP, the DC's ports; SSH too only when ufw goes off), "
                 "its DOCKER-USER rules and fabric-firewall.service; switch ufw off if it was off before fabric "
                 "(other ufw rules are kept; while ufw stays on, fabric's SSH rule stays so SSH still works); put "
                 "back the host's own rules fabric removed (2.1.2.13)",
                 lambda ctx: undo_firewall(ctx.config_dir)),
    "trust": ("remove fabric's root and intermediate CA from this host's trust store",
              lambda ctx: undo_trust(ctx.vars)),
    "time": ("put chrony's files back as they were before fabric wrote them (without a kept copy fabric's file "
             "stays) and restart chrony", lambda ctx: undo_time(ctx.config_dir)),
    "resolver": ("remove fabric's systemd-resolved drop-in (the stub listener on port 53 comes back) and put "
                 "/etc/resolv.conf back", lambda ctx: undo_resolver(ctx.config_dir)),
    "member": ("take this host out of its domain: remove the host's own computer account fabric made in the "
               "domain, put back the files fabric changed (krb5.conf, sssd.conf, nsswitch.conf, /etc/hosts), "
               "remove its keytab, turn sss off in NSS and PAM and stop sssd if fabric started it (the packages "
               "stay; local accounts were never changed)",
               lambda ctx: remove_host_account(ctx.config_dir, ctx.vars, lambda: ctx.secrets)
               + undo_member(ctx.config_dir)),
    "local_admin": ("remove this host's local-admin and its home folder (refused while it is signed in), fabric's "
                    "SSH drop-in for it (sshd reloaded) and fabric's record of it; OpenBao keeps its versions as its "
                    "history", lambda ctx: remove_local_admin(ctx.vars, ctx.config_dir)),
}


def undo_group(ctx, group, interactive, assume_yes):
    """Purpose: `fabricctl setup --undo GROUP`: revert one kind of host change fabric made and record the answer as
             no, so setup, apply and the timers leave it alone from then on (manual 1.2.9.5).
    Inputs:  ctx — SetupContext with state loaded (vars, config_dir); group — a groups.GROUPS name; interactive —
             False for --non-interactive; assume_yes — --yes (undo without asking).
    Returns: None; the change undone, what was done printed, consent.yaml records "no" for the group with the
             changes setup would make now (so an unchanged plan is not asked about again).
    Fails:   SetupError: an unknown group; a required group (packages, services, accounts: `fabricctl uninstall`
             removes those); resolver while use_host_dns is false (BIND needs port 53); an install set up before
             consent existed (setup must ask first); a non-interactive run without --yes; "no" at the prompt.
             RuntimeError / CalledProcessError / OSError from the undo itself.
    Feeds:   setup/run_setup (--undo)."""
    if group not in GROUPS:
        raise SetupError(f"unknown host-change group {group!r} (groups: {', '.join(GROUPS)})")
    meta = GROUPS[group]
    if group not in UNDO:
        raise SetupError(f"{meta['title']} cannot be undone on its own: {meta['declined']}. "
                         "`sudo fabricctl uninstall` removes fabric and undoes it")
    if group == "resolver" and not ctx.vars.get("use_host_dns", True):
        raise SetupError("BIND needs port 53 while use_host_dns is false: set use_host_dns: true, run "
                         "`sudo fabricctl setup`, then undo the resolver change")
    groups = load_consent(ctx.config_dir)
    if groups is None:
        raise SetupError("this install was set up before fabric asked about host changes: run `sudo fabricctl "
                         "setup` once (it asks about each), then undo")
    what, run = UNDO[group]
    heading(f"Undo: {meta['title']}")
    print(f"  This will {what}.")
    print(f"  {YELLOW}Afterwards: {meta['declined']}.{NC}")
    print(f"  fabric records your answer as no; `sudo fabricctl setup --approve {group}` makes the change again.")
    if not assume_yes:
        if not interactive:
            raise SetupError("pass --yes to undo without asking")
        while True:
            answer = ask(f"undo.{group}", f"  {BOLD}Undo it?{NC} [y/n] ").lower()
            if answer in ("y", "yes", "n", "no"):
                break
        if answer.startswith("n"):
            raise SetupError("nothing changed")
    for line in run(ctx) or ["nothing to undo: fabric had not changed it"]:
        ok(line)
    plan = plan_host_changes(ctx.vars, ctx.deploy_base, ctx.config_dir, os.path.join(ctx.source_dir, "jinja"),
                             [meta["step"]]).get(group, [])
    rec = groups.get(group) or {}
    groups[group] = {"answer": "no", "changes": list(dict.fromkeys((rec.get("changes") or []) + plan)),
                     "when": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                     "by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"}
    save_consent(ctx.config_dir, groups)
    ok(f"{meta['title']}: recorded as declined (shown in `fabricctl status`)")
