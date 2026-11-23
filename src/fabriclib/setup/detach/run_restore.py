import datetime
import subprocess
import sys

from fabriclib.backup.read_build import read_build
from fabriclib.backup.restore_bundle import restore_bundle
from fabriclib.common.errors import ValidationError
from fabriclib.consent.load_consent import load_consent
from fabriclib.setup.detach.launch_worker import CLI


def _now():
    """Purpose: the time a run ends, as the run record keeps it.
    Inputs:  none.
    Returns: str, ISO 8601 with the local offset, to the second.
    Fails:   never.
    Feeds:   run_restore."""
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def run_restore(ctx, record, save, key, steps, restore=restore_bundle, run=subprocess.run, cli=CLI):
    """Purpose: the work of the setup site's Restore from a backup (manual 1.3.7.10), as fabric-setup.service does it:
             the bundle opened and put back with its changes (restore_bundle), then setup run on it unattended, as
             `fabricctl restore` does (1.3.7.6), every line in the run's log the site follows. Run again after a
             restart of the unit, it does not unpack twice: setup's steps, idempotent, run again.
    Inputs:  ctx — SetupContext (deploy_base, source_dir, config_dir); record — the run's record, its options'
             "restore": {bundle, changes, allow_again}; save — write_run for this install; key — {"passphrase",
             "private_key"} handed over (None once the bundle is restored); steps — STEPS; restore, run, cli —
             restore_bundle, subprocess.run and cli.py (tests give their own).
    Returns: 0 when setup finished on the restored bundle, 1 when the restore was refused or setup failed (said in the
             log). The record ends "done" or "failed" with its result; record["restored"] keeps what moved
             ({"changed": {key: [old, new]}, "leftover": [[setting, value]]}) for the site's finish.
    Fails:   OSError from the run's files.
    Feeds:   detach/run_worker, detach/hand_over (a host without systemd)."""
    want = record["options"]["restore"]
    if not record.get("restored"):
        print(f"restoring {want['bundle']}", flush=True)
        try:
            out = restore(ctx.deploy_base, want["bundle"], key or {}, want.get("changes") or {},
                          read_build(ctx.source_dir)["version"], actor="setup site", source="web")
        except ValidationError as exc:
            print(f"error: the restore was refused, nothing was unpacked: {exc}", flush=True)
            record.update(state="failed", result=1, finished=_now())
            save(record)
            return 1
        record["restored"] = {"changed": {k: list(v) for k, v in out["changed"].items()},
                              "leftover": [list(x) for x in out.get("leftover", [])]}
        save(record)
        for k, (old, new) in out["changed"].items():
            print(f"  {k}: {old} -> {new}", flush=True)
        for setting, value in out.get("leftover", []):
            print(f"  still at the old address (change it after setup): {setting} = {value}", flush=True)
    approve = []
    if want.get("allow_again"):
        allowed = sorted(g for g, rec in (load_consent(ctx.config_dir) or {}).items() if rec.get("answer") == "yes")
        approve = ["--approve", ",".join(allowed)] if allowed else []
    print("setting fabric up on the restored bundle", flush=True)
    result = run([sys.executable, cli, "setup", "--yes", "--non-interactive", *approve,
                  *[x for name, _, _ in steps for x in ("--step", name)], "--deploy-base", ctx.deploy_base]).returncode
    record.update(state="done" if result == 0 else "failed", result=0 if result == 0 else 1, current=None,
                  finished=_now())
    save(record)
    return record["result"]
