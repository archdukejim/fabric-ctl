from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import SECRETS_FILE
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.dhcp.kea_key.start_key_rotation import start_key_rotation
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets
from fabriclib.system.apply_changes import apply_changes


def rotate_key(v, actor, source="cli", apply=apply_changes, load=load_secrets, save=save_secrets,
               audit=write_audit, secrets_path=SECRETS_FILE):
    """Purpose: `fabricctl dhcp rotate-key`: Kea's DNS key replaced now, whatever its age (decision 2.1.10.42, manual
             1.10.4.43), by the same steps an apply takes once the key is 330 days old: the new key made in fabric's
             secrets (start_key_rotation), then an apply renders BIND knowing both keys, reloads Kea on the new one
             and drops the old. A replacement already under way is finished by the same apply.
    Inputs:  v — the rendered vars (install_kea, dhcp.ddns); actor, source — the audit's; apply — apply_changes
             (tests give their own); load, save, audit — load_secrets, save_secrets, write_audit; secrets_path — the
             secrets file.
    Returns: {"started": the sentence saying what is replaced, or None when one was already under way; "ok": the
             apply's result; "output": its last 2000 characters}.
    Fails:   ValidationError, changing nothing: DHCP off here, or Kea registering no names (dhcp.ddns: false: it has
             no key), or Kea's key not made yet (no apply ran); from load_secrets or save_secrets (OpenBao locked).
             subprocess.TimeoutExpired from the apply.
    Feeds:   dhcp/run_dhcp_command (`fabricctl dhcp rotate-key`)."""
    if not v.get("install_kea"):
        raise ValidationError("DHCP is off here (install_kea: false): Kea has no DNS key to replace")
    if not (v.get("dhcp") or {}).get("ddns", True):
        raise ValidationError("Kea registers no names here (dhcp.ddns: false): it has no DNS key to replace")
    with vars_lock():
        secrets = load(secrets_path)
        if not secrets.get("kea_ddns_secret"):
            raise ValidationError("Kea's DNS key is not made yet: run an apply first (sudo fabricctl --apply)")
        under_way = bool(secrets.get("kea_ddns_old"))
        out = start_key_rotation(v, secrets, force=True)
        if out["changed"]:
            save({k: secrets[k] for k in ("kea_ddns_key", "kea_ddns_secret", "kea_ddns_made", "kea_ddns_old")},
                 secrets_path)
            audit(actor, "KEA_KEY_ROTATE", f"started: {secrets['kea_ddns_old']['name']} -> {secrets['kea_ddns_key']} "
                                           "(asked for)", source)
    ok, output = apply(actor, source=source)
    return {"started": None if under_way else out["started"], "ok": ok, "output": output[-2000:]}
