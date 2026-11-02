import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import SECRETS_FILE
from fabriclib.common.service_user import service_user
from fabriclib.common.write_audit import write_audit
from fabriclib.common.write_file_if_changed import write_file_if_changed
from fabriclib.dns.rndc import rndc
from fabriclib.secrets.save_secrets import save_secrets

FILES = {"named.conf.keys": 0o600, "named.conf.zones": 0o640}     # the key, and the grants naming it


def drop_old_key(final_vars, context, jinja_env, old, rndc_call=rndc, save=save_secrets, audit=write_audit,
                 secrets_path=SECRETS_FILE):
    """Purpose: the last step of replacing Kea's DNS key (decision 2.1.10.42, manual 1.10.4.43), once Kea runs on the
             new one: BIND's keys and zone grants rendered again without the old key, written, `rndc reconfig`;
             only then the old key removed from fabric's secrets, and the replacement audited (KEA_KEY_ROTATE).
             Until it ends, BIND keeps accepting both keys, and the next apply tries again.
    Inputs:  final_vars — the apply's checked settings (deploy_base_dir, service_users.bind); context — the apply's
             render context (the zone list, the reverse zones, the keys); jinja_env — fabric's Jinja environment;
             old — the key being dropped ({"name", ...}); rndc_call, save, audit — rndc, save_secrets, write_audit
             (tests give their own); secrets_path — fabric's secrets file.
    Returns: the old key's name.
    Fails:   ValidationError "BIND did not drop Kea's old key …" when `rndc reconfig` fails (the secrets keep the old
             key: the next apply drops it); OSError writing BIND's files; errors from save_secrets (OpenBao locked);
             jinja2 errors while rendering.
    Feeds:   deploy/restart_changed (the apply that replaced the key, after Kea took the new one)."""
    ctx = {**context, **final_vars, "kea_ddns_old": None}
    uid, gid = service_user(final_vars, "bind")
    config = os.path.join(final_vars["deploy_base_dir"], "bind9", "config")
    changed = False
    for name, mode in FILES.items():
        text = jinja_env.get_template(f"bind9/config/{name}.j2").render(**ctx)
        changed |= write_file_if_changed(os.path.join(config, name), text, mode, uid, gid)
    if changed:
        res = rndc_call(["reconfig"], timeout=90)
        if res is None or res.returncode != 0:
            why = (res.stderr or res.stdout).strip() if res else "BIND did not answer"
            raise ValidationError(f"BIND did not drop Kea's old key {old['name']} ({why}): it still accepts it; the "
                                  "next apply drops it (sudo fabricctl --apply)")
    save({"kea_ddns_old": None}, secrets_path)
    new = context.get("kea_ddns_key") or "kea-ddns"
    audit("root", "KEA_KEY_ROTATE", f"done: {old['name']} dropped, {new} in force "
                                    "(2.1.10.42)", "apply")
    return old["name"]
