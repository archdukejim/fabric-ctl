import hmac
import os

from fabriclib.common.write_audit import write_audit
from fabriclib.vault.common.obtain_key import obtain_key
from fabriclib.vault.common.read_slot_store import read_slot_store
from fabriclib.vault.common.slot_store_mac import slot_store_mac
from fabriclib.vault.common.write_private_file import write_private_file


def unlock_vault(v, errors=None):
    """Purpose: fabric-unlock: get the vault key from any present method and put it where OpenBao's static seal
             reads it.
    Inputs:  v — vars: openbao_runtime_dir (RAM), openbao_admin_dir (default /run/fabric/openbao-admin),
             service_users.openbao uid/gid. Reads slots.json and tries the methods unattended. errors — a list
             collecting "<slot id>: <reason>" for each method that failed, or None.
    Returns: {"slot": id of the method used, "tamper": bool}, or None when there is no store, no method is present,
             or a rotation is in progress and its previous key cannot be obtained (the seal then names both keys and
             OpenBao would not start with one, 2.3.1.57); nothing is written to RAM then.
    Fails:   OSError creating the folders or files (e.g. not root); KeyError if service_users has no openbao entry.
             A method's failure is not raised (obtain_key).
    Feeds:   `fabricctl vault unlock` (the openbao unit's start condition), rotate_vault_key, setup/setup_openbao,
             tests/openbao/run.py.
    Notes:   writes <runtime>/<key_id>.key (openbao user, 0400), and the previous key too while a rotation is in
             progress; also prepares the break-glass socket folder (openbao user, 0700). None means OpenBao must not
             start: without its key files it would not run at all. A store that does not match its signature is
             audited (VAULT_SLOTS_TAMPERED) but does not block the unlock: every key is still verified against its
             check value.
    """
    store = read_slot_store(v)
    if not store:
        return None
    key, slot_id = obtain_key(v, store, store["key_id"], errors=errors)
    if key is None:
        return None
    prev = None
    if store.get("previous_key_id"):        # every key the seal names, or none: never a half unlock (2.3.1.57)
        prev, _ = obtain_key(v, store, store["previous_key_id"], errors=errors)
        if prev is None:
            return None
    uid, gid = (int(v["service_users"]["openbao"][k]) for k in ("uid", "gid"))
    runtime = v["openbao_runtime_dir"]
    os.makedirs(runtime, mode=0o700, exist_ok=True)
    os.chown(runtime, uid, gid)
    admin = v.get("openbao_admin_dir") or "/run/fabric/openbao-admin"      # break-glass socket
    os.makedirs(admin, mode=0o700, exist_ok=True)
    os.chown(admin, uid, gid)
    os.chmod(admin, 0o700)
    os.chmod(runtime, 0o700)
    write_private_file(os.path.join(runtime, f"{store['key_id']}.key"), key, uid, gid, 0o400)
    if prev:
        write_private_file(os.path.join(runtime, f"{store['previous_key_id']}.key"), prev, uid, gid, 0o400)
    tamper = not hmac.compare_digest(slot_store_mac(store, key), store.get("mac", ""))
    if tamper:
        write_audit("fabric-unlock", "VAULT_SLOTS_TAMPERED",
                    "the unlock-method store does not match its signature (changed while locked?)", "host")
    return {"slot": slot_id, "tamper": tamper}
