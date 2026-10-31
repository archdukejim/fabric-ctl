import datetime
import os

from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.key_check_value import key_check_value
from fabriclib.vault.common.read_slot_store import read_slot_store
from fabriclib.vault.common.write_seal_config import write_seal_config
from fabriclib.vault.common.write_slot_store import write_slot_store
from fabriclib.vault.slots import local


def ensure_vault_key(v):
    """Purpose: make sure the vault key exists in at least one unlock method, and write seal.hcl for it.
    Inputs:  v — vars: openbao_key_dir (made root 0700), openbao_seal_key_id (default "fabric-1"),
             deploy_base_dir (openbao/data), service_users (for seal.hcl). Reads slots.json.
    Returns: "present" — a store exists (only seal.hcl is converged);
             "created" — fresh: a random 32-byte key in a new "local" slot.
    Fails:   ValidationError if OpenBao already holds data but no unlock method exists (a new key cannot open it:
             restore the key from backup); OSError (e.g. not root).
    Feeds:   setup/setup_openbao, tests/openbao/run.py.
    Notes:   never creates a key next to an initialised vault without one.
    """
    store = read_slot_store(v)
    if store:
        write_seal_config(v, store["key_id"], store.get("previous_key_id"))
        return "present"
    folder = v["openbao_key_dir"]
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chown(folder, 0, 0)
    os.chmod(folder, 0o700)
    key_id = v.get("openbao_seal_key_id", "fabric-1")
    data = os.path.join(v["deploy_base_dir"], "openbao", "data")
    if os.path.isdir(data) and os.listdir(data):
        raise ValidationError(f"no unlock method in {folder}, but OpenBao already holds data in {data}: restore "
                              "the key from your backup (a new key cannot open the existing vault)")
    key, state = os.urandom(32), "created"
    slot = {"id": "local", "type": "local", "label": "Key file on this host",
            "added": datetime.date.today().isoformat(), "device": {"path": folder}, "wraps": {}}
    slot["wraps"][key_id] = local.wrap(v, slot, key, key_id)
    write_slot_store(v, {"key_id": key_id, "previous_key_id": None, "kcv": {key_id: key_check_value(key, key_id)},
                         "slots": [slot]}, key)
    write_seal_config(v, key_id)
    return state
