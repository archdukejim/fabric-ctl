import os

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.vault.common.key_check_value import key_check_value
from fabriclib.vault.common.obtain_key import obtain_key
from fabriclib.vault.common.read_slot_store import read_slot_store
from fabriclib.vault.common.slot_type import slot_type
from fabriclib.vault.common.write_seal_config import write_seal_config
from fabriclib.vault.common.write_slot_store import write_slot_store
from fabriclib.vault.unlock_vault import unlock_vault
from fabriclib.vault.wipe_runtime_keys import wipe_runtime_keys


def _next_id(key_id):
    """Purpose: the next key version name.
    Inputs:  key_id — the current version, e.g. "fabric-1".
    Returns: "fabric-2" for "fabric-1"; "<key_id>-2" when it does not end in -<number>.
    Fails:   never.
    Feeds:   rotate_vault_key.
    """
    stem, _, n = key_id.rpartition("-")
    return f"{stem}-{int(n) + 1}" if n.isdigit() else f"{key_id}-2"


def _unlock_or_stop(v, when):
    """Purpose: put every key the seal names in RAM before OpenBao is restarted, or stop with OpenBao left running:
             a restart with a key missing leaves it down (a KMIP device that stopped answering mid-rotation did,
             2.3.1.57).
    Inputs:  v — vars; when — what the stop interrupts, for the message.
    Returns: None once every key is in RAM.
    Fails:   ValidationError naming each method that failed and how to finish; OpenBao is not restarted.
    Feeds:   rotate_vault_key.
    """
    errors = []
    if unlock_vault(v, errors=errors) is None:
        wipe_runtime_keys(v)                        # no key left behind in RAM; the running OpenBao needs none
        raise ValidationError(f"the vault key rotation stopped {when}: a key could not be read from its unlock "
                              f"method ({'; '.join(errors) or 'no method answered'}). OpenBao was not restarted and "
                              f"keeps running as it was; when the method answers again, run "
                              f"`fabricctl vault rotate --yes` to finish")


def rotate_vault_key(v, actor, restart, source="web"):
    """Purpose: a new vault key for every unlock method whose device is present now; the others are dropped (the
             answer to a lost stick or token). OpenBao moves over with its static seal's key rotation. A rotation
             that stopped part way (previous_key_id set) is finished instead of starting a new one.
    Inputs:  v — vars; actor — who asked (audit); restart — callable that restarts OpenBao and waits until it is
             active, raising otherwise (restart_openbao); source — audit source ("web").
    Returns: {"key_id": new version, "kept": [slot ids], "dropped": [slot ids], "resumed": bool}.
    Fails:   ValidationError: no store; no method present; a key that cannot be put in RAM before a restart
             (_unlock_or_stop: OpenBao left running, the store as it was at that step, so a second call finishes).
             An error wrapping the new key on a present method (from its slot type) stops before the store is saved.
             Errors from restart() propagate and leave the store with previous_key_id set (a second call finishes).
    Feeds:   agent route POST /v1/vault/rotate, `fabricctl vault rotate` (run_vault_command), tests/openbao/run.py.
    Notes:   steps: store saved with both keys and seal.hcl naming new (current) and old (previous); unlock and restart,
             so OpenBao re-wraps itself with the new key; old copies forgotten, store saved with the new key only,
             dropped methods discarded; unlock and restart with only the new key (proves it opens the vault); RAM
             copies wiped. The store can unlock both keys before anything restarts, so an interruption never leaves
             the vault without a way in; OpenBao is restarted only with every key its seal names in RAM (2.3.1.57).
             Audited as VAULT_ROTATE.
    """
    store = read_slot_store(v)
    if not store:
        raise ValidationError("no vault key: set up OpenBao first")
    resumed = bool(store.get("previous_key_id"))
    dropped, dropped_slots = [], []
    if resumed:                                     # a rotation that stopped part way: finished, not started again
        new_id, old_id = store["key_id"], store["previous_key_id"]
        new, _ = obtain_key(v, store, new_id, attended=True)
        if new is None:
            raise ValidationError("a vault key rotation is part way, and no unlock method that holds its new key is "
                                  "present: plug one in to finish it")
        kept = store["slots"]
    else:
        old_id = store["key_id"]
        old, _ = obtain_key(v, store, old_id, attended=True)
        if old is None:
            raise ValidationError("no unlock method is present: plug one in to rotate")
        new, new_id = os.urandom(32), _next_id(old_id)
        kept = []
        for slot in store["slots"]:
            mod = slot_type(slot["type"])
            key, _ = obtain_key(v, store, old_id, only=slot["id"], attended=True)
            if key is None:
                dropped.append(slot["id"])
                dropped_slots.append(slot)
                continue
            slot["wraps"][new_id] = mod.wrap(v, slot, new, new_id)
            kept.append(slot)
        store.update(slots=kept, key_id=new_id, previous_key_id=old_id)
        store["kcv"][new_id] = key_check_value(new, new_id)
        write_slot_store(v, store, new)             # both keys reachable from here on
    write_seal_config(v, new_id, old_id)
    _unlock_or_stop(v, "before OpenBao moved to the new key")
    restart()                                       # OpenBao re-wraps its root key with the new key
    for slot in kept:
        record = slot["wraps"].pop(old_id, None)
        mod = slot_type(slot["type"])
        if record and hasattr(mod, "forget"):
            mod.forget(v, slot, record)
    store.update(previous_key_id=None)
    store["kcv"].pop(old_id, None)
    write_slot_store(v, store, new)
    for slot in dropped_slots:
        if hasattr(slot_type(slot["type"]), "discard"):
            slot_type(slot["type"]).discard(v, slot)
    write_seal_config(v, new_id)
    summary = (f"{old_id} -> {new_id}; kept={','.join(s['id'] for s in kept)} dropped={','.join(dropped) or '-'}"
               + ("; finished a rotation that had stopped part way" if resumed else ""))
    try:
        _unlock_or_stop(v, f"after OpenBao moved to {new_id}, before the restart that proves it opens with it alone")
    except ValidationError:
        wipe_runtime_keys(v)
        write_audit(actor, "VAULT_ROTATE", summary + "; not yet proven by a restart", source)
        raise
    restart()                                       # proves the new key alone opens the vault
    wipe_runtime_keys(v)
    write_audit(actor, "VAULT_ROTATE", summary, source)
    return {"key_id": new_id, "kept": [s["id"] for s in kept], "dropped": dropped, "resumed": resumed}
