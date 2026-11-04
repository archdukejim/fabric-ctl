import copy
import threading
import time

HOLD_SECONDS = 60
_lock = threading.Lock()
_enabled = False
_value, _at = None, 0.0


def hold_secrets():
    """Purpose: from now on this process keeps what it reads from OpenBao for HOLD_SECONDS (decision 2.1.8.35: the read
             took about 190 ms on the test Pi, on each directory read of a page).
    Inputs:  none.
    Returns: None.
    Fails:   never.
    Feeds:   agent/server main."""
    global _enabled
    _enabled = True


def forget_secrets():
    """Purpose: what is kept is out of date: this process has just written them.
    Inputs:  none.
    Returns: None.
    Fails:   never.
    Feeds:   secrets/common/write_vault_secrets."""
    global _value
    with _lock:
        _value = None


def held_read(read):
    """Purpose: the secrets, read again only when nothing recent is kept (always, in a process that does not hold them).
    Inputs:  read — function giving the secrets.
    Returns: a copy of the dict, for the caller to change freely.
    Fails:   whatever read raises (nothing is kept then).
    Feeds:   load_secrets."""
    global _value, _at
    if not _enabled:
        return read()
    with _lock:
        if _value is None or time.monotonic() - _at > HOLD_SECONDS:
            _value, _at = read(), time.monotonic()
        return copy.deepcopy(_value)
