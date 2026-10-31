import time

from fabriclib.common.errors import ValidationError
from fabriclib.localadmin.constants import MAX_VERSIONS, MOUNT, PASSWORD_POLICY, PASSWORD_POLICY_HCL
from fabriclib.vault.common.bao_request import bao_request


def _call(v, token, method, path, body=None):
    """Purpose: one OpenBao call that must succeed.
    Inputs:  v — vars; token — fabric-setup's; method, path, body — as bao_request.
    Returns: the answer's data (dict).
    Fails:   ValidationError with OpenBao's errors.
    Feeds:   ensure_local_admin_store."""
    status, data = bao_request(v, method, path, token=token, body=body)
    if status not in (200, 204):
        raise ValidationError(f"OpenBao {method} {path}: {data.get('errors') or status}")
    return data


UPGRADING = "Upgrading from non-versioned to versioned data"     # a new KV v2 mount, for its first moments
WAIT_TRIES = 30


def _config_when_ready(v, token, sleep):
    """Purpose: the mount's config, once a new KV v2 mount has finished upgrading itself: OpenBao answers a new
             mount's first calls with an error saying it is upgrading (seen in the sandbox, 2.3.7.7.6), so that
             answer is waited out, one second at a time, up to WAIT_TRIES.
    Inputs:  v — vars; token — fabric-setup's; sleep — time.sleep (tests give their own).
    Returns: the config's data (dict).
    Fails:   ValidationError with OpenBao's errors (the upgrade still running after WAIT_TRIES seconds, said so).
    Feeds:   ensure_local_admin_store."""
    for _ in range(WAIT_TRIES):
        status, data = bao_request(v, "GET", f"{MOUNT}/config", token=token)
        if status in (200, 204):
            return data.get("data") or {}
        if not any(UPGRADING in str(e) for e in data.get("errors") or []):
            raise ValidationError(f"OpenBao GET {MOUNT}/config: {data.get('errors') or status}")
        sleep(1)
    raise ValidationError(f"OpenBao GET {MOUNT}/config: the new mount was still upgrading after {WAIT_TRIES} s "
                          f"({UPGRADING}); run the step again")


def ensure_local_admin_store(v, token, sleep=time.sleep):
    """Purpose: OpenBao's side of the local admin passwords (manual 1.7.1.3.2, 1.7.1.4.2): the KV v2 mount
             `local-admin/` (its own, apart from fabric/ and apps/, 10 versions kept) and the password policy
             `local-admin` (24 characters, nothing easily misread). Converges: a second run changes nothing.
    Inputs:  v — vars (OpenBao's address); token — a fabric-setup token; sleep — the wait while a new mount
             upgrades itself (tests give their own).
    Returns: list of str, what was made or changed ([] when nothing).
    Fails:   ValidationError when OpenBao refuses or does not answer.
    Feeds:   setup/setup_local_admin, tests/openbao/local_admin.py."""
    done = []
    if f"{MOUNT}/" not in _call(v, token, "GET", "sys/mounts"):
        _call(v, token, "POST", f"sys/mounts/{MOUNT}", {
            "type": "kv", "options": {"version": "2"},
            "description": "local admin passwords, set and kept by OpenBao (manual 1.7.1.3)"})
        done.append(f"OpenBao: the KV v2 mount {MOUNT}/")
    config = _config_when_ready(v, token, sleep)
    if config.get("max_versions") != MAX_VERSIONS:
        _call(v, token, "POST", f"{MOUNT}/config", {"max_versions": MAX_VERSIONS})
        done.append(f"OpenBao: {MOUNT}/ keeps {MAX_VERSIONS} versions")
    status, data = bao_request(v, "GET", f"sys/policies/password/{PASSWORD_POLICY}", token=token)
    if status != 200 or (data.get("data") or {}).get("policy", "").strip() != PASSWORD_POLICY_HCL.strip():
        _call(v, token, "PUT", f"sys/policies/password/{PASSWORD_POLICY}", {"policy": PASSWORD_POLICY_HCL})
        done.append(f"OpenBao: the password policy {PASSWORD_POLICY}")
    return done
