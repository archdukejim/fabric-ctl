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


def ensure_local_admin_store(v, token):
    """Purpose: OpenBao's side of the local admin passwords (manual 1.7.1.3.2, 1.7.1.4.2): the KV v2 mount
             `local-admin/` (its own, apart from fabric/ and apps/, 10 versions kept) and the password policy
             `local-admin` (24 characters, nothing easily misread). Converges: a second run changes nothing.
    Inputs:  v — vars (OpenBao's address); token — a fabric-setup token.
    Returns: list of str, what was made or changed ([] when nothing).
    Fails:   ValidationError when OpenBao refuses or does not answer.
    Feeds:   setup/setup_local_admin, tests/openbao/local_admin.py."""
    done = []
    if f"{MOUNT}/" not in _call(v, token, "GET", "sys/mounts"):
        _call(v, token, "POST", f"sys/mounts/{MOUNT}", {
            "type": "kv", "options": {"version": "2"},
            "description": "local admin passwords, set and kept by OpenBao (manual 1.7.1.3)"})
        done.append(f"OpenBao: the KV v2 mount {MOUNT}/")
    config = _call(v, token, "GET", f"{MOUNT}/config").get("data") or {}
    if config.get("max_versions") != MAX_VERSIONS:
        _call(v, token, "POST", f"{MOUNT}/config", {"max_versions": MAX_VERSIONS})
        done.append(f"OpenBao: {MOUNT}/ keeps {MAX_VERSIONS} versions")
    status, data = bao_request(v, "GET", f"sys/policies/password/{PASSWORD_POLICY}", token=token)
    if status != 200 or (data.get("data") or {}).get("policy", "").strip() != PASSWORD_POLICY_HCL.strip():
        _call(v, token, "PUT", f"sys/policies/password/{PASSWORD_POLICY}", {"policy": PASSWORD_POLICY_HCL})
        done.append(f"OpenBao: the password policy {PASSWORD_POLICY}")
    return done
