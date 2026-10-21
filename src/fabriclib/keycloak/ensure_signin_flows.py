from fabriclib.keycloak.quote import q
from fabriclib.keycloak.signin_levels import admin_level, signin_level
from fabriclib.keycloak.step import step

SIGNIN, ADMIN = "fabric-signin", "fabric-admin-signin"
# each flow's shape: (level, what) — what is an execution's providerId or a sub-flow's alias. The second factor: the
# passkey sub-flow (at "any", only for someone with a passkey), then the TOTP sub-flow (at "any", only when the passkey
# sub-flow did not run: someone without a passkey uses TOTP, enrolling it if needed)
def _shape(alias):
    """Purpose: the steps of one of fabric's sign-in flows, in order.
    Inputs:  alias — SIGNIN or ADMIN.
    Returns: list of (level, providerId or sub-flow alias).
    Fails:   never.
    Feeds:   _SHAPE."""
    return ([(0, "auth-cookie")] if alias == SIGNIN else []) + [
        (0, f"{alias} sign-in"), (1, f"{alias} first factor"), (2, "auth-spnego"), (2, "auth-username-password-form"),
        (1, f"{alias} second factor"), (2, f"{alias} passkey"), (3, "conditional-user-configured"),
        (3, "webauthn-authenticator"), (2, f"{alias} totp"), (3, "conditional-sub-flow-executed"),
        (3, "auth-otp-form")]


_SHAPE = {SIGNIN: _shape(SIGNIN), ADMIN: _shape(ADMIN)}

def _what(ex):
    """Purpose: an execution's place in _SHAPE: its sub-flow alias (a sub-flow) or its providerId.
    Inputs:  ex — an execution representation from the admin API.
    Returns: (level, str).
    Fails:   never.
    Feeds:   _ensure_shape, _wanted."""
    return ex.get("level", 0), (ex.get("displayName") if ex.get("authenticationFlow") else ex.get("providerId"))


def _ensure_shape(kc, realm, alias):
    """Purpose: the flow `alias` built to _SHAPE: created when missing, rebuilt when its shape differs (a flow edited by
             hand in Keycloak's console, or an older fabric's).
    Inputs:  kc — Admin; realm — realm name; alias — SIGNIN or ADMIN.
    Returns: list of the flow's executions (admin API representations, in order).
    Fails:   SystemExit from kc.call.
    Feeds:   ensure_signin_flows."""
    base = f"/{q(realm)}/authentication/flows"
    flows = {f["alias"]: f for f in kc.call("GET", base)[1]}
    if alias in flows:
        execs = kc.call("GET", f"{base}/{q(alias)}/executions")[1]
        if [_what(e) for e in execs] == _SHAPE[alias]:
            return execs
        _unbind(kc, realm, flows[alias]["id"])
        kc.call("DELETE", f"{base}/{flows[alias]['id']}")
        step(f"rebuilt the sign-in flow {alias} (its shape had changed)")
    kc.call("POST", base, {"alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                           "description": "fabric's sign-in (manual 2.3.6.2.6.2)"})
    parents = {0: alias}
    for level, what in _SHAPE[alias]:
        parent = parents[level]
        if what.startswith(alias):                  # a sub-flow
            kc.call("POST", f"{base}/{q(parent)}/executions/flow",
                    {"alias": what, "type": "basic-flow", "description": "", "provider": "registration-page-form"})
            parents[level + 1] = what
        else:
            kc.call("POST", f"{base}/{q(parent)}/executions/execution", {"provider": what})
    step(f"created the sign-in flow {alias}")
    execs = kc.call("GET", f"{base}/{q(alias)}/executions")[1]
    cond = next(e for e in execs if e.get("providerId") == "conditional-sub-flow-executed")
    kc.call("POST", f"/{q(realm)}/authentication/executions/{cond['id']}/config",
            {"alias": f"{alias} without a passkey",
             "config": {"flow_to_check": f"{alias} passkey", "check_result": "not-executed"}})
    return kc.call("GET", f"{base}/{q(alias)}/executions")[1]


def _wanted(alias, level, kerberos):
    """Purpose: each step's requirement in a flow, for a second-factor level and Kerberos on or off.
    Inputs:  alias — SIGNIN or ADMIN; level — "none", "any", "totp" or "passkey"; kerberos — bool.
    Returns: {(level, what): requirement}.
    Fails:   never.
    Feeds:   ensure_signin_flows."""
    passkey_flow, totp_flow = {"none": ("DISABLED", "DISABLED"), "any": ("CONDITIONAL", "CONDITIONAL"),
                               "totp": ("DISABLED", "REQUIRED"), "passkey": ("REQUIRED", "DISABLED")}[level]
    condition = "REQUIRED" if level == "any" else "DISABLED"     # the conditions decide only at "any"
    return {(0, "auth-cookie"): "ALTERNATIVE",
            # without the cookie (the admin flow) the sign-in is the only way in
            (0, f"{alias} sign-in"): "ALTERNATIVE" if alias == SIGNIN else "REQUIRED",
            (1, f"{alias} first factor"): "REQUIRED",
            (2, "auth-spnego"): "ALTERNATIVE" if kerberos else "DISABLED",
            (2, "auth-username-password-form"): "ALTERNATIVE" if kerberos else "REQUIRED",
            (1, f"{alias} second factor"): "DISABLED" if level == "none" else "REQUIRED",
            (2, f"{alias} passkey"): passkey_flow, (3, "conditional-user-configured"): condition,
            (3, "webauthn-authenticator"): "REQUIRED",
            (2, f"{alias} totp"): totp_flow, (3, "conditional-sub-flow-executed"): condition,
            (3, "auth-otp-form"): "REQUIRED"}

def _unbind(kc, realm, flow_id):
    """Purpose: let a flow be deleted: the realm's browser flow back to Keycloak's own, and no client's override
             naming it (ensure_signin_flows and the client steps bind fabric's flows again in the same run).
    Inputs:  kc — Admin; realm — realm name; flow_id — the flow's id.
    Returns: None.
    Fails:   SystemExit from kc.call.
    Feeds:   _ensure_shape, ensure_signin_flows."""
    rep = kc.call("GET", f"/{q(realm)}")[1]
    alias = next((f["alias"] for f in kc.call("GET", f"/{q(realm)}/authentication/flows")[1] if f["id"] == flow_id),
                 None)
    if rep.get("browserFlow") == alias:
        kc.call("PUT", f"/{q(realm)}", {"browserFlow": "browser"})
    for client in kc.call("GET", f"/{q(realm)}/clients")[1]:
        if (client.get("authenticationFlowBindingOverrides") or {}).get("browser") == flow_id:
            client["authenticationFlowBindingOverrides"] = {}
            kc.call("PUT", f"/{q(realm)}/clients/{client['id']}", client)


def ensure_signin_flows(kc, realm, v):
    """Purpose: fabric's two sign-in flows (manual 2.3.6.2.6.2) and the realm settings they use: fabric-signin, the
             realm's browser flow (every app), and fabric-admin-signin for the admin tools (the web console, OpenBao's
             UI), which never accepts the session cookie, so a sign-in without the admin tools' second
             factor never carries into them. Each: Kerberos (on with signin_kerberos) or the password form, then the
             second factor of its level ("any": a passkey for someone who has one, else TOTP, enrolled if needed).
             Passkeys (WebAuthn) must be unlocked on the device (user verification required).
    Inputs:  kc — Admin; realm — realm name; v — vars: signin_kerberos, signin_admin_second_factor,
             signin_everyone_second_factor, hostname_keycloak.
    Returns: str, the admin flow's id (the admin tools' clients bind it).
    Fails:   ValidationError from signin_level for an unknown level; SystemExit from kc.call.
    Feeds:   configure_keycloak."""
    kerberos = bool(v.get("signin_kerberos", False))
    levels = {SIGNIN: signin_level(v.get("signin_everyone_second_factor")), ADMIN: admin_level(v)}
    base = f"/{q(realm)}/authentication/flows"
    for alias, level in levels.items():
        wanted = _wanted(alias, level, kerberos)
        changed = False
        for ex in _ensure_shape(kc, realm, alias):
            req = wanted[_what(ex)]
            if ex.get("requirement") != req:
                ex["requirement"] = req
                kc.call("PUT", f"{base}/{q(alias)}/executions", ex)
                changed = True
        if changed:
            step(f"sign-in flow {alias}: Kerberos {'on' if kerberos else 'off'}, second factor {level}")
    rep = kc.call("GET", f"/{q(realm)}")[1]
    want = {"browserFlow": SIGNIN, "webAuthnPolicyRpId": v["hostname_keycloak"],
            "webAuthnPolicyUserVerificationRequirement": "required", "webAuthnPolicyRpEntityName": realm}
    if any(rep.get(k) != val for k, val in want.items()):
        kc.call("PUT", f"/{q(realm)}", want)
        step("realm: fabric-signin is the browser flow; passkeys unlocked on the device (user verification)")
    flows = {f["alias"]: f["id"] for f in kc.call("GET", base)[1]}
    return flows[ADMIN]
